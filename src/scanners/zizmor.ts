import { mkdir, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join, relative, resolve } from "node:path";

import { z } from "zod";

import type { Confidence, Severity } from "../contracts/reports.js";
import type { InventoryFile } from "../inventory/inventory-handler.js";
import {
  restrictedEnvironment,
  type CommandRunner,
} from "../process/command-runner.js";
import {
  normalizeFinding,
  ScannerError,
  scannerExecutionError,
  type ScannerRun,
} from "./types.js";

const PointSchema = z.looseObject({ row: z.number().int().nonnegative() });
const LocationSchema = z.looseObject({
  symbolic: z.looseObject({
    key: z.looseObject({
      Local: z.looseObject({ verbatim_path: z.string().min(1).max(4_000) }),
    }),
    kind: z.unknown(),
  }),
  concrete: z.looseObject({
    location: z.looseObject({
      start_point: PointSchema,
      end_point: PointSchema,
    }),
  }),
});
const ZizmorFindingSchema = z.looseObject({
  ident: z.string().min(1).max(120),
  desc: z.string().min(1).max(1_000),
  determinations: z.looseObject({
    confidence: z.string(),
    severity: z.string(),
  }),
  locations: z.array(LocationSchema).min(1).max(1_000),
  ignored: z.boolean(),
});
const ZizmorReportSchema = z.array(ZizmorFindingSchema).max(100_000);

function portableOutputPath(root: string, value: string) {
  const normalized = value.replace(/^\.\//u, "");
  const absolute = isAbsolute(normalized)
    ? resolve(normalized)
    : resolve(root, normalized);
  const output = relative(resolve(root), absolute).replaceAll("\\", "/");
  if (!output || output === ".." || output.startsWith("../"))
    throw new Error("zizmor path is outside the checkout.");
  return output;
}

function severity(value: string): Severity {
  switch (value.toLowerCase()) {
    case "high":
      return "high";
    case "medium":
      return "medium";
    case "low":
      return "low";
    case "informational":
      return "info";
    default:
      throw new Error("Unsupported zizmor severity.");
  }
}

function confidence(value: string): Confidence {
  switch (value.toLowerCase()) {
    case "high":
      return "high";
    case "medium":
      return "medium";
    case "low":
      return "low";
    default:
      throw new Error("Unsupported zizmor confidence.");
  }
}

function isPrimary(kind: unknown) {
  return kind === "Primary";
}

function cleanText(value: string, maxLength: number) {
  return value
    .replace(/[\u0000-\u001f\u007f]/gu, " ")
    .trim()
    .slice(0, maxLength);
}

function parseReport(root: string, stdout: string) {
  let report: z.infer<typeof ZizmorReportSchema>;
  try {
    report = ZizmorReportSchema.parse(JSON.parse(stdout));
  } catch {
    throw new ScannerError(
      "MALFORMED_SCANNER_OUTPUT",
      "system",
      "zizmor returned malformed JSON output.",
      "zizmor",
    );
  }
  try {
    return report
      .map((value) => {
        if (value.ignored)
          throw new Error("Ignored zizmor output is forbidden.");
        const location =
          value.locations.find((candidate) =>
            isPrimary(candidate.symbolic.kind),
          ) ?? value.locations[0]!;
        return normalizeFinding({
          origin: "zizmor",
          ruleId: cleanText(value.ident, 120),
          category: "workflow-security",
          severity: severity(value.determinations.severity),
          confidence: confidence(value.determinations.confidence),
          path: portableOutputPath(
            root,
            location.symbolic.key.Local.verbatim_path,
          ),
          lineStart: location.concrete.location.start_point.row + 1,
          lineEnd: location.concrete.location.end_point.row + 1,
          evidenceSha: null,
          title: cleanText(value.desc, 200),
          explanation:
            "zizmor matched a GitHub Actions security audit; workflow excerpts were removed.",
        });
      })
      .sort((left, right) => left.fingerprint.localeCompare(right.fingerprint));
  } catch {
    throw new ScannerError(
      "MALFORMED_SCANNER_OUTPUT",
      "system",
      "zizmor returned an invalid finding identity or location.",
      "zizmor",
    );
  }
}

export async function runZizmor({
  root,
  inputs,
  runner,
  executable = "zizmor",
  version,
  temporaryRoot = tmpdir(),
}: {
  root: string;
  inputs: InventoryFile[];
  runner: CommandRunner;
  executable?: string;
  version: string;
  temporaryRoot?: string;
}): Promise<ScannerRun> {
  if (inputs.length === 0)
    return {
      name: "zizmor",
      version,
      status: "not-applicable",
      findings: [],
    };

  const operationRoot = await mkdtemp(join(temporaryRoot, "zizmor-"));
  try {
    const cachePath = join(operationRoot, "zizmor-cache");
    await mkdir(cachePath);
    const result = await runner.run(
      executable,
      [
        "--format=json-v1",
        "--no-progress",
        "--color=never",
        "--offline",
        "--no-ignores",
        "--strict-collection",
        "--persona=regular",
        "--cache-dir",
        cachePath,
        ...inputs.map((input) => join(root, ...input.path.split("/"))),
      ],
      {
        cwd: root,
        environment: restrictedEnvironment({
          NO_COLOR: "1",
          ZIZMOR_OFFLINE: "1",
        }),
        timeoutMs: 600_000,
        maxOutputBytes: 100_000_000,
        shell: false,
      },
    );
    if (!result.ok) throw scannerExecutionError("zizmor", result.error.code);
    if (![0, 11, 12, 13, 14].includes(result.value.exitCode))
      throw new ScannerError(
        "SCANNER_FAILED",
        result.value.exitCode === 3 ? "repository" : "system",
        `zizmor exited with code ${result.value.exitCode}.`,
        "zizmor",
      );
    const findings = parseReport(root, result.value.stdout);
    if (result.value.exitCode !== 0 && findings.length === 0)
      throw new ScannerError(
        "MALFORMED_SCANNER_OUTPUT",
        "system",
        "zizmor reported findings without structured results.",
        "zizmor",
      );
    return {
      name: "zizmor",
      version,
      status: "completed",
      findings,
    };
  } finally {
    await rm(operationRoot, { recursive: true, force: true });
  }
}
