import { mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { isAbsolute, join, relative, resolve } from "node:path";

import { z } from "zod";

import type { Severity } from "../contracts/reports.js";
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

const BehaviorSchema = z.looseObject({
  Description: z.string().min(1).max(2_000),
  RiskLevel: z.string(),
  ID: z.string().min(1).max(120),
});
const FileReportSchema = z.looseObject({
  Path: z.string().min(1).max(4_000),
  Behaviors: z.array(BehaviorSchema).max(100_000),
});
const MalcontentReportSchema = z.looseObject({
  Files: z.record(z.string(), FileReportSchema),
});

function portableOutputPath(root: string, value: string) {
  const normalized = value.replace(/^\.\//u, "");
  const absolute = isAbsolute(normalized)
    ? resolve(normalized)
    : resolve(root, normalized);
  const output = relative(resolve(root), absolute).replaceAll("\\", "/");
  if (!output || output === ".." || output.startsWith("../"))
    throw new Error("malcontent path is outside the checkout.");
  return output;
}

function severity(value: string): Severity {
  switch (value.toLowerCase()) {
    case "critical":
      return "critical";
    case "high":
      return "high";
    case "medium":
      return "medium";
    case "low":
      return "low";
    default:
      throw new Error("Unsupported malcontent severity.");
  }
}

function cleanText(value: string, maxLength: number) {
  return value
    .replace(/[\u0000-\u001f\u007f]/gu, " ")
    .trim()
    .slice(0, maxLength);
}

function parseReport(root: string, stdout: string) {
  let report: z.infer<typeof MalcontentReportSchema>;
  try {
    report = MalcontentReportSchema.parse(JSON.parse(stdout));
  } catch {
    throw new ScannerError(
      "MALFORMED_SCANNER_OUTPUT",
      "system",
      "malcontent returned malformed JSON output.",
      "malcontent",
    );
  }
  try {
    const findings = Object.values(report.Files).flatMap((file) => {
      const path = portableOutputPath(root, file.Path);
      return file.Behaviors.map((behavior) =>
        normalizeFinding({
          origin: "malcontent",
          ruleId: cleanText(behavior.ID, 120),
          category: "binary-analysis",
          severity: severity(behavior.RiskLevel),
          confidence: "high",
          path,
          lineStart: null,
          lineEnd: null,
          evidenceSha: null,
          title: cleanText(behavior.Description, 200),
          explanation:
            "malcontent matched an embedded capability rule; matched strings were removed.",
        }),
      );
    });
    return [
      ...new Map(
        findings.map((finding) => [finding.fingerprint, finding]),
      ).values(),
    ].sort((left, right) => left.fingerprint.localeCompare(right.fingerprint));
  } catch {
    throw new ScannerError(
      "MALFORMED_SCANNER_OUTPUT",
      "system",
      "malcontent returned an invalid finding identity or source path.",
      "malcontent",
    );
  }
}

export async function runMalcontent({
  root,
  inputs,
  runner,
  executable = "malcontent",
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
      name: "malcontent",
      version,
      status: "not-applicable",
      findings: [],
    };

  const operationRoot = await mkdtemp(join(temporaryRoot, "malcontent-"));
  try {
    const result = await runner.run(
      executable,
      [
        "scan",
        "--format=json",
        "--exit-extraction",
        "--max-depth=4",
        "--max-files=500000",
        "--max-image-size=1073741824",
        "--min-risk=high",
        "--jobs=2",
        ...inputs.map((input) => join(root, ...input.path.split("/"))),
      ],
      {
        cwd: root,
        environment: restrictedEnvironment({
          NO_COLOR: "1",
          XDG_CACHE_HOME: join(operationRoot, "cache"),
        }),
        timeoutMs: 900_000,
        maxOutputBytes: 100_000_000,
        shell: false,
      },
    );
    if (!result.ok)
      throw scannerExecutionError("malcontent", result.error.code);
    if (result.value.exitCode !== 0)
      throw new ScannerError(
        "SCANNER_FAILED",
        "system",
        `malcontent exited with code ${result.value.exitCode}.`,
        "malcontent",
      );
    return {
      name: "malcontent",
      version,
      status: "completed",
      findings: parseReport(root, result.value.stdout),
    };
  } finally {
    await rm(operationRoot, { recursive: true, force: true });
  }
}
