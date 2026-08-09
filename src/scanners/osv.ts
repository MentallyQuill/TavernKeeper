import { mkdtemp, rm, writeFile } from "node:fs/promises";
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

const UNSAFE_PUBLIC_IDENTITY =
  /[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069<>]/u;
const URL_LIKE_IDENTITY = /\b(?:https?|ftp):\/\/|\bwww\./iu;

const PackageIdentityStringSchema = (maximum: number) =>
  z
    .string()
    .trim()
    .min(1)
    .max(maximum)
    .refine(
      (value) =>
        !UNSAFE_PUBLIC_IDENTITY.test(value) && !URL_LIKE_IDENTITY.test(value),
      "OSV package identity contains unsafe public text.",
    );

const VulnerabilitySchema = z.looseObject({
  id: z.string().min(1).max(120),
  database_specific: z
    .looseObject({ severity: z.string().optional() })
    .optional(),
});
const PackageIdentitySchema = z.looseObject({
  name: PackageIdentityStringSchema(160),
  version: PackageIdentityStringSchema(160),
  ecosystem: PackageIdentityStringSchema(80),
});
const PackageSchema = z.looseObject({
  package: PackageIdentitySchema,
  vulnerabilities: z.array(VulnerabilitySchema).max(100_000),
});
const ResultSchema = z.looseObject({
  source: z.looseObject({ path: z.string().min(1).max(4_000) }),
  packages: z.array(PackageSchema).max(100_000),
});
const OsvReportSchema = z.looseObject({
  results: z.array(ResultSchema).max(100_000),
});

function portableOutputPath(root: string, value: string) {
  const absolute = isAbsolute(value) ? resolve(value) : resolve(root, value);
  const output = relative(resolve(root), absolute).replaceAll("\\", "/");
  if (!output || output === ".." || output.startsWith("../"))
    throw new Error("OSV path is outside the checkout.");
  return output;
}

function severity(value: string | undefined): Severity {
  switch (value?.toLowerCase()) {
    case "critical":
      return "critical";
    case "high":
      return "high";
    case "low":
      return "low";
    case "moderate":
    case "medium":
    default:
      return "medium";
  }
}

function findingTitle({
  ecosystem,
  name,
  version,
}: z.infer<typeof PackageIdentitySchema>) {
  const detailed = `Known vulnerable ${ecosystem} dependency: ${name}@${version}`;
  return detailed.length <= 200
    ? detailed
    : `Known vulnerable dependency: ${name}`;
}

function parseReport(root: string, stdout: string) {
  let report: z.infer<typeof OsvReportSchema>;
  try {
    report = OsvReportSchema.parse(JSON.parse(stdout));
  } catch {
    throw new ScannerError(
      "MALFORMED_SCANNER_OUTPUT",
      "system",
      "OSV-Scanner returned malformed JSON output.",
      "osv-scanner",
    );
  }
  try {
    const findings = report.results.flatMap((result) => {
      const path = portableOutputPath(root, result.source.path);
      return result.packages.flatMap((entry) =>
        entry.vulnerabilities.map((vulnerability) =>
          normalizeFinding({
            origin: "osv-scanner",
            ruleId: vulnerability.id,
            category: "dependency-vulnerability",
            severity: severity(vulnerability.database_specific?.severity),
            confidence: "high",
            path,
            lineStart: null,
            lineEnd: null,
            evidenceSha: null,
            title: findingTitle(entry.package),
            explanation: `OSV-Scanner matched a known advisory for ${entry.package.ecosystem} package ${entry.package.name} at resolved version ${entry.package.version}.`,
          }),
        ),
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
      "OSV-Scanner returned an invalid finding identity or source path.",
      "osv-scanner",
    );
  }
}

export async function runOsv({
  root,
  inputs,
  runner,
  executable = "osv-scanner",
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
      name: "osv-scanner",
      version,
      status: "not-applicable",
      findings: [],
    };

  const operationRoot = await mkdtemp(join(temporaryRoot, "osv-"));
  try {
    const configPath = join(operationRoot, "trusted-empty-config.toml");
    await writeFile(
      configPath,
      "# TavernKeeper intentionally ignores target configuration.\n",
      {
        flag: "wx",
      },
    );
    const result = await runner.run(
      executable,
      [
        "scan",
        "source",
        "--format=json",
        "--verbosity=error",
        "--no-resolve",
        `--config=${configPath}`,
        ...inputs.map(
          (input) => `--lockfile=${join(root, ...input.path.split("/"))}`,
        ),
      ],
      {
        cwd: root,
        environment: restrictedEnvironment({ NO_COLOR: "1" }),
        timeoutMs: 900_000,
        maxOutputBytes: 100_000_000,
        shell: false,
      },
    );
    if (!result.ok)
      throw scannerExecutionError("osv-scanner", result.error.code);
    if (result.value.exitCode !== 0 && result.value.exitCode !== 1)
      throw new ScannerError(
        "SCANNER_FAILED",
        result.value.exitCode === 128 ? "repository" : "system",
        `OSV-Scanner exited with code ${result.value.exitCode}.`,
        "osv-scanner",
      );
    const findings = parseReport(root, result.value.stdout);
    if (result.value.exitCode === 1 && findings.length === 0)
      throw new ScannerError(
        "MALFORMED_SCANNER_OUTPUT",
        "system",
        "OSV-Scanner reported findings without structured results.",
        "osv-scanner",
      );
    return {
      name: "osv-scanner",
      version,
      status: "completed",
      findings,
    };
  } finally {
    await rm(operationRoot, { recursive: true, force: true });
  }
}
