import { createHash } from "node:crypto";
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

const PackageIdentitySourceStringSchema = (maximum: number) =>
  z
    .string()
    .trim()
    .max(maximum)
    .refine(
      (value) => !UNSAFE_PUBLIC_IDENTITY.test(value),
      "OSV package identity contains unsafe text.",
    );

function isSafePublicIdentity(value: string) {
  return value.length > 0 && !URL_LIKE_IDENTITY.test(value);
}

const VulnerabilitySchema = z.looseObject({
  id: z.string().min(1).max(120),
  database_specific: z
    .looseObject({ severity: z.string().optional() })
    .optional(),
});
const PackageIdentitySchema = z
  .looseObject({
    name: PackageIdentitySourceStringSchema(160),
    version: PackageIdentitySourceStringSchema(160),
    ecosystem: PackageIdentitySourceStringSchema(80),
    commit: z
      .string()
      .trim()
      .regex(/^[a-f0-9]{7,64}$/iu)
      .optional(),
  })
  .superRefine(({ commit, ecosystem, name, version }, context) => {
    if (commit !== undefined) {
      if (version.length > 0 && !isSafePublicIdentity(version))
        context.addIssue({
          code: "custom",
          message: "OSV package version contains unsafe public text.",
        });
      return;
    }
    if (version.length === 0) {
      context.addIssue({
        code: "custom",
        message: "OSV package identity needs a version or commit.",
      });
      return;
    }
    if (
      !isSafePublicIdentity(ecosystem) ||
      !isSafePublicIdentity(name) ||
      !isSafePublicIdentity(version)
    )
      context.addIssue({
        code: "custom",
        message: "OSV package identity contains unsafe public text.",
      });
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

function boundedFindingTitle(...alternatives: string[]) {
  return (
    alternatives.find((alternative) => alternative.length <= 200) ??
    "Known vulnerable dependency"
  );
}

function findingTitle({
  commit,
  ecosystem,
  name,
  version,
}: z.infer<typeof PackageIdentitySchema>) {
  if (commit !== undefined)
    return version.length === 0
      ? boundedFindingTitle(
          `Known vulnerable commit dependency: ${commit}`,
          "Known vulnerable commit dependency",
        )
      : boundedFindingTitle(
          `Known vulnerable git dependency: ${version}@${commit}`,
          `Known vulnerable git dependency: ${commit}`,
          "Known vulnerable git dependency",
        );
  const detailed = `Known vulnerable ${ecosystem} dependency: ${name}@${version}`;
  return boundedFindingTitle(
    detailed,
    `Known vulnerable dependency: ${name}`,
    "Known vulnerable dependency",
  );
}

function findingExplanation({
  commit,
  ecosystem,
  name,
  version,
}: z.infer<typeof PackageIdentitySchema>) {
  if (commit !== undefined)
    return version.length === 0
      ? `OSV-Scanner matched a known advisory for a commit-addressed dependency at commit ${commit}.`
      : `OSV-Scanner matched a known advisory for a git dependency at version ${version} and commit ${commit}.`;
  return `OSV-Scanner matched a known advisory for ${ecosystem} package ${name} at resolved version ${version}.`;
}

function findingRuleId(
  vulnerabilityId: string,
  { commit, ecosystem, name, version }: z.infer<typeof PackageIdentitySchema>,
) {
  const identity = createHash("sha256")
    .update(
      JSON.stringify([
        vulnerabilityId,
        ecosystem,
        name,
        version,
        commit ?? null,
      ]),
    )
    .digest("hex")
    .slice(0, 24);
  return `${vulnerabilityId.slice(0, 91)}:pkg:${identity}`;
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
            ruleId: findingRuleId(vulnerability.id, entry.package),
            category: "dependency-vulnerability",
            severity: severity(vulnerability.database_specific?.severity),
            confidence: "high",
            path,
            lineStart: null,
            lineEnd: null,
            evidenceSha: null,
            title: findingTitle(entry.package),
            explanation: findingExplanation(entry.package),
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
