import { createHash } from "node:crypto";

import { z } from "zod";

import type { InventoryClassification } from "../inventory/classify.js";
import type { Inventory } from "../inventory/inventory-handler.js";
import {
  findingFingerprint,
  type ScannerRun,
} from "../scanners/types.js";
import {
  ConfidenceSchema,
  SeveritySchema,
  type Finding,
} from "./reports.js";
import { FullShaSchema, TargetSchema, type Target } from "./targets.js";

const DigestSchema = z.string().regex(/^[0-9a-f]{64}$/u);
const VersionSchema = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/u);
const CountSchema = z.number().int().nonnegative();
const PortablePathSchema = z
  .string()
  .min(1)
  .max(500)
  .refine(
    (path) =>
      !path.includes("\\") &&
      !path.startsWith("/") &&
      !/^[A-Za-z]:/u.test(path) &&
      path
        .split("/")
        .every(
          (segment) => segment !== "" && segment !== "." && segment !== "..",
        ),
    "Path must be a normalized repository-relative path.",
  );

const FileByteTotalsSchema = z.strictObject({
  files: CountSchema,
  bytes: CountSchema,
});

const ExclusionTotalsSchema = z.strictObject({
  dependency_lockfiles: FileByteTotalsSchema,
  vendored_dependencies: FileByteTotalsSchema,
  generated_bundles: FileByteTotalsSchema,
  minified_files: FileByteTotalsSchema,
  binaries: FileByteTotalsSchema,
  archives: FileByteTotalsSchema,
  oversized_files: FileByteTotalsSchema,
  unsafe_entries: FileByteTotalsSchema,
});

const ScanPackageInventoryFileSchema = z.strictObject({
  path: PortablePathSchema,
  bytes: CountSchema,
  sha256: DigestSchema,
  kind: z.enum(["text", "binary", "oversized"]),
  likely_minified: z.boolean(),
  executable: z.boolean(),
});

export const RequiredScanPackageTools = [
  "inventory",
  "tavernkeeper-static",
  "gitleaks",
  "opengrep",
  "osv-scanner",
  "zizmor",
  "malcontent",
] as const;

const ScanPackageToolSchema = z.strictObject({
  name: z.enum(RequiredScanPackageTools),
  version: VersionSchema,
  status: z.enum(["completed", "not-applicable"]),
});

const ScanPackageFindingSchema = z
  .strictObject({
    origin: z.string().regex(/^[a-z0-9][a-z0-9:_-]{0,79}$/u),
    rule_id: z.string().min(1).max(120),
    category: z.string().regex(/^[a-z0-9][a-z0-9-]{0,79}$/u),
    severity: SeveritySchema,
    confidence: ConfidenceSchema,
    path: PortablePathSchema,
    line_start: z.number().int().positive().nullable(),
    line_end: z.number().int().positive().nullable(),
    evidence_sha: FullShaSchema.nullable(),
    title: z.string().min(1).max(200),
    explanation: z.string().min(1).max(1_000),
    remediation: z.string().min(1).max(1_000).optional(),
    reference_url: z.url().optional(),
    fingerprint: DigestSchema,
  })
  .refine(
    (finding) =>
      finding.line_start === null
        ? finding.line_end === null
        : finding.line_end === null || finding.line_end >= finding.line_start,
    { path: ["line_end"], message: "Line range is invalid." },
  );

export const ScanPackageV1Schema = z.strictObject({
  schema_version: z.literal(1),
  target: TargetSchema,
  scanner_version: VersionSchema,
  scanner_policy_version: VersionSchema,
  rule_catalog_version: VersionSchema,
  history: z.strictObject({
    base_sha: FullShaSchema.nullable(),
    commits: z.number().int().min(1).max(20),
  }),
  inventory: z.strictObject({
    totals: FileByteTotalsSchema,
    first_party_text: FileByteTotalsSchema,
    excluded: ExclusionTotalsSchema,
    files: z.array(ScanPackageInventoryFileSchema),
  }),
  tools: z.array(ScanPackageToolSchema),
  findings: z.array(ScanPackageFindingSchema),
  evidence_validation: z.strictObject({
    findings: CountSchema,
    paths_validated: CountSchema,
    fingerprints_validated: CountSchema,
  }),
});

export type ScanPackageV1 = z.infer<typeof ScanPackageV1Schema>;

export interface BuildScanPackageInput {
  target: Target;
  history: { baseSha: string | null; commits: number };
  scannerVersion: string;
  scannerPolicyVersion: string;
  ruleCatalogVersion: string;
  inventory: Inventory;
  classification: InventoryClassification;
  tools: ReadonlyArray<Pick<ScannerRun, "name" | "version" | "status">>;
  findings: readonly Finding[];
}

function expectedToolForOrigin(origin: string) {
  const tools: Record<
    string,
    (typeof RequiredScanPackageTools)[number] | undefined
  > = {
    tavernkeeper: "tavernkeeper-static",
    gitleaks: "gitleaks",
    opengrep: "opengrep",
    "osv-scanner": "osv-scanner",
    zizmor: "zizmor",
    malcontent: "malcontent",
  };
  return tools[origin];
}

function canonicalValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (value !== null && typeof value === "object")
    return Object.fromEntries(
      Object.entries(value)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, nested]) => [key, canonicalValue(nested)]),
    );
  return value;
}

function packageFingerprint(finding: ScanPackageV1["findings"][number]) {
  return findingFingerprint({
    origin: finding.origin,
    ruleId: finding.rule_id,
    path: finding.path,
    lineStart: finding.line_start,
    lineEnd: finding.line_end,
    evidenceSha: finding.evidence_sha,
  });
}

export function validateScanPackageEvidence(input: unknown): ScanPackageV1 {
  const scanPackage = ScanPackageV1Schema.parse(input);
  const inventoryPaths = new Set(
    scanPackage.inventory.files.map(({ path }) => path),
  );
  if (inventoryPaths.size !== scanPackage.inventory.files.length)
    throw new Error("Scan Package inventory paths must be unique.");

  const inventoryBytes = scanPackage.inventory.files.reduce(
    (total, file) => total + file.bytes,
    0,
  );
  if (
    scanPackage.inventory.totals.files !==
      scanPackage.inventory.files.length ||
    scanPackage.inventory.totals.bytes !== inventoryBytes
  )
    throw new Error("Scan Package inventory count is inconsistent.");

  const excluded = Object.values(scanPackage.inventory.excluded).reduce(
    (totals, category) => ({
      files: totals.files + category.files,
      bytes: totals.bytes + category.bytes,
    }),
    { files: 0, bytes: 0 },
  );
  if (
    excluded.files + scanPackage.inventory.first_party_text.files !==
      scanPackage.inventory.totals.files ||
    excluded.bytes + scanPackage.inventory.first_party_text.bytes !==
      scanPackage.inventory.totals.bytes
  )
    throw new Error("Scan Package classification count is inconsistent.");

  if (
    scanPackage.tools.length !== RequiredScanPackageTools.length ||
    new Set(scanPackage.tools.map(({ name }) => name)).size !==
      RequiredScanPackageTools.length ||
    RequiredScanPackageTools.some(
      (name) => !scanPackage.tools.some((tool) => tool.name === name),
    )
  )
    throw new Error("Scan Package required tool coverage is incomplete.");

  const completedTools = new Set(
    scanPackage.tools
      .filter(({ status }) => status === "completed")
      .map(({ name }) => name),
  );
  for (const finding of scanPackage.findings) {
    if (!inventoryPaths.has(finding.path))
      throw new Error(`Scan Package finding path is not inventoried: ${finding.path}`);
    const expectedTool = expectedToolForOrigin(finding.origin);
    if (expectedTool === undefined || !completedTools.has(expectedTool))
      throw new Error(
        `Scan Package finding origin has no completed tool: ${finding.origin}`,
      );
    if (finding.fingerprint !== packageFingerprint(finding))
      throw new Error(
        `Scan Package finding fingerprint is invalid: ${finding.fingerprint}`,
      );
  }

  const expectedFindings = scanPackage.findings.length;
  if (
    scanPackage.evidence_validation.findings !== expectedFindings ||
    scanPackage.evidence_validation.paths_validated !== expectedFindings ||
    scanPackage.evidence_validation.fingerprints_validated !== expectedFindings
  )
    throw new Error("Scan Package evidence count is inconsistent.");

  return scanPackage;
}

export function buildScanPackage(input: BuildScanPackageInput): ScanPackageV1 {
  const firstPartyBytes = input.classification.firstPartyText.reduce(
    (total, file) => total + file.bytes,
    0,
  );
  const findings = input.findings
    .map((finding) => ({
      origin: finding.origin,
      rule_id: finding.rule_id,
      category: finding.category,
      severity: finding.severity,
      confidence: finding.confidence,
      path: finding.path,
      line_start: finding.line_start,
      line_end: finding.line_end,
      evidence_sha: finding.evidence_sha,
      title: finding.title,
      explanation: finding.explanation,
      ...(finding.remediation === undefined
        ? {}
        : { remediation: finding.remediation }),
      ...(finding.reference_url === undefined
        ? {}
        : { reference_url: finding.reference_url }),
      fingerprint: finding.fingerprint,
    }))
    .sort((left, right) => left.fingerprint.localeCompare(right.fingerprint));
  const tools = input.tools
    .map(({ name, version, status }) => ({ name, version, status }))
    .sort(
      (left, right) =>
        RequiredScanPackageTools.indexOf(
          left.name as (typeof RequiredScanPackageTools)[number],
        ) -
        RequiredScanPackageTools.indexOf(
          right.name as (typeof RequiredScanPackageTools)[number],
        ),
    );
  const scanPackage = ScanPackageV1Schema.parse({
    schema_version: 1,
    target: input.target,
    scanner_version: input.scannerVersion,
    scanner_policy_version: input.scannerPolicyVersion,
    rule_catalog_version: input.ruleCatalogVersion,
    history: {
      base_sha: input.history.baseSha,
      commits: input.history.commits,
    },
    inventory: {
      totals: input.inventory.totals,
      first_party_text: {
        files: input.classification.firstPartyText.length,
        bytes: firstPartyBytes,
      },
      excluded: input.classification.excluded,
      files: input.inventory.files
        .map((file) => ({
          path: file.path,
          bytes: file.bytes,
          sha256: file.sha256,
          kind: file.kind,
          likely_minified: file.likelyMinified === true,
          executable: file.executable === true,
        }))
        .sort((left, right) => left.path.localeCompare(right.path)),
    },
    tools,
    findings,
    evidence_validation: {
      findings: findings.length,
      paths_validated: findings.length,
      fingerprints_validated: findings.length,
    },
  });
  return validateScanPackageEvidence(scanPackage);
}

export function scanPackageDigest(input: unknown) {
  const scanPackage = validateScanPackageEvidence(input);
  return createHash("sha256")
    .update(JSON.stringify(canonicalValue(scanPackage)))
    .digest("hex");
}
