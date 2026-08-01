import {
  ScanReportSchema,
  type Finding,
  type ScanMode,
  type ScanReport,
  type Severity,
} from "../contracts/reports.js";
import type { Target } from "../contracts/targets.js";
import { err, ok, type Result } from "../core/result.js";
import {
  inventoryRepository,
  type Inventory,
  type InventorySpec,
} from "../inventory/inventory-handler.js";
import {
  reviewEvidence,
  type ModelReviewOutcome,
  type ReviewEvidenceSpec,
} from "../model/minimax-review.js";
import { ProcessCommandRunner } from "../process/command-runner.js";
import {
  runExternalTools,
  type ExternalToolRun,
} from "../scanners/external-tools.js";
import { scanStaticRules } from "../scanners/static-rules.js";

export interface ScanRepositorySpec {
  target: Target;
  root: string;
  historyCommits: number;
  scannedAt: string;
  scannerVersion: string;
  mode: ScanMode;
  model: {
    enabled: boolean;
    apiKey: string | null;
    baseUrl: string;
    model: string;
  };
}

export interface ScanDependencies {
  inventory(spec: InventorySpec): Promise<Result<Inventory>>;
  staticScan(files: Inventory["files"]): Finding[];
  externalScan(root: string): Promise<ExternalToolRun[]>;
  review(spec: ReviewEvidenceSpec): Promise<Result<ModelReviewOutcome>>;
}

const severityOrder: Severity[] = ["critical", "high", "medium", "low", "info"];

function summary(findings: Finding[]) {
  return Object.fromEntries(
    severityOrder.map((value) => [
      value,
      findings.filter(({ severity }) => severity === value).length,
    ]),
  ) as ScanReport["summary"];
}

const defaultDependencies: ScanDependencies = {
  inventory: inventoryRepository,
  staticScan: scanStaticRules,
  externalScan: (root) =>
    runExternalTools({ root, runner: new ProcessCommandRunner() }),
  review: reviewEvidence,
};

export async function scanRepository(
  spec: ScanRepositorySpec,
  dependencies: ScanDependencies = defaultDependencies,
): Promise<Result<ScanReport, "INVENTORY_FAILED" | "INVALID_REPORT">> {
  const inventoryResult = await dependencies.inventory({
    root: spec.root,
    maxFiles: spec.mode === "deep" ? 100_000 : 50_000,
    maxTotalBytes: spec.mode === "deep" ? 2_000_000_000 : 1_000_000_000,
    maxFileBytes: spec.mode === "deep" ? 5_000_000 : 1_000_000,
  });
  if (!inventoryResult.ok) {
    return err("INVENTORY_FAILED", inventoryResult.error.message);
  }
  const inventory = inventoryResult.value;
  const deterministicFindings = dependencies.staticScan(inventory.files);
  const externalRuns = await dependencies.externalScan(spec.root);
  const externalFindings = externalRuns.flatMap(({ findings }) => findings);
  const modelResult = await dependencies.review({
    enabled: spec.model.enabled,
    apiKey: spec.model.apiKey,
    baseUrl: spec.model.baseUrl,
    model: spec.model.model,
    mode: spec.mode,
    files: inventory.files,
    deterministicFindings: [...deterministicFindings, ...externalFindings],
    maxFiles: spec.mode === "deep" ? 400 : 20,
    maxCharsPerFile: spec.mode === "deep" ? 40_000 : 12_000,
    maxInputChars: spec.mode === "deep" ? 1_000_000 : 120_000,
    maxOutputTokens: spec.mode === "deep" ? 8_000 : 2_000,
  });
  const modelOutcome: ModelReviewOutcome = modelResult.ok
    ? modelResult.value
    : {
        status: "failed",
        provider: spec.model.enabled ? "minimax" : null,
        model: spec.model.enabled ? spec.model.model : null,
        findings: [],
      };
  const findings = [
    ...deterministicFindings,
    ...externalFindings,
    ...modelOutcome.findings,
  ]
    .filter(
      (finding, index, values) =>
        values.findIndex(({ fingerprint }) => fingerprint === finding.fingerprint) === index,
    )
    .sort((left, right) => left.fingerprint.localeCompare(right.fingerprint));
  const tools = [
    { name: "built-in", status: "completed" as const, version: spec.scannerVersion },
    ...externalRuns.map(({ findings: _findings, ...coverage }) => coverage),
  ];
  const complete =
    externalRuns.every(({ status }) => status === "completed") &&
    modelOutcome.status !== "failed";
  const counts = summary(findings);
  const requiresReview = counts.critical + counts.high + counts.medium > 0;
  const report: ScanReport = {
    schema_version: 1,
    scanner_version: spec.scannerVersion,
    source_id: spec.target.source_id,
    provider: "github",
    repository_id: spec.target.repository_id,
    repository: spec.target.repository,
    target_sha: spec.target.target_sha,
    scanned_at: new Date(spec.scannedAt).toISOString(),
    mode: spec.mode,
    status: requiresReview
      ? "review-suggested"
      : complete
        ? "no-high-confidence-indicators"
        : "incomplete",
    summary: counts,
    coverage: {
      complete,
      history_commits: spec.historyCommits,
      inventory: { files: inventory.files.length, bytes: inventory.totalBytes },
      tools,
      model: {
        status: modelOutcome.status,
        provider: modelOutcome.provider,
        model: modelOutcome.model,
      },
    },
    findings,
  };
  const parsed = ScanReportSchema.safeParse(report);
  return parsed.success
    ? ok(parsed.data)
    : err("INVALID_REPORT", "Constructed report failed its public contract.");
}
