import { createHash } from "node:crypto";
import { lstat, readFile } from "node:fs/promises";
import { join } from "node:path";

import type { ScannerPolicyV2 } from "../config/policy.js";
import { buildScanPackage } from "../contracts/scan-package.js";
import {
  FindingSchema,
  type Finding,
  type ScanReportV4,
} from "../contracts/reports.js";
import { TargetSchema, type Target } from "../contracts/targets.js";
import { planHistory } from "../git/history.js";
import { verifyExactHead } from "../git/checkout.js";
import {
  classifyInventory,
  type InventoryClassification,
} from "../inventory/classify.js";
import {
  inventoryRepository,
  type Inventory,
  type InventoryFile,
  type InventorySpec,
} from "../inventory/inventory-handler.js";
import type { CommandRunner } from "../process/command-runner.js";
import { buildDeterministicReport } from "../report/deterministic-report.js";
import {
  runApplicableScanners,
  type ApplicableScannerSpec,
  type ScannerExecutables,
  type ScannerVersionPins,
} from "../scanners/run-scanners.js";
import {
  scanStaticRules,
  type StaticSourceFile,
} from "../scanners/static-rules.js";
import {
  ScannerError,
  type ScannerErrorCode,
  type ScannerRun,
} from "../scanners/types.js";

export interface ScanRepositorySpec {
  target: Target;
  projectKinds: readonly ("extension" | "frontend" | "preset")[];
  root: string;
  previousReportShas: string[];
  completedAt: string;
  scannerVersion: string;
  scannerPolicyVersion: string;
  ruleCatalogVersion: string;
  reportVersion: number;
  supersedesReportId: string | null;
  policy: ScannerPolicyV2;
  pins: ScannerVersionPins;
  rulesRoot: string;
  runner: CommandRunner;
  executables?: Partial<ScannerExecutables>;
  temporaryRoot?: string;
}

export interface ScanDependencies {
  inventory(spec: InventorySpec): ReturnType<typeof inventoryRepository>;
  classify(inventory: Inventory): InventoryClassification;
  history: typeof planHistory;
  structuralScan(root: string, files: InventoryFile[]): Promise<Finding[]>;
  scanners(spec: ApplicableScannerSpec): Promise<ScannerRun[]>;
  verifyHead: typeof verifyExactHead;
}

export interface SanitizedCandidate {
  report: ScanReportV4;
}

export interface ScanFailure {
  code: string;
  scope: "repository" | "system";
  message: string;
}

export type ScanResult =
  { ok: true; value: SanitizedCandidate } | { ok: false; error: ScanFailure };

async function loadStaticSource(
  root: string,
  file: InventoryFile,
): Promise<StaticSourceFile> {
  const path = join(root, ...file.path.split("/"));
  const metadata = await lstat(path);
  if (!metadata.isFile() || metadata.isSymbolicLink())
    throw new Error("Static source changed after safe inventory.");
  const bytes = await readFile(path);
  if (
    bytes.length !== file.bytes ||
    createHash("sha256").update(bytes).digest("hex") !== file.sha256
  )
    throw new Error("Static source changed after safe inventory.");
  let content: string;
  try {
    content = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
  } catch {
    throw new Error("Static source contains invalid UTF-8 after inventory.");
  }
  if (content.includes("\0"))
    throw new Error("Static source contains binary data after inventory.");
  return { ...file, content };
}

export async function scanStructuralFiles(
  root: string,
  files: InventoryFile[],
) {
  const loaded: StaticSourceFile[] = [];
  for (const file of files) loaded.push(await loadStaticSource(root, file));
  return scanStaticRules(loaded).sort((left, right) =>
    left.fingerprint.localeCompare(right.fingerprint),
  );
}

const defaultDependencies: ScanDependencies = {
  inventory: inventoryRepository,
  classify: classifyInventory,
  history: planHistory,
  structuralScan: scanStructuralFiles,
  scanners: runApplicableScanners,
  verifyHead: verifyExactHead,
};

const scannerOrder = [
  "tavernkeeper-static",
  "gitleaks",
  "opengrep",
  "osv-scanner",
  "zizmor",
  "malcontent",
] as const;

function failure(
  code: string,
  scope: ScanFailure["scope"],
  message: string,
): ScanResult {
  return { ok: false, error: { code, scope, message } };
}

function expectedScannerStatus(
  name: string,
  classification: InventoryClassification,
) {
  if (name === "osv-scanner")
    return classification.applicability.osv ? "completed" : "not-applicable";
  if (name === "zizmor")
    return classification.applicability.zizmor ? "completed" : "not-applicable";
  if (name === "malcontent")
    return classification.applicability.malcontent
      ? "completed"
      : "not-applicable";
  return "completed";
}

export function validateScannerRuns(
  runs: ScannerRun[],
  classification: InventoryClassification,
  structuralFindings: Finding[],
  expectedVersions: Record<string, string>,
) {
  if (
    runs.length !== scannerOrder.length ||
    new Set(runs.map(({ name }) => name)).size !== runs.length ||
    scannerOrder.some((name) => !runs.some((run) => run.name === name))
  )
    throw new ScannerError(
      "SCANNER_FAILED",
      "system",
      "Required scanner coverage set is incomplete.",
    );
  for (const run of runs) {
    if (
      run.status !== expectedScannerStatus(run.name, classification) ||
      run.version !== expectedVersions[run.name]
    )
      throw new ScannerError(
        "SCANNER_FAILED",
        "system",
        `Required scanner coverage is incomplete for ${run.name}.`,
      );
    for (const finding of run.findings) FindingSchema.parse(finding);
  }
  const streamed = structuralFindings
    .map(({ fingerprint }) => fingerprint)
    .sort();
  const reported = runs
    .find(({ name }) => name === "tavernkeeper-static")!
    .findings.map(({ fingerprint }) => fingerprint)
    .sort();
  if (JSON.stringify(streamed) !== JSON.stringify(reported))
    throw new ScannerError(
      "SCANNER_FAILED",
      "system",
      "Streamed structural findings were not preserved.",
    );
}

export function canonicalScannerRuns(runs: ScannerRun[]) {
  return [...runs].sort(
    (left, right) =>
      scannerOrder.indexOf(left.name as (typeof scannerOrder)[number]) -
      scannerOrder.indexOf(right.name as (typeof scannerOrder)[number]),
  );
}

function scannerVersions(spec: ScanRepositorySpec) {
  return {
    "tavernkeeper-static": spec.policy.version,
    gitleaks: spec.pins.gitleaks.version,
    opengrep: spec.pins.opengrep.version,
    "osv-scanner": spec.pins.osvScanner.version,
    zizmor: spec.pins.zizmor.version,
    malcontent: spec.pins.malcontent.version,
  };
}

export function inventoryIsConsistent(inventory: Inventory) {
  return (
    inventory.totals.files === inventory.files.length &&
    inventory.totals.bytes ===
      inventory.files.reduce((total, file) => total + file.bytes, 0) &&
    inventory.totalBytes === inventory.totals.bytes &&
    new Set(inventory.files.map(({ path }) => path)).size ===
      inventory.files.length
  );
}

export function classificationIsConsistent(
  inventory: Inventory,
  classification: InventoryClassification,
) {
  const inventoryByPath = new Map(
    inventory.files.map((file) => [file.path, file]),
  );
  const firstPartyPaths = new Set<string>();
  for (const file of classification.firstPartyText) {
    const inventoried = inventoryByPath.get(file.path);
    if (
      firstPartyPaths.has(file.path) ||
      inventoried === undefined ||
      inventoried.kind !== "text" ||
      inventoried.bytes !== file.bytes ||
      inventoried.sha256 !== file.sha256
    )
      return false;
    firstPartyPaths.add(file.path);
  }
  const excluded = Object.values(classification.excluded).reduce(
    (totals, category) => ({
      files: totals.files + category.files,
      bytes: totals.bytes + category.bytes,
    }),
    { files: 0, bytes: 0 },
  );
  const firstPartyBytes = classification.firstPartyText.reduce(
    (total, file) => total + file.bytes,
    0,
  );
  if (
    excluded.files + classification.firstPartyText.length !==
      inventory.totals.files ||
    excluded.bytes + firstPartyBytes !== inventory.totals.bytes
  )
    return false;
  for (const name of ["osv", "zizmor", "malcontent"] as const)
    if (
      classification.applicability[name] !==
        classification.scannerInputs[name].length > 0 ||
      classification.scannerInputs[name].some(
        (file) => !inventoryByPath.has(file.path),
      )
    )
      return false;
  return true;
}

function scannerOptions(spec: ScanRepositorySpec) {
  return {
    ...(spec.executables === undefined
      ? {}
      : { executables: spec.executables }),
    ...(spec.temporaryRoot === undefined
      ? {}
      : { temporaryRoot: spec.temporaryRoot }),
  };
}

export async function scanRepository(
  spec: ScanRepositorySpec,
  dependencies: ScanDependencies = defaultDependencies,
): Promise<ScanResult> {
  try {
    const target = TargetSchema.safeParse(spec.target);
    if (
      !target.success ||
      spec.projectKinds.length === 0 ||
      spec.scannerPolicyVersion !== spec.policy.version ||
      spec.policy.version !== "2" ||
      spec.ruleCatalogVersion !== "1"
    )
      return failure(
        "INVALID_SCAN_SPEC",
        "system",
        "Scan configuration failed validation.",
      );

    const inventoryResult = await dependencies.inventory({
      root: spec.root,
      maxFiles: spec.policy.inventory.maxFiles,
      maxTotalBytes: spec.policy.inventory.maxTotalBytes,
      maxFileBytes: spec.policy.inventory.maxFileBytes,
    });
    if (!inventoryResult.ok)
      return failure(
        inventoryResult.error.code,
        "repository",
        "Repository inventory did not complete.",
      );
    const inventory = inventoryResult.value;
    if (!inventoryIsConsistent(inventory))
      return failure(
        "INVENTORY_INVALID",
        "system",
        "Repository inventory totals are inconsistent.",
      );
    const classification = dependencies.classify(inventory);
    if (!classificationIsConsistent(inventory, classification))
      return failure(
        "CLASSIFICATION_INVALID",
        "system",
        "Repository classification does not partition the inventory.",
      );

    const history = await dependencies.history(
      spec.root,
      spec.previousReportShas,
      spec.runner,
    );
    if (!history.ok)
      return failure(
        history.error.code,
        "repository",
        "Bounded repository history did not complete.",
      );
    const structuralFindings = await dependencies.structuralScan(
      spec.root,
      classification.firstPartyText,
    );
    const scannerRuns = await dependencies.scanners({
      root: spec.root,
      history: {
        baseSha: history.value.baseSha,
        targetSha: target.data.target_sha,
        commits: history.value.historyCommits,
      },
      classification,
      structuralFiles: [],
      structuralFindings,
      runner: spec.runner,
      policy: spec.policy,
      pins: spec.pins,
      rulesRoot: spec.rulesRoot,
      ...scannerOptions(spec),
    });
    validateScannerRuns(
      scannerRuns,
      classification,
      structuralFindings,
      scannerVersions(spec),
    );
    const orderedRuns = canonicalScannerRuns(scannerRuns);
    const verifiedHead = await dependencies.verifyHead(
      spec.root,
      target.data.target_sha,
      spec.runner,
    );
    if (!verifiedHead.ok)
      return failure(
        verifiedHead.error.code,
        "repository",
        "Repository head changed before deterministic finalization.",
      );

    const scanPackage = buildScanPackage({
      target: target.data,
      history: {
        baseSha: history.value.baseSha,
        commits: history.value.historyCommits,
      },
      scannerVersion: spec.scannerVersion,
      scannerPolicyVersion: spec.scannerPolicyVersion,
      ruleCatalogVersion: spec.ruleCatalogVersion,
      inventory,
      classification,
      tools: [
        {
          name: "inventory",
          version: spec.scannerVersion,
          status: "completed",
        },
        ...orderedRuns,
      ],
      findings: orderedRuns.flatMap(({ findings }) => findings),
    });
    return {
      ok: true,
      value: {
        report: buildDeterministicReport(scanPackage, {
          targetSha: target.data.target_sha,
          completedAt: spec.completedAt,
          reportVersion: spec.reportVersion,
          supersedesReportId: spec.supersedesReportId,
        }),
      },
    };
  } catch (error) {
    if (error instanceof ScannerError)
      return failure(error.code, error.scope, error.message);
    return failure(
      "REPORT_INVALID",
      "system",
      "Atomic deterministic scan assembly failed validation.",
    );
  }
}

export type { ScannerErrorCode };
