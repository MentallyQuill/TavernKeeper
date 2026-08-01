import { createHash } from "node:crypto";

import {
  buildFindingCounts,
  deriveResult,
  FindingSchema,
  ScanReportSchema,
  type Finding,
  type ScanMode,
  type ScanReport,
} from "../contracts/reports.js";
import { TargetSchema, type Target } from "../contracts/targets.js";
import type { ScannerPolicy } from "../config/policy.js";
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
import type { ModelChunkCache } from "../model/chunk-cache.js";
import { chunkCorpus, type ModelChunk } from "../model/chunker.js";
import {
  loadModelCorpus,
  selectModelCorpus,
  type ModelCorpusFile,
} from "../model/corpus.js";
import { ModelCacheError } from "../model/chunk-cache.js";
import { reviewWithConfiguredModel } from "../model/model-review.js";
import {
  ModelRequestError,
  validateModelEndpoint,
} from "../model/openai-compatible-client.js";
import type { ModelRelationship } from "../model/synthesis.js";
import type { CommandRunner } from "../process/command-runner.js";
import {
  runApplicableScanners,
  type ApplicableScannerSpec,
  type ScannerExecutables,
  type ScannerVersionPins,
} from "../scanners/run-scanners.js";
import { scanStaticRules } from "../scanners/static-rules.js";
import {
  ScannerError,
  type ScannerErrorCode,
  type ScannerRun,
} from "../scanners/types.js";

export interface ScanRepositorySpec {
  target: Target;
  root: string;
  previousReportShas: string[];
  completedAt: string;
  scannerVersion: string;
  scannerPolicyVersion: string;
  promptPolicyVersion: string;
  reportVersion: number;
  supersedesReportId: string | null;
  mode: ScanMode;
  policy: ScannerPolicy;
  pins: ScannerVersionPins;
  rulesRoot: string;
  runner: CommandRunner;
  relationships?: ModelRelationship[];
  executables?: Partial<ScannerExecutables>;
  temporaryRoot?: string;
  model: {
    endpoint: string;
    apiKey: string | null;
    identifier: string;
    cache: ModelChunkCache;
  };
}

export interface ScanDependencies {
  inventory(spec: InventorySpec): ReturnType<typeof inventoryRepository>;
  classify(inventory: Inventory): InventoryClassification;
  history: typeof planHistory;
  structuralScan(root: string, files: InventoryFile[]): Promise<Finding[]>;
  scanners(spec: ApplicableScannerSpec): Promise<ScannerRun[]>;
  loadCorpus(
    root: string,
    selected: InventoryFile[],
  ): Promise<ModelCorpusFile[]>;
  chunk(
    files: ModelCorpusFile[],
    policy: Parameters<typeof chunkCorpus>[1],
  ): ModelChunk[];
  verifyHead: typeof verifyExactHead;
  review: typeof reviewWithConfiguredModel;
}

export interface SanitizedCandidate {
  report: ScanReport;
}

export interface ScanFailure {
  code: string;
  scope: "repository" | "system";
  message: string;
}

export type ScanResult =
  { ok: true; value: SanitizedCandidate } | { ok: false; error: ScanFailure };

async function scanStructuralFiles(root: string, files: InventoryFile[]) {
  const findings: Finding[] = [];
  for (const file of files) {
    const loaded = await loadModelCorpus(root, [file]);
    findings.push(...scanStaticRules(loaded));
  }
  return findings.sort((left, right) =>
    left.fingerprint.localeCompare(right.fingerprint),
  );
}

const defaultDependencies: ScanDependencies = {
  inventory: inventoryRepository,
  classify: classifyInventory,
  history: planHistory,
  structuralScan: scanStructuralFiles,
  scanners: runApplicableScanners,
  loadCorpus: loadModelCorpus,
  chunk: chunkCorpus,
  verifyHead: verifyExactHead,
  review: reviewWithConfiguredModel,
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

function validateScannerRuns(
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

function canonicalScannerRuns(runs: ScannerRun[]) {
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

function inventoryIsConsistent(inventory: Inventory) {
  return (
    inventory.totals.files === inventory.files.length &&
    inventory.totals.bytes ===
      inventory.files.reduce((total, file) => total + file.bytes, 0) &&
    inventory.totalBytes === inventory.totals.bytes &&
    new Set(inventory.files.map(({ path }) => path)).size ===
      inventory.files.length
  );
}

function classificationIsConsistent(
  inventory: Inventory,
  classification: InventoryClassification,
) {
  const inventoryByPath = new Map(
    inventory.files.map((file) => [file.path, file]),
  );
  const eligiblePaths = new Set<string>();
  for (const file of classification.modelEligible) {
    const inventoried = inventoryByPath.get(file.path);
    if (
      eligiblePaths.has(file.path) ||
      inventoried === undefined ||
      inventoried.kind !== "text" ||
      inventoried.bytes !== file.bytes ||
      inventoried.sha256 !== file.sha256
    )
      return false;
    eligiblePaths.add(file.path);
  }
  const excluded = Object.values(classification.excluded).reduce(
    (totals, category) => ({
      files: totals.files + category.files,
      bytes: totals.bytes + category.bytes,
    }),
    { files: 0, bytes: 0 },
  );
  const eligibleBytes = classification.modelEligible.reduce(
    (total, file) => total + file.bytes,
    0,
  );
  if (
    excluded.files + classification.modelEligible.length !==
      inventory.totals.files ||
    excluded.bytes + eligibleBytes !== inventory.totals.bytes
  )
    return false;
  for (const name of ["osv", "zizmor", "malcontent"] as const) {
    if (
      classification.applicability[name] !==
        classification.scannerInputs[name].length > 0 ||
      classification.scannerInputs[name].some(
        (file) => !inventoryByPath.has(file.path),
      )
    )
      return false;
  }
  return true;
}

function validateChunkCoverage(
  selected: InventoryFile[],
  chunks: ModelChunk[],
) {
  const selectedByPath = new Map(selected.map((file) => [file.path, file]));
  const submittedPaths = new Set<string>();
  let invalid = false;
  for (const chunk of chunks) {
    const expectedHashes = chunk.segments.map(
      ({ content_hash }) => content_hash,
    );
    if (
      chunk.bytes !==
        chunk.segments.reduce((total, segment) => total + segment.bytes, 0) ||
      JSON.stringify(chunk.content_hashes) !== JSON.stringify(expectedHashes)
    )
      invalid = true;
    for (const segment of chunk.segments) {
      submittedPaths.add(segment.path);
      const selectedFile = selectedByPath.get(segment.path);
      if (
        selectedFile === undefined ||
        segment.source_sha256 !== selectedFile.sha256 ||
        segment.bytes !== Buffer.byteLength(segment.content, "utf8") ||
        segment.content_hash !==
          createHash("sha256").update(segment.content).digest("hex")
      )
        invalid = true;
    }
  }
  if (
    invalid ||
    submittedPaths.size !== selectedByPath.size ||
    selected.some(({ path }) => !submittedPaths.has(path))
  )
    throw new ModelRequestError(
      "MODEL_INVALID_RESPONSE",
      "system",
      "Model chunk plan does not exactly cover eligible source paths.",
    );
}

function validateModelCoverage({
  chunks,
  deterministicFindings,
  model,
  endpoint,
  identifier,
}: {
  chunks: ModelChunk[];
  deterministicFindings: Finding[];
  model: Awaited<ReturnType<typeof reviewWithConfiguredModel>>;
  endpoint: string;
  identifier: string;
}) {
  const expectedChunkIds = chunks.map(({ id }) => id);
  const expectedOrigin = new URL(endpoint).origin;
  if (
    model.endpointOrigin !== expectedOrigin ||
    model.provider !== new URL(endpoint).hostname ||
    model.model !== identifier ||
    JSON.stringify(model.completedChunkIds) !== JSON.stringify(expectedChunkIds)
  )
    throw new ModelRequestError(
      "MODEL_INVALID_RESPONSE",
      "system",
      "Configured model coverage identity is incomplete.",
    );
  const finalFingerprints = new Set(
    model.findings.map(({ fingerprint }) => fingerprint),
  );
  if (
    deterministicFindings.some(
      ({ fingerprint }) => !finalFingerprints.has(fingerprint),
    )
  )
    throw new ModelRequestError(
      "MODEL_INVALID_RESPONSE",
      "system",
      "Final synthesis removed deterministic evidence.",
    );
}

function reportId(input: Omit<ScanReport, "report_id">) {
  return createHash("sha256")
    .update(
      JSON.stringify({
        schema_version: input.schema_version,
        scanner_version: input.scanner_version,
        scanner_policy_version: input.scanner_policy_version,
        prompt_policy_version: input.prompt_policy_version,
        source_id: input.source_id,
        repository_id: input.repository_id,
        target_sha: input.target_sha,
        completed_at: input.completed_at,
        mode: input.mode,
        report_version: input.report_version,
        supersedes_report_id: input.supersedes_report_id,
      }),
    )
    .digest("hex");
}

function buildReport({
  spec,
  inventory,
  classification,
  history,
  scannerRuns,
  chunks,
  model,
}: {
  spec: ScanRepositorySpec;
  inventory: Inventory;
  classification: InventoryClassification;
  history: Awaited<ReturnType<typeof planHistory>> & { ok: true };
  scannerRuns: ScannerRun[];
  chunks: ModelChunk[];
  model: Awaited<ReturnType<typeof reviewWithConfiguredModel>>;
}) {
  const findings = [...model.findings].sort((left, right) =>
    left.fingerprint.localeCompare(right.fingerprint),
  );
  const eligibleTextBytes = classification.modelEligible.reduce(
    (total, file) => total + file.bytes,
    0,
  );
  const withoutId: Omit<ScanReport, "report_id"> = {
    schema_version: 1,
    report_version: spec.reportVersion,
    supersedes_report_id: spec.supersedesReportId,
    scanner_version: spec.scannerVersion,
    scanner_policy_version: spec.scannerPolicyVersion,
    prompt_policy_version: spec.promptPolicyVersion,
    source_id: spec.target.source_id,
    provider: "github",
    repository_id: spec.target.repository_id,
    repository: spec.target.repository,
    canonical_url: spec.target.canonical_url,
    target_sha: spec.target.target_sha,
    completed_at: spec.completedAt,
    mode: spec.mode,
    history: {
      base_sha: history.value.baseSha,
      commits: history.value.historyCommits,
    },
    coverage: {
      inventory: {
        files: inventory.totals.files,
        bytes: inventory.totals.bytes,
        eligible_text_files: classification.modelEligible.length,
        eligible_text_bytes: eligibleTextBytes,
        excluded: classification.excluded,
      },
      tools: [
        {
          name: "inventory",
          version: spec.scannerVersion,
          status: "completed",
        },
        ...scannerRuns.map(({ name, version, status }) => ({
          name,
          version,
          status,
        })),
      ],
      model: {
        status: "completed",
        endpoint_origin: model.endpointOrigin,
        provider: model.provider,
        model: model.model,
        input_chunks: chunks.length,
        completed_chunks: model.completedChunkIds.length,
        input_tokens: model.usage.inputTokens,
        output_tokens: model.usage.outputTokens,
        cache_read_tokens: model.usage.cacheReadTokens,
        reasoning_tokens: model.usage.reasoningTokens,
        total_tokens: model.usage.inputTokens + model.usage.outputTokens,
      },
    },
    result: deriveResult(findings),
    finding_counts: buildFindingCounts(findings),
    findings,
  };
  return ScanReportSchema.parse({
    ...withoutId,
    report_id: reportId(withoutId),
  });
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
    let endpointValid = true;
    try {
      validateModelEndpoint(spec.model.endpoint);
    } catch {
      endpointValid = false;
    }
    if (
      !target.success ||
      spec.scannerPolicyVersion !== spec.policy.version ||
      spec.model.identifier.trim() === "" ||
      spec.model.apiKey === null ||
      spec.model.apiKey.trim() === "" ||
      !endpointValid
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
      classification.modelEligible,
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
    const orderedScannerRuns = canonicalScannerRuns(scannerRuns);
    const deterministicFindings = orderedScannerRuns.flatMap(
      ({ findings }) => findings,
    );

    const selected = selectModelCorpus({
      mode: spec.mode,
      classification,
      changedPaths: history.value.changedPaths,
      findingPaths: deterministicFindings.map(({ path }) => path),
    });
    const corpus = await dependencies.loadCorpus(spec.root, selected);
    const chunks = dependencies.chunk(corpus, {
      chunkBytes: spec.policy.model.chunkBytes,
      overlapBytes: spec.policy.model.chunkOverlapBytes,
      modelIdentifier: spec.model.identifier,
      promptPolicyVersion: spec.promptPolicyVersion,
      scannerPolicyVersion: spec.scannerPolicyVersion,
    });
    validateChunkCoverage(selected, chunks);

    const verifiedHead = await dependencies.verifyHead(
      spec.root,
      target.data.target_sha,
      spec.runner,
    );
    if (!verifiedHead.ok)
      return failure(
        verifiedHead.error.code,
        "repository",
        "Repository head changed before configured-model review.",
      );

    const model = await dependencies.review({
      endpoint: spec.model.endpoint,
      apiKey: spec.model.apiKey,
      model: spec.model.identifier,
      chunks,
      deterministicFindings,
      relationships: spec.relationships ?? [],
      promptPolicyVersion: spec.promptPolicyVersion,
      scannerPolicyVersion: spec.scannerPolicyVersion,
      maxOutputTokensPerChunk: spec.policy.model.maxOutputTokensPerChunk,
      maxSynthesisOutputTokens: spec.policy.model.maxSynthesisOutputTokens,
      cache: spec.model.cache,
    });
    validateModelCoverage({
      chunks,
      deterministicFindings,
      model,
      endpoint: spec.model.endpoint,
      identifier: spec.model.identifier,
    });

    return {
      ok: true,
      value: {
        report: buildReport({
          spec,
          inventory,
          classification,
          history,
          scannerRuns: orderedScannerRuns,
          chunks,
          model,
        }),
      },
    };
  } catch (error) {
    if (error instanceof ScannerError)
      return failure(error.code, error.scope, error.message);
    if (error instanceof ModelRequestError)
      return failure(
        error.code,
        error.code === "MODEL_INVALID_RESPONSE" ? "repository" : error.scope,
        error.message,
      );
    if (error instanceof ModelCacheError)
      return failure(error.code, error.scope, error.message);
    return failure(
      "REPORT_INVALID",
      "system",
      "Atomic scan assembly failed validation.",
    );
  }
}

export type { ScannerErrorCode };
