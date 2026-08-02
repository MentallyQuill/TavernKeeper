import { createHash } from "node:crypto";

import {
  buildModelConcernCounts,
  deriveV3Result,
  FindingSchema,
  type Finding,
  type ScanMode,
  type ScanReportV3,
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
import { reviewRepositoryWithConfiguredModel } from "../model/model-review.js";
import {
  ModelRequestError,
  validateModelEndpoint,
} from "../model/openai-compatible-client.js";
import type { ValidatedRepositorySynthesis } from "../model/repository-synthesis.js";
import { buildEvidenceManifest } from "../model/evidence-manifest.js";
import type { CommandRunner } from "../process/command-runner.js";
import { reportIdentity } from "../publish/report-path.js";
import { sanitizeReportV3 } from "../publish/sanitize.js";
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
  projectKinds: readonly ("extension" | "frontend" | "preset")[];
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
  review: typeof reviewRepositoryWithConfiguredModel;
}

export interface SanitizedCandidate {
  report: ScanReportV3;
}

export interface ScanFailure {
  code: string;
  scope: "repository" | "system";
  message: string;
}

export type ScanResult =
  { ok: true; value: SanitizedCandidate } | { ok: false; error: ScanFailure };

export async function scanStructuralFiles(
  root: string,
  files: InventoryFile[],
) {
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
  review: reviewRepositoryWithConfiguredModel,
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

export function validateChunkCoverage(
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
  model,
  endpoint,
  identifier,
}: {
  chunks: ModelChunk[];
  model: Awaited<ReturnType<typeof reviewRepositoryWithConfiguredModel>>;
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
  if (
    model.stageCompletion.chunkReview.required !== chunks.length ||
    model.stageCompletion.chunkReview.completed !== chunks.length ||
    model.stageCompletion.synthesis.required !== 1 ||
    model.stageCompletion.synthesis.completed !== 1
  )
    throw new ModelRequestError(
      "MODEL_INVALID_RESPONSE",
      "system",
      "Configured model stage completion is incomplete.",
    );
}

function projectV3ReportSections(
  tools: Array<{
    name: string;
    version: string;
    status: "completed" | "not-applicable";
  }>,
  chunks: readonly ModelChunk[],
  deterministicFindings: readonly Finding[],
  synthesis: ValidatedRepositorySynthesis,
  targetSha: string,
) {
  const normalizedOrigin = (origin: string) =>
    origin === "tavernkeeper" ? "tavernkeeper-static" : origin;
  const manifest = buildEvidenceManifest(
    chunks,
    deterministicFindings,
    targetSha,
  );
  const coveredTools = new Set(tools.map(({ name }) => name));
  if (
    manifest.scannerSignals.some(
      ({ origin }) => !coveredTools.has(normalizedOrigin(origin)),
    )
  )
    throw new Error("Deterministic signal origin is missing tool coverage.");
  const tool_results = tools.map((tool) => ({
    ...tool,
    signals: manifest.scannerSignals
      .filter(({ origin }) => normalizedOrigin(origin) === tool.name)
      .map(
        ({
          id,
          rule_id,
          category,
          severity,
          confidence,
          title,
          path,
          line_start,
          line_end,
        }) => ({
          evidence_id: id,
          rule_id,
          category,
          severity,
          confidence,
          title,
          path,
          line_start,
          line_end,
        }),
      ),
  }));
  const model_review = {
    assessment: synthesis.assessment,
    recap: synthesis.recap,
    concerns: synthesis.concerns.map((concern) => ({
      id: concern.id,
      category: concern.category,
      severity: concern.severity,
      confidence: concern.confidence,
      title: concern.title,
      explanation: concern.explanation,
      evidence: concern.evidence.map((evidence) => ({
        evidence_id: evidence.evidenceId,
        kind: evidence.kind,
        path: evidence.path,
        line_start: evidence.lineStart,
        line_end: evidence.lineEnd,
        target_sha: evidence.targetSha,
      })),
    })),
  };
  return { tool_results, model_review };
}

type V3IdentityBody = Pick<
  ScanReportV3,
  | "report_version"
  | "supersedes_report_id"
  | "scanner_version"
  | "scanner_policy_version"
  | "prompt_policy_version"
  | "source_id"
  | "provider"
  | "repository_id"
  | "repository"
  | "canonical_url"
  | "target_sha"
  | "completed_at"
  | "mode"
>;

export function assembleAndSanitizeReportV3({
  identity,
  history,
  inventory,
  tools,
  model,
  chunks,
  deterministicFindings,
  synthesis,
}: {
  identity: V3IdentityBody;
  history: ScanReportV3["history"];
  inventory: ScanReportV3["coverage"]["inventory"];
  tools: ScanReportV3["coverage"]["tools"];
  model: ScanReportV3["coverage"]["model"];
  chunks: readonly ModelChunk[];
  deterministicFindings: readonly Finding[];
  synthesis: ValidatedRepositorySynthesis;
}) {
  const sections = projectV3ReportSections(
    tools,
    chunks,
    deterministicFindings,
    synthesis,
    identity.target_sha,
  );
  const withoutId: Omit<ScanReportV3, "report_id"> = {
    schema_version: 3,
    ...identity,
    history,
    coverage: {
      inventory,
      tools,
      model,
      evidence_validation: {
        status: "completed",
        validated_findings: sections.model_review.concerns.length,
      },
    },
    result: deriveV3Result(sections.model_review),
    finding_counts: buildModelConcernCounts(sections.model_review.concerns),
    ...sections,
  };
  return sanitizeReportV3({
    ...withoutId,
    report_id: reportIdentity(withoutId),
  });
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
  model: Awaited<ReturnType<typeof reviewRepositoryWithConfiguredModel>>;
}) {
  const tools = [
    {
      name: "inventory",
      version: spec.scannerVersion,
      status: "completed" as const,
    },
    ...scannerRuns.map(({ name, version, status }) => ({
      name,
      version,
      status,
    })),
  ];
  const deterministicFindings = scannerRuns.flatMap(({ findings }) => findings);
  const eligibleTextBytes = classification.modelEligible.reduce(
    (total, file) => total + file.bytes,
    0,
  );
  return assembleAndSanitizeReportV3({
    identity: {
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
    },
    history: {
      base_sha: history.value.baseSha,
      commits: history.value.historyCommits,
    },
    inventory: {
      files: inventory.totals.files,
      bytes: inventory.totals.bytes,
      eligible_text_files: classification.modelEligible.length,
      eligible_text_bytes: eligibleTextBytes,
      excluded: classification.excluded,
    },
    tools,
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
    chunks,
    deterministicFindings,
    synthesis: model.synthesis,
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
      spec.projectKinds.length === 0 ||
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

    const selected = selectModelCorpus({ classification });
    const corpus = await dependencies.loadCorpus(spec.root, selected);
    const chunks = dependencies.chunk(corpus, {
      chunkBytes: spec.policy.model.chunkBytes,
      overlapBytes: spec.policy.model.chunkOverlapBytes,
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
      targetSha: target.data.target_sha,
      projectKinds: spec.projectKinds,
      chunks,
      deterministicFindings,
      tools: [
        { name: "inventory", status: "completed" as const },
        ...orderedScannerRuns.map(({ name, status }) => ({ name, status })),
      ],
      promptPolicyVersion: spec.promptPolicyVersion,
      scannerPolicyVersion: spec.scannerPolicyVersion,
      chunkReviewPolicy: spec.policy.model.chunkReviewPolicy,
      synthesisPolicy: spec.policy.model.synthesisPolicy,
      maxOutputTokensPerChunkReview:
        spec.policy.model.maxOutputTokensPerChunkReview,
      maxChunkReviewCharacters: spec.policy.model.maxChunkReviewCharacters,
      maxOutputTokensForSynthesis:
        spec.policy.model.maxOutputTokensForSynthesis,
      cache: spec.model.cache,
    });
    validateModelCoverage({
      chunks,
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
