import { createHash, randomUUID } from "node:crypto";
import {
  access,
  mkdir,
  readFile,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { basename, resolve, sep } from "node:path";

import { z } from "zod";

import type { ScannerPins, ScannerPolicy } from "../config/policy.js";
import {
  FindingSchema,
  ScanModeSchema,
  ScanReportV3Schema,
  ToolCoverageSchema,
} from "../contracts/reports.js";
import {
  FullShaSchema,
  parseTargetManifest,
  requireTargetManifestV2,
  TargetSchema,
} from "../contracts/targets.js";
import { checkoutExactTarget } from "../git/checkout.js";
import { planHistory } from "../git/history.js";
import { classifyInventory } from "../inventory/classify.js";
import { inventoryRepository } from "../inventory/inventory-handler.js";
import type { ModelChunkCache } from "../model/chunk-cache.js";
import { chunkCorpus, type ModelChunk } from "../model/chunker.js";
import { loadModelCorpus, selectModelCorpus } from "../model/corpus.js";
import { buildEvidenceManifest } from "../model/evidence-manifest.js";
import { reviewRepositoryWithConfiguredModel } from "../model/model-review.js";
import {
  requestTextCompletion as defaultRequestTextCompletion,
  validateModelEndpoint,
  type RequestStructuredCompletion,
} from "../model/openai-compatible-client.js";
import { validateRepositorySynthesis } from "../model/repository-synthesis.js";
import { RepositorySynthesisSchema } from "../model/review-contracts.js";
import type { CommandRunner } from "../process/command-runner.js";
import {
  runApplicableScanners,
  type ScannerExecutables,
} from "../scanners/run-scanners.js";
import {
  canonicalScannerRuns,
  classificationIsConsistent,
  inventoryIsConsistent,
  assembleAndSanitizeReportV3,
  scanStructuralFiles,
  validateChunkCoverage,
  validateScannerRuns,
} from "./scan-handler.js";

const DigestSchema = z.string().regex(/^[0-9a-f]{64}$/u);
const VersionSchema = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/u);
const RepositoryPathSchema = z
  .string()
  .min(1)
  .max(500)
  .refine(
    (value) =>
      !value.includes("\\") &&
      !value.startsWith("/") &&
      !/^[A-Za-z]:/u.test(value) &&
      value.split("/").every((part) => !["", ".", ".."].includes(part)),
  );
const NonNegativeIntegerSchema = z.number().int().nonnegative();
const FileByteTotalsSchema = z.strictObject({
  files: NonNegativeIntegerSchema,
  bytes: NonNegativeIntegerSchema,
});
const InventoryCoverageSchema = z.strictObject({
  files: NonNegativeIntegerSchema,
  bytes: NonNegativeIntegerSchema,
  eligible_text_files: NonNegativeIntegerSchema,
  eligible_text_bytes: NonNegativeIntegerSchema,
  excluded: z.strictObject({
    dependency_lockfiles: FileByteTotalsSchema,
    vendored_dependencies: FileByteTotalsSchema,
    generated_bundles: FileByteTotalsSchema,
    minified_files: FileByteTotalsSchema,
    binaries: FileByteTotalsSchema,
    archives: FileByteTotalsSchema,
    oversized_files: FileByteTotalsSchema,
    unsafe_entries: FileByteTotalsSchema,
  }),
});
const SelectedFileSchema = z.strictObject({
  path: RepositoryPathSchema,
  bytes: NonNegativeIntegerSchema,
  sha256: DigestSchema,
});
const ChunkManifestSchema = z.strictObject({
  id: DigestSchema,
  file: z.string().regex(/^chunks\/[0-9]{6}\.json$/u),
  bytes: NonNegativeIntegerSchema,
  content_hashes: z.array(DigestSchema),
  paths: z.array(RepositoryPathSchema),
});
const SegmentSchema = z.strictObject({
  path: RepositoryPathSchema,
  line_start: z.number().int().positive(),
  line_end: z.number().int().positive(),
  content: z.string(),
  bytes: NonNegativeIntegerSchema,
  overlap_bytes: NonNegativeIntegerSchema,
  content_hash: DigestSchema,
  source_sha256: DigestSchema,
});
const ModelChunkSchema = z.strictObject({
  id: DigestSchema,
  bytes: NonNegativeIntegerSchema,
  content_hashes: z.array(DigestSchema),
  segments: z.array(SegmentSchema).min(1),
});

const PreparedSessionObjectSchema = z.strictObject({
  schema_version: z.literal(3),
  session_id: DigestSchema,
  target: TargetSchema,
  project_kinds: z.array(z.enum(["extension", "frontend", "preset"])).min(1),
  prepared_at: z.iso.datetime(),
  scanner_version: VersionSchema,
  scanner_policy_version: VersionSchema,
  prompt_policy_version: VersionSchema,
  report_version: z.number().int().positive(),
  supersedes_report_id: DigestSchema.nullable(),
  mode: ScanModeSchema,
  history: z.strictObject({
    base_sha: FullShaSchema.nullable(),
    commits: z.number().int().min(1).max(20),
  }),
  inventory: InventoryCoverageSchema,
  tools: z.array(ToolCoverageSchema).min(1),
  deterministic_findings: z.array(FindingSchema),
  selected_files: z.array(SelectedFileSchema),
  chunks: z.array(ChunkManifestSchema),
});

export const PreparedSessionSchema = PreparedSessionObjectSchema.superRefine(
  (session, context) => {
    if (
      session.project_kinds.some(
        (kind, index) => index > 0 && session.project_kinds[index - 1]! >= kind,
      )
    ) {
      context.addIssue({
        code: "custom",
        path: ["project_kinds"],
        message: "Prepared project kinds must be unique and sorted.",
      });
    }
    for (const [path, values] of [
      ["selected_files", session.selected_files.map(({ path }) => path)],
      ["chunks", session.chunks.map(({ id }) => id)],
      ["chunks", session.chunks.map(({ file }) => file)],
    ] as const)
      if (new Set(values).size !== values.length)
        context.addIssue({
          code: "custom",
          path: [path],
          message: "Prepared session identities must be unique.",
        });
    const selected = new Set(session.selected_files.map(({ path }) => path));
    const submitted = new Set(session.chunks.flatMap(({ paths }) => paths));
    if (
      selected.size !== submitted.size ||
      [...selected].some((path) => !submitted.has(path))
    )
      context.addIssue({
        code: "custom",
        path: ["chunks"],
        message: "Prepared chunks must cover every selected file.",
      });
  },
);

type PreparedSession = z.infer<typeof PreparedSessionSchema>;

export class ScanPhaseError extends Error {
  constructor(
    readonly code: string,
    readonly scope: "repository" | "system",
    message: string,
  ) {
    super(message);
    this.name = "ScanPhaseError";
  }
}

const ModelUsageSchema = z.strictObject({
  inputTokens: NonNegativeIntegerSchema,
  outputTokens: NonNegativeIntegerSchema,
  cacheReadTokens: NonNegativeIntegerSchema,
  reasoningTokens: NonNegativeIntegerSchema,
});
const CompletedReviewSchema = z.strictObject({
  schema_version: z.literal(3),
  session_id: DigestSchema,
  status: z.literal("completed"),
  endpoint_origin: z.url(),
  provider: VersionSchema,
  model: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$/u),
  completed_chunk_ids: z.array(DigestSchema),
  synthesis: RepositorySynthesisSchema,
  stage_completion: z.strictObject({
    chunk_review: z.strictObject({
      required: NonNegativeIntegerSchema,
      completed: NonNegativeIntegerSchema,
    }),
    synthesis: z.strictObject({
      required: z.literal(1),
      completed: z.literal(1),
    }),
  }),
  usage: ModelUsageSchema,
  cache_hits: NonNegativeIntegerSchema,
  cache_misses: NonNegativeIntegerSchema,
});
const ObsoleteReviewSchema = z.strictObject({
  schema_version: z.literal(3),
  session_id: DigestSchema,
  status: z.literal("obsolete"),
  reason: z.literal("target-advanced"),
});
export const SessionReviewSchema = z.discriminatedUnion("status", [
  CompletedReviewSchema,
  ObsoleteReviewSchema,
]);
export type SessionReview = z.infer<typeof SessionReviewSchema>;

function identityFields(session: Omit<PreparedSession, "session_id">) {
  return {
    schema_version: session.schema_version,
    target: session.target,
    project_kinds: session.project_kinds,
    scanner_version: session.scanner_version,
    scanner_policy_version: session.scanner_policy_version,
    prompt_policy_version: session.prompt_policy_version,
    report_version: session.report_version,
    supersedes_report_id: session.supersedes_report_id,
    mode: session.mode,
    history: session.history,
    inventory: session.inventory,
    tools: session.tools,
    deterministic_fingerprints: session.deterministic_findings.map(
      ({ fingerprint }) => fingerprint,
    ),
    selected_files: session.selected_files,
    chunks: session.chunks,
  };
}

export function preparedSessionIdentity(
  input: Omit<PreparedSession, "session_id"> | Record<string, unknown>,
) {
  const identityInput: Record<string, unknown> = { ...input };
  delete identityInput.session_id;
  const parsed = PreparedSessionObjectSchema.omit({ session_id: true }).parse(
    identityInput,
  );
  return createHash("sha256")
    .update(JSON.stringify(identityFields(parsed)))
    .digest("hex");
}

async function pathExists(path: string) {
  try {
    await access(path);
    return true;
  } catch (error) {
    if (
      error !== null &&
      typeof error === "object" &&
      "code" in error &&
      error.code === "ENOENT"
    )
      return false;
    throw error;
  }
}

function requireEphemeralPath(path: string, prefix: string) {
  const resolved = resolve(path);
  if (!basename(resolved).startsWith(prefix))
    throw new Error("Ephemeral scan path name is unsafe.");
  return resolved;
}

export async function prepareTargetSession({
  target: targetInput,
  projectKinds,
  checkoutRoot: checkoutRootInput,
  sessionRoot: sessionRootInput,
  previousReportShas,
  preparedAt,
  scannerVersion,
  scannerPolicyVersion,
  promptPolicyVersion,
  reportVersion,
  supersedesReportId,
  mode,
  policy,
  pins,
  rulesRoot,
  runner,
  executables,
  temporaryRoot,
}: {
  target: unknown;
  projectKinds: readonly ("extension" | "frontend" | "preset")[];
  checkoutRoot: string;
  sessionRoot: string;
  previousReportShas: string[];
  preparedAt: string;
  scannerVersion: string;
  scannerPolicyVersion: string;
  promptPolicyVersion: string;
  reportVersion: number;
  supersedesReportId: string | null;
  mode: z.infer<typeof ScanModeSchema>;
  policy: ScannerPolicy;
  pins: ScannerPins;
  rulesRoot: string;
  runner: CommandRunner;
  executables?: Partial<ScannerExecutables>;
  temporaryRoot?: string;
}) {
  const target = TargetSchema.parse(targetInput);
  if (scannerPolicyVersion !== policy.version || projectKinds.length === 0)
    throw new ScanPhaseError(
      "INVALID_SCAN_SPEC",
      "system",
      "Prepared scanner policy version does not match policy.",
    );
  const checkoutRoot = requireEphemeralPath(
    checkoutRootInput,
    "tavernkeeper-checkout-",
  );
  const sessionRoot = requireEphemeralPath(
    sessionRootInput,
    "tavernkeeper-session-",
  );
  if (
    checkoutRoot === sessionRoot ||
    (await pathExists(checkoutRoot)) ||
    (await pathExists(sessionRoot))
  )
    throw new Error("Ephemeral scan paths must be distinct and absent.");
  let checkoutCreated = false;
  let sessionCreated = false;
  try {
    checkoutCreated = true;
    const checkout = await checkoutExactTarget({
      target,
      destination: checkoutRoot,
      runner,
    });
    if (!checkout.ok)
      throw new ScanPhaseError(
        checkout.error.code,
        "repository",
        "Exact target checkout failed.",
      );
    const inventoryResult = await inventoryRepository({
      root: checkoutRoot,
      maxFiles: policy.inventory.maxFiles,
      maxTotalBytes: policy.inventory.maxTotalBytes,
      maxFileBytes: policy.inventory.maxFileBytes,
    });
    if (!inventoryResult.ok)
      throw new ScanPhaseError(
        inventoryResult.error.code,
        "repository",
        "Repository inventory failed.",
      );
    const inventory = inventoryResult.value;
    if (!inventoryIsConsistent(inventory))
      throw new ScanPhaseError(
        "INVENTORY_INVALID",
        "system",
        "Repository inventory totals are inconsistent.",
      );
    const classification = classifyInventory(inventory);
    if (!classificationIsConsistent(inventory, classification))
      throw new ScanPhaseError(
        "CLASSIFICATION_INVALID",
        "system",
        "Repository classification is incomplete.",
      );
    const history = await planHistory(checkoutRoot, previousReportShas, runner);
    if (!history.ok)
      throw new ScanPhaseError(
        history.error.code,
        "repository",
        "Repository history failed.",
      );
    const structuralFindings = await scanStructuralFiles(
      checkoutRoot,
      classification.modelEligible,
    );
    const scannerRuns = await runApplicableScanners({
      root: checkoutRoot,
      history: {
        baseSha: history.value.baseSha,
        targetSha: target.target_sha,
        commits: history.value.historyCommits,
      },
      classification,
      structuralFiles: [],
      structuralFindings,
      runner,
      policy,
      pins,
      rulesRoot,
      ...(executables === undefined ? {} : { executables }),
      ...(temporaryRoot === undefined ? {} : { temporaryRoot }),
    });
    validateScannerRuns(scannerRuns, classification, structuralFindings, {
      "tavernkeeper-static": policy.version,
      gitleaks: pins.gitleaks.version,
      opengrep: pins.opengrep.version,
      "osv-scanner": pins.osvScanner.version,
      zizmor: pins.zizmor.version,
      malcontent: pins.malcontent.version,
    });
    const orderedRuns = canonicalScannerRuns(scannerRuns);
    const deterministicFindings = orderedRuns.flatMap(
      ({ findings }) => findings,
    );
    const selected = selectModelCorpus({ classification });
    await mkdir(resolve(sessionRoot, "chunks"), { recursive: true });
    sessionCreated = true;
    const chunks: z.infer<typeof ChunkManifestSchema>[] = [];
    let chunkPosition = 0;
    for (const file of selected) {
      const corpus = await loadModelCorpus(checkoutRoot, [file]);
      const fileChunks = chunkCorpus(corpus, {
        chunkBytes: policy.model.chunkBytes,
        overlapBytes: policy.model.chunkOverlapBytes,
        promptPolicyVersion,
        scannerPolicyVersion,
      });
      validateChunkCoverage([file], fileChunks);
      for (const chunk of fileChunks) {
        const relative = `chunks/${String(chunkPosition).padStart(6, "0")}.json`;
        await writeFile(
          resolve(sessionRoot, ...relative.split("/")),
          `${JSON.stringify(chunk)}\n`,
          { flag: "wx" },
        );
        chunks.push({
          id: chunk.id,
          file: relative,
          bytes: chunk.bytes,
          content_hashes: chunk.content_hashes,
          paths: [...new Set(chunk.segments.map(({ path }) => path))],
        });
        chunkPosition += 1;
      }
    }
    const eligibleTextBytes = classification.modelEligible.reduce(
      (total, file) => total + file.bytes,
      0,
    );
    const withoutIdentity = {
      schema_version: 3 as const,
      target,
      project_kinds: [...projectKinds].sort(),
      prepared_at: preparedAt,
      scanner_version: scannerVersion,
      scanner_policy_version: scannerPolicyVersion,
      prompt_policy_version: promptPolicyVersion,
      report_version: reportVersion,
      supersedes_report_id: supersedesReportId,
      mode,
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
      tools: [
        {
          name: "inventory",
          version: scannerVersion,
          status: "completed" as const,
        },
        ...orderedRuns.map(({ name, version, status }) => ({
          name,
          version,
          status,
        })),
      ],
      deterministic_findings: [...deterministicFindings].sort((left, right) =>
        left.fingerprint.localeCompare(right.fingerprint),
      ),
      selected_files: selected.map(({ path, bytes, sha256 }) => ({
        path,
        bytes,
        sha256,
      })),
      chunks,
    };
    const prepared = PreparedSessionSchema.parse({
      ...withoutIdentity,
      session_id: preparedSessionIdentity(withoutIdentity),
    });
    await writeFile(
      resolve(sessionRoot, "prepared.json"),
      `${JSON.stringify(prepared, null, 2)}\n`,
      { flag: "wx" },
    );
    return { prepared, checkoutRoot, sessionRoot };
  } catch (error) {
    if (sessionCreated) await rm(sessionRoot, { recursive: true, force: true });
    if (checkoutCreated)
      await rm(checkoutRoot, { recursive: true, force: true });
    throw error;
  }
}

async function loadPrepared(sessionRoot: string) {
  const prepared = PreparedSessionSchema.parse(
    JSON.parse(await readFile(resolve(sessionRoot, "prepared.json"), "utf8")),
  );
  if (prepared.session_id !== preparedSessionIdentity(prepared))
    throw new Error("Prepared session identity does not match its contents.");
  return prepared;
}

async function loadChunk(
  sessionRoot: string,
  prepared: PreparedSession,
  position: number,
) {
  const manifest = prepared.chunks[position]!;
  const path = resolve(sessionRoot, ...manifest.file.split("/"));
  const root = resolve(sessionRoot);
  if (!path.startsWith(`${root}${sep}`))
    throw new Error("Prepared chunk path escaped the session.");
  const chunk = ModelChunkSchema.parse(
    JSON.parse(await readFile(path, "utf8")),
  ) as ModelChunk;
  const paths = [...new Set(chunk.segments.map(({ path: value }) => value))];
  if (
    chunk.id !== manifest.id ||
    chunk.bytes !== manifest.bytes ||
    JSON.stringify(chunk.content_hashes) !==
      JSON.stringify(manifest.content_hashes) ||
    JSON.stringify(paths) !== JSON.stringify(manifest.paths)
  )
    throw new Error("Prepared chunk does not match its manifest.");
  validateChunkCoverage(
    prepared.selected_files
      .filter(({ path: value }) => paths.includes(value))
      .map((file) => ({ ...file, kind: "text" as const })),
    [chunk],
  );
  return chunk;
}

export async function reviewPreparedSession({
  sessionRoot,
  manifest: manifestInput,
  endpoint,
  apiKey,
  model,
  policy,
  cache,
  requestTextCompletion,
  requestStructuredCompletion,
  verifyHead,
}: {
  sessionRoot: string;
  manifest: unknown;
  endpoint: string;
  apiKey: string | null;
  model: string;
  policy: ScannerPolicy;
  cache: ModelChunkCache;
  requestTextCompletion?: typeof defaultRequestTextCompletion;
  requestStructuredCompletion?: RequestStructuredCompletion;
  verifyHead: () => Promise<
    { ok: true; value: string } | { ok: false; error: unknown }
  >;
}): Promise<SessionReview> {
  const prepared = await loadPrepared(sessionRoot);
  requireTargetManifestV2(parseTargetManifest(manifestInput));
  if (prepared.scanner_policy_version !== policy.version)
    throw new ScanPhaseError(
      "INVALID_SCAN_SPEC",
      "system",
      "Prepared scanner policy no longer matches.",
    );
  if (!(await verifyHead()).ok)
    throw new ScanPhaseError(
      "HEAD_MISMATCH",
      "repository",
      "Prepared target is no longer valid for model review.",
    );
  const configured = validateModelEndpoint(endpoint);
  const chunks: ModelChunk[] = [];
  for (let position = 0; position < prepared.chunks.length; position += 1) {
    chunks.push(await loadChunk(sessionRoot, prepared, position));
  }
  const reviewed = await reviewRepositoryWithConfiguredModel({
    endpoint,
    apiKey,
    model,
    targetSha: prepared.target.target_sha,
    projectKinds: prepared.project_kinds,
    chunks,
    deterministicFindings: prepared.deterministic_findings,
    tools: prepared.tools.map(({ name, status }) => ({ name, status })),
    promptPolicyVersion: prepared.prompt_policy_version,
    scannerPolicyVersion: prepared.scanner_policy_version,
    chunkReviewPolicy: policy.model.chunkReviewPolicy,
    synthesisPolicy: policy.model.synthesisPolicy,
    maxOutputTokensPerChunkReview: policy.model.maxOutputTokensPerChunkReview,
    maxChunkReviewCharacters: policy.model.maxChunkReviewCharacters,
    maxOutputTokensForSynthesis: policy.model.maxOutputTokensForSynthesis,
    cache,
    ...(requestTextCompletion === undefined ? {} : { requestTextCompletion }),
    ...(requestStructuredCompletion === undefined
      ? {}
      : { requestStructuredCompletion }),
  });
  if (
    reviewed.endpointOrigin !== configured.origin ||
    reviewed.provider !== configured.hostname ||
    reviewed.model !== model
  )
    throw new Error("Model review endpoint identity changed.");
  return CompletedReviewSchema.parse({
    schema_version: 3,
    session_id: prepared.session_id,
    status: "completed",
    endpoint_origin: configured.origin,
    provider: configured.hostname,
    model,
    completed_chunk_ids: reviewed.completedChunkIds,
    synthesis: {
      assessment: reviewed.synthesis.assessment,
      recap: reviewed.synthesis.recap,
      concerns: reviewed.synthesis.concerns.map(
        ({
          title,
          category,
          severity,
          confidence,
          explanation,
          evidence_ids,
        }) => ({
          title,
          category,
          severity,
          confidence,
          explanation,
          evidence_ids,
        }),
      ),
    },
    stage_completion: {
      chunk_review: reviewed.stageCompletion.chunkReview,
      synthesis: reviewed.stageCompletion.synthesis,
    },
    usage: reviewed.usage,
    cache_hits: reviewed.cacheHits,
    cache_misses: reviewed.cacheMisses,
  });
}

function safeSessionRoot(sessionRoot: string) {
  const root = resolve(sessionRoot);
  if (!basename(root).startsWith("tavernkeeper-session-"))
    throw new Error("Ephemeral session directory name is unsafe.");
  return root;
}

async function writeExclusive(path: string, value: unknown) {
  const destination = resolve(path);
  if (await pathExists(destination))
    throw new Error("Candidate output already exists.");
  const temporary = `${destination}.${randomUUID()}.tmp`;
  try {
    await writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`, {
      flag: "wx",
    });
    await rename(temporary, destination);
  } finally {
    await rm(temporary, { force: true });
  }
}

export async function finalizePreparedSession({
  sessionRoot: sessionRootInput,
  review: reviewInput,
  output,
  completedAt,
}: {
  sessionRoot: string;
  review: unknown;
  output: string;
  completedAt: string;
}): Promise<
  | { status: "obsolete" }
  | {
      status: "completed";
      candidate: { report: z.infer<typeof ScanReportV3Schema> };
    }
> {
  const sessionRoot = safeSessionRoot(sessionRootInput);
  const destination = resolve(output);
  if (
    destination === sessionRoot ||
    destination.startsWith(`${sessionRoot}${sep}`)
  )
    throw new Error("Candidate output must be outside the ephemeral session.");
  const prepared = await loadPrepared(sessionRoot);
  try {
    const review = SessionReviewSchema.parse(reviewInput);
    if (review.session_id !== prepared.session_id)
      throw new Error("Model review does not match the prepared session.");
    if (review.status === "obsolete") return { status: "obsolete" };
    const expectedChunkIds = prepared.chunks.map(({ id }) => id);
    if (
      JSON.stringify(review.completed_chunk_ids) !==
      JSON.stringify(expectedChunkIds)
    )
      throw new Error("Model review did not complete every prepared chunk.");
    if (
      review.stage_completion.chunk_review.required !==
        expectedChunkIds.length ||
      review.stage_completion.chunk_review.completed !==
        expectedChunkIds.length ||
      review.stage_completion.synthesis.required !== 1 ||
      review.stage_completion.synthesis.completed !== 1
    )
      throw new Error("Model review did not complete every required stage.");
    const chunks: ModelChunk[] = [];
    for (let position = 0; position < prepared.chunks.length; position += 1)
      chunks.push(await loadChunk(sessionRoot, prepared, position));
    const validatedSynthesis = validateRepositorySynthesis(
      JSON.stringify(review.synthesis),
      buildEvidenceManifest(
        chunks,
        prepared.deterministic_findings,
        prepared.target.target_sha,
      ),
    ).validated;
    const report = assembleAndSanitizeReportV3({
      identity: {
        report_version: prepared.report_version,
        supersedes_report_id: prepared.supersedes_report_id,
        scanner_version: prepared.scanner_version,
        scanner_policy_version: prepared.scanner_policy_version,
        prompt_policy_version: prepared.prompt_policy_version,
        source_id: prepared.target.source_id,
        provider: prepared.target.provider,
        repository_id: prepared.target.repository_id,
        repository: prepared.target.repository,
        canonical_url: prepared.target.canonical_url,
        target_sha: prepared.target.target_sha,
        completed_at: completedAt,
        mode: prepared.mode,
      },
      history: prepared.history,
      inventory: prepared.inventory,
      tools: prepared.tools,
      model: {
        status: "completed",
        endpoint_origin: review.endpoint_origin,
        provider: review.provider,
        model: review.model,
        input_chunks: expectedChunkIds.length,
        completed_chunks: review.completed_chunk_ids.length,
        input_tokens: review.usage.inputTokens,
        output_tokens: review.usage.outputTokens,
        cache_read_tokens: review.usage.cacheReadTokens,
        reasoning_tokens: review.usage.reasoningTokens,
        total_tokens: review.usage.inputTokens + review.usage.outputTokens,
      },
      chunks,
      deterministicFindings: prepared.deterministic_findings,
      synthesis: validatedSynthesis,
    });
    const candidate = { report };
    await writeExclusive(destination, candidate);
    return { status: "completed", candidate };
  } finally {
    await rm(sessionRoot, { recursive: true, force: true });
  }
}
