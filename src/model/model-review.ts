import type { Finding } from "../contracts/reports.js";
import { FullShaSchema } from "../contracts/targets.js";
import { reviewChunk, type CompletedChunkReview } from "./chunk-review.js";
import type { ModelChunkCache } from "./chunk-cache.js";
import type { ModelChunk } from "./chunker.js";
import {
  buildEvidenceManifest,
  type EvidenceManifest,
} from "./evidence-manifest.js";
import {
  ModelRequestError,
  requestStructuredCompletion,
  requestTextCompletion,
  validateModelEndpoint,
  type ModelUsage,
} from "./openai-compatible-client.js";
import {
  synthesizeRepository,
  type ValidatedRepositorySynthesis,
} from "./repository-synthesis.js";

type ProjectKind = "extension" | "frontend" | "preset";
type ToolState = { name: string; status: "completed" | "not-applicable" };

export interface ConfiguredModelReviewSpec {
  endpoint: string;
  apiKey: string | null;
  model: string;
  targetSha: string;
  projectKinds: readonly ProjectKind[];
  chunks: ModelChunk[];
  deterministicFindings: Finding[];
  evidenceManifest?: EvidenceManifest;
  tools?: ToolState[];
  promptPolicyVersion: string;
  scannerPolicyVersion: string;
  chunkReviewPolicy?: string;
  synthesisPolicy?: string;
  maxOutputTokensPerChunkReview?: number;
  maxChunkReviewCharacters?: number;
  maxOutputTokensForSynthesis?: number;
  cache: ModelChunkCache;
  requestTextCompletion?: typeof requestTextCompletion;
  requestStructuredCompletion?: typeof requestStructuredCompletion;
  /** Temporary input compatibility for Task 4 callers. Ignored. */
  relationships?: unknown[];
  /** Temporary input compatibility for Task 4 callers. Ignored. */
  rolePolicies?: Record<string, string>;
  /** Temporary input compatibility for Task 4 callers. */
  maxOutputTokensPerRole?: number;
  /** Temporary input compatibility for Task 4 callers. Ignored. */
  requestCompletion?: typeof requestStructuredCompletion;
}

export interface CompletedModelReview {
  endpointOrigin: string;
  provider: string;
  model: string;
  completedChunkIds: string[];
  synthesis: ValidatedRepositorySynthesis;
  stageCompletion: {
    chunkReview: { required: number; completed: number };
    synthesis: { required: 1; completed: 1 };
  };
  usage: ModelUsage;
  cacheHits: number;
  cacheMisses: number;
}

interface ValidatedConfiguration {
  endpointOrigin: string;
  provider: string;
  apiKey: string;
  evidenceManifest: EvidenceManifest;
  tools: ToolState[];
  chunkReviewPolicy: string;
  synthesisPolicy: string;
  maxOutputTokensPerChunkReview: number;
  maxChunkReviewCharacters: number;
  maxOutputTokensForSynthesis: number;
}

interface CacheCounts {
  hits: number;
  misses: number;
}

const zeroUsage: ModelUsage = {
  inputTokens: 0,
  outputTokens: 0,
  cacheReadTokens: 0,
  reasoningTokens: 0,
};
const ImmediateAttempts = 3;

export function addModelUsage(left: ModelUsage, right: ModelUsage): ModelUsage {
  return {
    inputTokens: left.inputTokens + right.inputTokens,
    outputTokens: left.outputTokens + right.outputTokens,
    cacheReadTokens: left.cacheReadTokens + right.cacheReadTokens,
    reasoningTokens: left.reasoningTokens + right.reasoningTokens,
  };
}

function positiveInteger(value: unknown): value is number {
  return Number.isInteger(value) && Number(value) > 0;
}

function repositoryEvidenceError() {
  return new ModelRequestError(
    "MODEL_INVALID_RESPONSE",
    "repository",
    "Configured repository evidence does not match the requested review.",
    "synthesis_evidence" as never,
  );
}

function validateSpec(spec: ConfiguredModelReviewSpec): ValidatedConfiguration {
  const endpoint = validateModelEndpoint(spec.endpoint);
  const maximumOutput = spec.maxOutputTokensPerRole;
  const maxOutputTokensPerChunkReview =
    spec.maxOutputTokensPerChunkReview ?? maximumOutput;
  const maxOutputTokensForSynthesis =
    spec.maxOutputTokensForSynthesis ?? maximumOutput;
  const maxChunkReviewCharacters =
    spec.maxChunkReviewCharacters ?? maximumOutput;
  if (
    spec.apiKey === null ||
    spec.apiKey.trim() === "" ||
    spec.model.trim() === "" ||
    !FullShaSchema.safeParse(spec.targetSha).success ||
    spec.projectKinds.length === 0 ||
    new Set(spec.projectKinds).size !== spec.projectKinds.length ||
    spec.promptPolicyVersion.trim() === "" ||
    spec.scannerPolicyVersion.trim() === "" ||
    !positiveInteger(maxOutputTokensPerChunkReview) ||
    !positiveInteger(maxChunkReviewCharacters) ||
    !positiveInteger(maxOutputTokensForSynthesis) ||
    new Set(spec.chunks.map(({ id }) => id)).size !== spec.chunks.length
  )
    throw new ModelRequestError(
      "MODEL_CONFIGURATION",
      "system",
      "Configured model review is incomplete or invalid.",
    );

  const canonicalManifest = buildEvidenceManifest(
    spec.chunks,
    spec.deterministicFindings,
    spec.targetSha,
  );
  const evidenceManifest = spec.evidenceManifest ?? canonicalManifest;
  if (JSON.stringify(evidenceManifest) !== JSON.stringify(canonicalManifest))
    throw repositoryEvidenceError();
  const tools =
    spec.tools ??
    [...new Set(spec.deterministicFindings.map(({ origin }) => origin))].map(
      (name) => ({ name, status: "completed" as const }),
    );
  if (
    new Set(tools.map(({ name }) => name)).size !== tools.length ||
    tools.some(
      ({ name, status }) =>
        !/^[a-z0-9][a-z0-9-]{0,79}$/u.test(name) ||
        !["completed", "not-applicable"].includes(status),
    )
  )
    throw new ModelRequestError(
      "MODEL_CONFIGURATION",
      "system",
      "Configured model review is incomplete or invalid.",
    );
  return {
    endpointOrigin: endpoint.origin,
    provider: endpoint.hostname,
    apiKey: spec.apiKey,
    evidenceManifest,
    tools,
    chunkReviewPolicy:
      spec.chunkReviewPolicy ?? `chunk-review:${spec.promptPolicyVersion}`,
    synthesisPolicy:
      spec.synthesisPolicy ??
      `repository-synthesis:${spec.promptPolicyVersion}`,
    maxOutputTokensPerChunkReview,
    maxChunkReviewCharacters,
    maxOutputTokensForSynthesis,
  };
}

async function completeOnce(
  spec: ConfiguredModelReviewSpec,
  configured: ValidatedConfiguration,
  cacheCounts: CacheCounts,
): Promise<CompletedModelReview> {
  let usage = zeroUsage;
  const completedChunkReviews: CompletedChunkReview[] = [];
  for (const chunk of spec.chunks) {
    const completed = await reviewChunk({
      endpoint: spec.endpoint,
      apiKey: configured.apiKey,
      model: spec.model,
      endpointOrigin: configured.endpointOrigin,
      provider: configured.provider,
      targetSha: spec.targetSha,
      projectKinds: spec.projectKinds,
      chunk,
      evidenceManifest: configured.evidenceManifest,
      promptPolicyVersion: spec.promptPolicyVersion,
      scannerPolicyVersion: spec.scannerPolicyVersion,
      chunkReviewPolicy: configured.chunkReviewPolicy,
      maxOutputTokens: configured.maxOutputTokensPerChunkReview,
      maxCharacters: configured.maxChunkReviewCharacters,
      cache: spec.cache,
      ...(spec.requestTextCompletion === undefined
        ? {}
        : { requestCompletion: spec.requestTextCompletion }),
    });
    completedChunkReviews.push(completed);
    usage = addModelUsage(usage, completed.usage);
    if (completed.cached) cacheCounts.hits += 1;
    else cacheCounts.misses += 1;
  }

  const structuredRequest =
    spec.requestStructuredCompletion ?? spec.requestCompletion;
  const completedSynthesis = await synthesizeRepository({
    endpoint: spec.endpoint,
    apiKey: configured.apiKey,
    model: spec.model,
    endpointOrigin: configured.endpointOrigin,
    provider: configured.provider,
    targetSha: spec.targetSha,
    projectKinds: spec.projectKinds,
    expectedChunkIds: spec.chunks.map(({ id }) => id),
    completedChunkReviews,
    evidenceManifest: configured.evidenceManifest,
    tools: configured.tools,
    promptPolicyVersion: spec.promptPolicyVersion,
    scannerPolicyVersion: spec.scannerPolicyVersion,
    synthesisPolicy: configured.synthesisPolicy,
    maxOutputTokens: configured.maxOutputTokensForSynthesis,
    cache: spec.cache,
    ...(structuredRequest === undefined
      ? {}
      : { requestCompletion: structuredRequest }),
  });
  usage = addModelUsage(usage, completedSynthesis.usage);
  if (completedSynthesis.cached) cacheCounts.hits += 1;
  else cacheCounts.misses += 1;

  return {
    endpointOrigin: configured.endpointOrigin,
    provider: configured.provider,
    model: spec.model,
    completedChunkIds: completedChunkReviews.map(({ chunkId }) => chunkId),
    synthesis: completedSynthesis.synthesis,
    stageCompletion: {
      chunkReview: {
        required: spec.chunks.length,
        completed: completedChunkReviews.length,
      },
      synthesis: { required: 1, completed: 1 },
    },
    usage,
    cacheHits: cacheCounts.hits,
    cacheMisses: cacheCounts.misses,
  };
}

export async function reviewRepositoryWithConfiguredModel(
  spec: ConfiguredModelReviewSpec,
): Promise<CompletedModelReview> {
  const configured = validateSpec(spec);
  const cacheCounts = { hits: 0, misses: 0 };
  for (let attempt = 1; attempt <= ImmediateAttempts; attempt += 1) {
    try {
      return await completeOnce(spec, configured, cacheCounts);
    } catch (error) {
      const retryable =
        error instanceof ModelRequestError &&
        error.code === "MODEL_INVALID_RESPONSE" &&
        error.scope === "repository";
      if (!retryable || attempt === ImmediateAttempts) throw error;
    }
  }
  throw new Error("Configured model review retry loop ended unexpectedly.");
}

export const reviewWithConfiguredModel = reviewRepositoryWithConfiguredModel;
