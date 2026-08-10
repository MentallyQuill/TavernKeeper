import { createHash } from "node:crypto";

import type { EvidenceContextGroup } from "../context/evidence-context.js";
import { z } from "zod";
import {
  ContextualAssessmentInputSchema,
  ContextualAssessmentSchema,
  ContextualObservationProgressSchema,
  ContextualObservationSchema,
  ContextualReviewResponseSchema,
  contextualReviewResponseJsonSchemaForBatch,
  contextualReviewResponseJsonSchemaForGroup,
  sanitizeContextualReviewNarratives,
  type ContextualAssessment,
  type ContextualAssessmentInput,
  type ContextualObservation,
  type ContextualObservationProgress,
  type ContextualReviewResponse,
} from "./contextual-review-contract.js";
import {
  buildContextualReviewPrompt,
  buildContextualReviewBatchPrompt,
  CONTEXTUAL_PROMPT_VERSION,
  CONTEXTUAL_SCHEMA_VERSION,
  type ContextualReviewRepair,
} from "./contextual-prompt.js";
import {
  ModelRequestError,
  type ModelCompletionResult,
  type ModelResponseDiagnostic,
  type ModelUsage,
  requestTextCompletion,
  type TextCompletionRequest,
  validateModelEndpoint,
} from "./openai-compatible-client.js";
import {
  isJsonRepairDiagnostic,
  type JsonRepairProvider,
  repairCompletedReviewBindings,
} from "./json-repair.js";
import { redactSource } from "./redaction.js";
import { validateCompletedGroupReview } from "./review-coverage.js";
import type { ReusableReviewGroup } from "./review-cache.js";

export interface ContextualReviewPolicy {
  version: "5";
  promptVersion: typeof CONTEXTUAL_PROMPT_VERSION;
  schemaVersion: typeof CONTEXTUAL_SCHEMA_VERSION;
  maxImmediateAttempts: number;
  maxOutputTokens: number;
  maxResponseBytes: number;
  timeoutMs: number;
  maxBatchGroups: number;
  maxBatchInputTokens: number;
  maxFreshBehaviorCases: number;
  maxProviderCalls: number;
  maxEstimatedInputTokens: number;
  maxActualInputTokens: number;
  maxActualOutputTokens: number;
}

type RequestCompletion = (
  request: TextCompletionRequest,
) => Promise<ModelCompletionResult>;

export interface ContextualReviewProvider {
  endpoint: string;
  apiKey: string;
  model: string;
  requestCompletion?: RequestCompletion;
  fetchImpl?: typeof fetch;
  resolveAddresses?: (hostname: string) => Promise<string[]>;
}

const CountSchema = z.number().int().nonnegative();
const UsageSchema = z.strictObject({
  inputTokens: CountSchema,
  outputTokens: CountSchema,
  cacheReadTokens: CountSchema,
  reasoningTokens: CountSchema,
});
const CompletionIdSchema = z
  .string()
  .regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/u);
export const ReviewBatchUsageSchema = z.strictObject({
  kind: z.enum(["contextual_review", "json_repair"]),
  attempt: z.number().int().min(1).max(5),
  group_count: z.number().int().min(1).max(5),
  candidate_count: z.number().int().min(1).max(320),
  estimated_input_tokens: CountSchema.nullable(),
  over_budget: z.boolean(),
  input_tokens: CountSchema,
  output_tokens: CountSchema,
  cache_read_tokens: CountSchema,
  reasoning_tokens: CountSchema,
});
export type ReviewBatchUsage = z.infer<typeof ReviewBatchUsageSchema>;
export const ReviewUnitSchema = z
  .strictObject({
    group_id: z.string().regex(/^[0-9a-f]{64}$/u),
    review_input_digest: z.string().regex(/^[0-9a-f]{64}$/u),
    candidate_ids: z
      .array(z.string().regex(/^[0-9a-f]{64}$/u))
      .min(1)
      .max(64),
    reused: z.boolean(),
    origin_report_id: z
      .string()
      .regex(/^[0-9a-f]{64}$/u)
      .nullable(),
  })
  .superRefine((unit, context) => {
    if (unit.reused !== (unit.origin_report_id !== null))
      context.addIssue({
        code: "custom",
        path: ["origin_report_id"],
        message: "Only reused review units have an origin report.",
      });
    if (new Set(unit.candidate_ids).size !== unit.candidate_ids.length)
      context.addIssue({
        code: "custom",
        path: ["candidate_ids"],
        message: "Review unit candidate identities must be unique.",
      });
  });
export type ReviewUnit = z.infer<typeof ReviewUnitSchema>;

export const CompletedContextualReviewSchema = z
  .strictObject({
    policy_version: z.literal("5"),
    prompt_version: z.literal(CONTEXTUAL_PROMPT_VERSION),
    schema_version: z.literal(CONTEXTUAL_SCHEMA_VERSION),
    model: z.string().trim().min(1).max(200),
    provider: z.string().regex(/^[A-Za-z0-9.-]{1,253}$/u),
    endpoint_origin: z.url(),
    coverage: z.strictObject({ required: CountSchema, completed: CountSchema }),
    assessments: z.array(ContextualAssessmentSchema),
    observations: z.array(ContextualObservationSchema),
    usage: UsageSchema,
    completion_ids: z.array(CompletionIdSchema),
    review_units: z.array(ReviewUnitSchema).optional(),
    review_batches: z.array(ReviewBatchUsageSchema).optional(),
  })
  .superRefine((review, context) => {
    let endpoint: URL;
    try {
      endpoint = new URL(review.endpoint_origin);
    } catch {
      return;
    }
    if (
      endpoint.origin !== review.endpoint_origin ||
      endpoint.protocol !== "https:" ||
      endpoint.hostname !== review.provider
    )
      context.addIssue({
        code: "custom",
        path: ["endpoint_origin"],
        message: "Review provider identity must match its HTTPS origin.",
      });
    const candidateIds = review.assessments.map(
      (assessment) => assessment.candidate_id,
    );
    if (
      review.coverage.completed !== review.assessments.length ||
      review.coverage.required !== review.coverage.completed ||
      new Set(candidateIds).size !== candidateIds.length
    )
      context.addIssue({
        code: "custom",
        path: ["coverage"],
        message: "Persisted contextual review coverage must be complete.",
      });
    if (new Set(review.completion_ids).size !== review.completion_ids.length)
      context.addIssue({
        code: "custom",
        path: ["completion_ids"],
        message: "Completion identities must be unique.",
      });
    if (
      review.review_batches !== undefined &&
      (review.review_batches.length !== review.completion_ids.length ||
        (
          [
            ["input_tokens", review.usage.inputTokens],
            ["output_tokens", review.usage.outputTokens],
            ["cache_read_tokens", review.usage.cacheReadTokens],
            ["reasoning_tokens", review.usage.reasoningTokens],
          ] as const
        ).some(
          ([field, total]) =>
            review.review_batches!.reduce(
              (sum, batch) => sum + batch[field],
              0,
            ) !== total,
        ))
    )
      context.addIssue({
        code: "custom",
        path: ["review_batches"],
        message: "Review batch usage must reconcile with total usage.",
      });
    if (review.review_units !== undefined) {
      const unitCandidateIds = review.review_units.flatMap(
        ({ candidate_ids }) => candidate_ids,
      );
      if (
        (review.review_units.length === 0 && candidateIds.length > 0) ||
        new Set(review.review_units.map(({ group_id }) => group_id)).size !==
          review.review_units.length ||
        JSON.stringify([...unitCandidateIds].sort()) !==
          JSON.stringify([...candidateIds].sort())
      )
        context.addIssue({
          code: "custom",
          path: ["review_units"],
          message: "Review units must cover every completed candidate once.",
        });
    }
  });

export type CompletedContextualReview = z.infer<
  typeof CompletedContextualReviewSchema
>;

export const ContextualReviewProgressSchema = z
  .strictObject({
    policy_version: z.literal("5"),
    prompt_version: z.literal(CONTEXTUAL_PROMPT_VERSION),
    schema_version: z.literal(CONTEXTUAL_SCHEMA_VERSION),
    model: z.string().trim().min(1).max(200),
    provider: z.string().regex(/^[A-Za-z0-9.-]{1,253}$/u),
    endpoint_origin: z.url(),
    completed_group_ids: z.array(z.string().regex(/^[0-9a-f]{64}$/u)),
    assessments: z.array(ContextualAssessmentInputSchema),
    observations: z.array(ContextualObservationProgressSchema),
    usage: UsageSchema,
    completion_ids: z.array(CompletionIdSchema),
    review_units: z.array(ReviewUnitSchema).optional(),
    review_batches: z.array(ReviewBatchUsageSchema).optional(),
  })
  .superRefine((progress, context) => {
    let endpoint: URL;
    try {
      endpoint = new URL(progress.endpoint_origin);
    } catch {
      return;
    }
    if (
      endpoint.origin !== progress.endpoint_origin ||
      endpoint.protocol !== "https:" ||
      endpoint.hostname !== progress.provider
    )
      context.addIssue({
        code: "custom",
        path: ["endpoint_origin"],
        message:
          "Review progress provider identity must match its HTTPS origin.",
      });
    if (
      new Set(progress.completed_group_ids).size !==
      progress.completed_group_ids.length
    )
      context.addIssue({
        code: "custom",
        path: ["completed_group_ids"],
        message: "Completed review group identities must be unique.",
      });
    if (
      new Set(progress.assessments.map(({ candidate_id }) => candidate_id))
        .size !== progress.assessments.length
    )
      context.addIssue({
        code: "custom",
        path: ["assessments"],
        message: "Progress assessment identities must be unique.",
      });
    if (
      new Set(
        progress.observations.map((observation) => JSON.stringify(observation)),
      ).size !== progress.observations.length
    )
      context.addIssue({
        code: "custom",
        path: ["observations"],
        message: "Progress observation identities must be unique.",
      });
    if (
      new Set(progress.completion_ids).size !== progress.completion_ids.length
    )
      context.addIssue({
        code: "custom",
        path: ["completion_ids"],
        message: "Progress completion identities must be unique.",
      });
    if (
      progress.review_batches !== undefined &&
      (progress.review_batches.length !== progress.completion_ids.length ||
        (
          [
            ["input_tokens", progress.usage.inputTokens],
            ["output_tokens", progress.usage.outputTokens],
            ["cache_read_tokens", progress.usage.cacheReadTokens],
            ["reasoning_tokens", progress.usage.reasoningTokens],
          ] as const
        ).some(
          ([field, total]) =>
            progress.review_batches!.reduce(
              (sum, batch) => sum + batch[field],
              0,
            ) !== total,
        ))
    )
      context.addIssue({
        code: "custom",
        path: ["review_batches"],
        message: "Progress review batch usage must reconcile with totals.",
      });
  });

export type ContextualReviewProgress = z.infer<
  typeof ContextualReviewProgressSchema
>;

interface ValidatedContextualReviewProgress {
  progress: ContextualReviewProgress;
  assessments: ContextualAssessment[];
  observations: ContextualObservation[];
  reviewUnits: ReviewUnit[];
  reviewBatches: ReviewBatchUsage[];
}

export interface ReviewEvidenceGroupsSpec {
  groups: readonly EvidenceContextGroup[];
  provider: ContextualReviewProvider;
  jsonRepairProvider?: JsonRepairProvider | undefined;
  policy: ContextualReviewPolicy;
  progress?: ContextualReviewProgress | undefined;
  reusableGroups?: ReadonlyMap<string, ReusableReviewGroup> | undefined;
  reviewInputDigests?: ReadonlyMap<string, string> | undefined;
  onProgress?:
    ((progress: ContextualReviewProgress) => Promise<void>) | undefined;
  expandContext?: (
    group: EvidenceContextGroup,
    request: Extract<
      ContextualReviewResponse,
      { status: "needs_more_context" }
    >,
    attempt: number,
  ) => Promise<EvidenceContextGroup>;
}

export class ContextualReviewProgressError extends ModelRequestError {
  constructor(message: string) {
    super("MODEL_EVIDENCE_INVALID", "repository", message);
    this.name = "ContextualReviewProgressError";
  }
}

function extractSingleJsonObject(content: string): unknown {
  const trimmed = content.trim();
  const fenced = /^```(?:json)?\s*([\s\S]*?)\s*```$/iu.exec(trimmed);
  const candidate = fenced?.[1]?.trim() ?? trimmed;
  try {
    const direct = JSON.parse(candidate) as unknown;
    if (direct !== null && typeof direct === "object" && !Array.isArray(direct))
      return direct;
  } catch {
    // Fall through to bounded extraction from provider-added prose.
  }

  const objects: string[] = [];
  let start = -1;
  let depth = 0;
  let quoted = false;
  let escaped = false;
  for (let index = 0; index < candidate.length; index += 1) {
    const character = candidate[index]!;
    if (quoted) {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === '"') quoted = false;
      continue;
    }
    if (character === '"') {
      quoted = true;
      continue;
    }
    if (character === "{") {
      if (depth === 0) start = index;
      depth += 1;
    } else if (character === "}" && depth > 0) {
      depth -= 1;
      if (depth === 0 && start >= 0) {
        objects.push(candidate.slice(start, index + 1));
        start = -1;
      }
    }
  }
  if (objects.length !== 1 || depth !== 0)
    throw new ModelRequestError(
      "MODEL_INVALID_RESPONSE",
      "repository",
      "Contextual reviewer did not return one complete JSON object.",
      "response_json",
    );
  try {
    return JSON.parse(objects[0]!) as unknown;
  } catch {
    throw new ModelRequestError(
      "MODEL_INVALID_RESPONSE",
      "repository",
      "Contextual reviewer returned malformed JSON.",
      "response_json",
    );
  }
}

function parseReviewValue(value: unknown, sanitizeUnsafeNarratives = false) {
  const parsed = ContextualReviewResponseSchema.safeParse(
    sanitizeUnsafeNarratives
      ? sanitizeContextualReviewNarratives(value)
      : value,
  );
  if (!parsed.success) {
    const path = parsed.error.issues[0]?.path ?? [];
    const root = path[0];
    const field = path[2];
    const assessmentFields = {
      candidate_id: "assessment_candidate_id",
      evidence_ids: "assessment_evidence_ids",
      disposition: "assessment_disposition",
      impact: "assessment_impact",
      exploitability: "assessment_exploitability",
      confidence: "assessment_confidence",
      risk_exposure: "assessment_risk_exposure",
      recommended_risk: "assessment_recommended_risk",
      technical_explanation: "assessment_technical_explanation",
      layman_explanation: "assessment_layman_explanation",
      developer_action: "assessment_developer_action",
      locations: "assessment_locations",
    } as const;
    const diagnostic =
      root === "assessments"
        ? typeof field === "string" && field in assessmentFields
          ? assessmentFields[field as keyof typeof assessmentFields]
          : "assessment_schema"
        : root === "observations"
          ? "observation_schema"
          : "review_schema";
    throw new ModelRequestError(
      "MODEL_INVALID_RESPONSE",
      "repository",
      "Contextual reviewer returned an invalid assessment schema.",
      diagnostic,
    );
  }
  return parsed.data;
}

function parseCheckedReviewValue(
  value: unknown,
  sanitizeUnsafeNarratives = false,
) {
  const decodedContent = JSON.stringify(value);
  if (
    decodedContent === undefined ||
    redactSource(decodedContent) !== decodedContent
  )
    throw new ModelRequestError(
      "MODEL_EVIDENCE_INVALID",
      "repository",
      "Contextual reviewer returned secret-shaped text in a review entry.",
      "response_content",
    );
  return parseReviewValue(value, sanitizeUnsafeNarratives);
}

function extractedResponse(content: string) {
  if (redactSource(content) !== content)
    throw new ModelRequestError(
      "MODEL_EVIDENCE_INVALID",
      "repository",
      "Contextual reviewer returned secret-shaped text.",
      "response_content",
    );
  const extracted = extractSingleJsonObject(content);
  const decodedContent = JSON.stringify(extracted);
  if (redactSource(decodedContent) !== decodedContent)
    throw new ModelRequestError(
      "MODEL_EVIDENCE_INVALID",
      "repository",
      "Contextual reviewer returned encoded secret-shaped text.",
      "response_content",
    );
  return extracted;
}

function parseReviewResponse(
  content: string,
  sanitizeUnsafeNarratives = false,
) {
  const wireEnvelope = z
    .strictObject({ review: z.unknown() })
    .safeParse(extractedResponse(content));
  if (!wireEnvelope.success)
    throw new ModelRequestError(
      "MODEL_INVALID_RESPONSE",
      "repository",
      "Contextual reviewer returned an invalid response envelope.",
      "review_schema",
    );
  return parseReviewValue(wireEnvelope.data.review, sanitizeUnsafeNarratives);
}

function parseBatchResponse(
  content: string,
  groups: readonly EvidenceContextGroup[],
  sanitizeUnsafeNarratives = false,
) {
  const wireEnvelope = z
    .strictObject({ reviews: z.array(z.unknown()).min(1).max(5) })
    .safeParse(extractSingleJsonObject(content));
  if (!wireEnvelope.success)
    throw new ModelRequestError(
      "MODEL_INVALID_RESPONSE",
      "repository",
      "Contextual reviewer returned an invalid batch envelope.",
      "review_schema",
    );
  const expectedIds = new Set(groups.map(({ group_id }) => group_id));
  const entries = new Map<string, unknown[]>();
  for (const value of wireEnvelope.data.reviews) {
    const entry = z
      .strictObject({ group_id: z.string(), review: z.unknown() })
      .safeParse(value);
    if (!entry.success || !expectedIds.has(entry.data.group_id)) continue;
    entries.set(entry.data.group_id, [
      ...(entries.get(entry.data.group_id) ?? []),
      entry.data.review,
    ]);
  }
  return new Map<string, ContextualReviewResponse | Error>(
    groups.map((group) => {
      const matching = entries.get(group.group_id) ?? [];
      if (matching.length !== 1)
        return [
          group.group_id,
          new ModelRequestError(
            "MODEL_INVALID_RESPONSE",
            "repository",
            "Contextual reviewer omitted or duplicated a batch group.",
            "review_schema",
          ),
        ] as const;
      try {
        return [
          group.group_id,
          parseCheckedReviewValue(matching[0], sanitizeUnsafeNarratives),
        ] as const;
      } catch (error) {
        return [
          group.group_id,
          error instanceof Error
            ? error
            : new ModelRequestError(
                "MODEL_INVALID_RESPONSE",
                "repository",
                "Contextual reviewer returned an invalid batch group.",
                "review_schema",
              ),
        ] as const;
      }
    }),
  );
}

function zeroUsage(): ModelUsage {
  return {
    inputTokens: 0,
    outputTokens: 0,
    cacheReadTokens: 0,
    reasoningTokens: 0,
  };
}

function addUsage(total: ModelUsage, usage: ModelUsage) {
  total.inputTokens += usage.inputTokens;
  total.outputTokens += usage.outputTokens;
  total.cacheReadTokens += usage.cacheReadTokens;
  total.reasoningTokens += usage.reasoningTokens;
}

function validatePolicy(policy: ContextualReviewPolicy) {
  if (
    policy.version !== "5" ||
    policy.promptVersion !== CONTEXTUAL_PROMPT_VERSION ||
    policy.schemaVersion !== CONTEXTUAL_SCHEMA_VERSION ||
    !Number.isInteger(policy.maxImmediateAttempts) ||
    policy.maxImmediateAttempts < 1 ||
    policy.maxImmediateAttempts > 5 ||
    !Number.isInteger(policy.maxOutputTokens) ||
    policy.maxOutputTokens < 1 ||
    !Number.isInteger(policy.maxResponseBytes) ||
    policy.maxResponseBytes < 1 ||
    !Number.isInteger(policy.timeoutMs) ||
    policy.timeoutMs < 1 ||
    !Number.isInteger(policy.maxBatchGroups) ||
    policy.maxBatchGroups < 1 ||
    policy.maxBatchGroups > 5 ||
    !Number.isInteger(policy.maxBatchInputTokens) ||
    policy.maxBatchInputTokens < 1 ||
    !Number.isInteger(policy.maxFreshBehaviorCases) ||
    policy.maxFreshBehaviorCases < 1 ||
    !Number.isInteger(policy.maxProviderCalls) ||
    policy.maxProviderCalls < 1 ||
    !Number.isInteger(policy.maxEstimatedInputTokens) ||
    policy.maxEstimatedInputTokens < 1 ||
    !Number.isInteger(policy.maxActualInputTokens) ||
    policy.maxActualInputTokens < 1 ||
    !Number.isInteger(policy.maxActualOutputTokens) ||
    policy.maxActualOutputTokens < 1
  )
    throw new ModelRequestError(
      "MODEL_CONFIGURATION",
      "system",
      "Contextual review policy is invalid.",
    );
}

function retryable(error: unknown) {
  return (
    error instanceof ModelRequestError &&
    error.scope === "repository" &&
    ["MODEL_INVALID_RESPONSE", "MODEL_EVIDENCE_INVALID"].includes(error.code)
  );
}

function isDeepSeekV4FlashModel(model: string) {
  return /(?:^|\/)deepseek-v4-flash(?:[-:./]|$)/iu.test(model);
}

function progressError(message: string): never {
  throw new ContextualReviewProgressError(message);
}

function validatedProgress(
  input: ContextualReviewProgress | undefined,
  spec: ReviewEvidenceGroupsSpec,
  endpoint: URL,
): ValidatedContextualReviewProgress | undefined {
  if (input === undefined) return undefined;
  const parsed = ContextualReviewProgressSchema.safeParse(input);
  if (!parsed.success)
    progressError("Contextual review progress failed bounded validation.");
  const progress = parsed.data;
  if (
    progress.model !== spec.provider.model ||
    progress.provider !== endpoint.hostname ||
    progress.endpoint_origin !== endpoint.origin
  )
    progressError("Contextual review progress provider identity changed.");
  const completedGroups = spec.groups.slice(
    0,
    progress.completed_group_ids.length,
  );
  if (
    completedGroups.length !== progress.completed_group_ids.length ||
    completedGroups.some(
      (group, index) => group.group_id !== progress.completed_group_ids[index],
    )
  )
    progressError(
      "Contextual review progress is not the completed group prefix.",
    );

  const expectedAssessments: ContextualAssessment[] = [];
  const expectedObservations: ContextualObservation[] = [];
  const observationGroups = new Map<string, ContextualObservationProgress[]>();
  for (const observation of progress.observations) {
    const owner = completedGroups.find((group) => {
      const candidateIds = new Set(
        group.candidates.map(({ candidate_id }) => candidate_id),
      );
      return observation.related_candidate_ids.every((candidateId) =>
        candidateIds.has(candidateId),
      );
    });
    if (owner === undefined)
      progressError(
        "Contextual review progress contains an unowned observation.",
      );
    observationGroups.set(owner.group_id, [
      ...(observationGroups.get(owner.group_id) ?? []),
      observation,
    ]);
  }
  for (const group of completedGroups) {
    const candidateIds = new Set(
      group.candidates.map(({ candidate_id }) => candidate_id),
    );
    const assessments = progress.assessments.filter(({ candidate_id }) =>
      candidateIds.has(candidate_id),
    );
    const observations = (observationGroups.get(group.group_id) ?? []).map(
      (observation) => ({
        ...observation,
        locations: observation.locations.map((location) => ({
          path: group.path,
          ...location,
        })),
      }),
    );
    let validated;
    try {
      validated = validateCompletedGroupReview(
        group,
        {
          status: "complete",
          assessments,
          observations,
        },
        spec.groups.map(({ path }) => path),
      );
    } catch (error) {
      if (
        error instanceof ModelRequestError &&
        error.code === "MODEL_EVIDENCE_INVALID"
      )
        progressError(
          "Contextual review progress failed authoritative evidence replay.",
        );
      throw error;
    }
    expectedAssessments.push(...validated.assessments);
    expectedObservations.push(...validated.observations);
  }
  const checkpointAssessments: ContextualAssessmentInput[] =
    expectedAssessments.map(({ locations: _locations, ...assessment }) =>
      ContextualAssessmentInputSchema.parse(assessment),
    );
  const checkpointObservations: ContextualObservationProgress[] =
    expectedObservations.map(
      ({ observation_id: _observationId, locations, ...observation }) =>
        ContextualObservationProgressSchema.parse({
          ...observation,
          locations: locations.map(({ path: _path, ...location }) => location),
        }),
    );
  if (
    JSON.stringify(checkpointAssessments) !==
      JSON.stringify(progress.assessments) ||
    JSON.stringify(checkpointObservations) !==
      JSON.stringify(progress.observations)
  )
    progressError(
      "Contextual review progress does not match completed evidence.",
    );
  const reviewUnits =
    progress.review_units ??
    completedGroups.map((group) => ({
      group_id: group.group_id,
      review_input_digest:
        spec.reviewInputDigests?.get(group.group_id) ?? group.group_id,
      candidate_ids: group.candidates.map(({ candidate_id }) => candidate_id),
      reused: false,
      origin_report_id: null,
    }));
  if (
    reviewUnits.length !== completedGroups.length ||
    reviewUnits.some((unit, index) => {
      const group = completedGroups[index]!;
      return (
        unit.group_id !== group.group_id ||
        unit.review_input_digest !==
          (spec.reviewInputDigests?.get(group.group_id) ?? group.group_id) ||
        JSON.stringify(unit.candidate_ids) !==
          JSON.stringify(
            group.candidates.map(({ candidate_id }) => candidate_id),
          )
      );
    })
  )
    progressError("Contextual review progress unit provenance changed.");
  return {
    progress,
    assessments: expectedAssessments,
    observations: expectedObservations,
    reviewUnits,
    reviewBatches: progress.review_batches ?? [],
  };
}

async function reviewGroup(
  initialGroup: EvidenceContextGroup,
  spec: ReviewEvidenceGroupsSpec,
  usage: ModelUsage,
  completionIds: string[],
) {
  let group = initialGroup;
  let repair: ContextualReviewRepair | undefined;
  let lastError: unknown;
  let repairCandidate:
    | {
        review: Extract<ContextualReviewResponse, { status: "complete" }>;
        diagnostic: Extract<
          ModelResponseDiagnostic,
          | "assessment_evidence_ids"
          | "observation_evidence_ids"
          | "observation_locations"
        >;
      }
    | undefined;
  for (
    let attempt = 1;
    attempt <= spec.policy.maxImmediateAttempts;
    attempt += 1
  ) {
    let completedResponse:
      Extract<ContextualReviewResponse, { status: "complete" }> | undefined;
    try {
      const finalAttempt = attempt === spec.policy.maxImmediateAttempts;
      const prompt = buildContextualReviewPrompt(group, repair, finalAttempt);
      const request = spec.provider.requestCompletion ?? requestTextCompletion;
      const completion = await request({
        endpoint: spec.provider.endpoint,
        apiKey: spec.provider.apiKey,
        model: spec.provider.model,
        maxOutputTokens: spec.policy.maxOutputTokens,
        maxResponseBytes: spec.policy.maxResponseBytes,
        timeoutMs: spec.policy.timeoutMs,
        systemContent: prompt.systemContent,
        userContent: prompt.userContent,
        responseJsonSchema: {
          name: "tavernkeeper_contextual_review",
          schema: contextualReviewResponseJsonSchemaForGroup(
            group,
            finalAttempt,
          ),
        },
        ...(spec.provider.fetchImpl === undefined
          ? {}
          : { fetchImpl: spec.provider.fetchImpl }),
        ...(spec.provider.resolveAddresses === undefined
          ? {}
          : { resolveAddresses: spec.provider.resolveAddresses }),
      });
      const endpoint = new URL(spec.provider.endpoint);
      if (
        completion.endpointOrigin !== endpoint.origin ||
        completion.provider !== endpoint.hostname
      )
        throw new ModelRequestError(
          "MODEL_INVALID_RESPONSE",
          "system",
          "Contextual reviewer returned a mismatched provider identity.",
          "response_envelope",
        );
      addUsage(usage, completion.usage);
      completionIds.push(completion.completionId);
      const response = parseReviewResponse(
        completion.content,
        // Keep corrective feedback authoritative until the bounded final
        // attempt, then salvage only invalid non-empty narrative strings.
        finalAttempt,
      );
      if (response.status === "needs_more_context") {
        const candidateIds = new Set(
          group.candidates.map((candidate) => candidate.candidate_id),
        );
        if (
          new Set(response.candidate_ids).size !==
            response.candidate_ids.length ||
          response.candidate_ids.some(
            (candidateId) => !candidateIds.has(candidateId),
          )
        )
          throw new ModelRequestError(
            "MODEL_EVIDENCE_INVALID",
            "repository",
            "Contextual reviewer requested context for an unknown candidate.",
            "assessment_candidate_id",
          );
        if (!spec.expandContext)
          throw new ModelRequestError(
            "MODEL_CONTEXT_INCOMPLETE",
            "repository",
            "Contextual review requires more source context.",
          );
        if (finalAttempt)
          throw new ModelRequestError(
            "MODEL_CONTEXT_INCOMPLETE",
            "repository",
            "Contextual review remained unresolved after context expansion.",
          );
        const expanded = await spec.expandContext(group, response, attempt);
        if (
          expanded.group_id !== group.group_id ||
          expanded.repository !== group.repository ||
          expanded.path !== group.path ||
          expanded.target_sha !== group.target_sha ||
          expanded.evidence_sha !== group.evidence_sha ||
          JSON.stringify(
            expanded.candidates.map((candidate) => [
              candidate.candidate_id,
              candidate.evidence_id,
            ]),
          ) !==
            JSON.stringify(
              group.candidates.map((candidate) => [
                candidate.candidate_id,
                candidate.evidence_id,
              ]),
            )
        )
          throw new ModelRequestError(
            "MODEL_EVIDENCE_INVALID",
            "repository",
            "Expanded context changed immutable evidence identity.",
          );
        group = expanded;
        repair = undefined;
        continue;
      }
      completedResponse = response;
      return validateCompletedGroupReview(
        group,
        response,
        spec.groups.map(({ path }) => path),
      );
    } catch (error) {
      lastError = error;
      if (!retryable(error)) throw error;
      if (attempt === spec.policy.maxImmediateAttempts) {
        if (
          completedResponse !== undefined &&
          error instanceof ModelRequestError &&
          isJsonRepairDiagnostic(error.diagnostic)
        )
          repairCandidate = {
            review: completedResponse,
            diagnostic: error.diagnostic,
          };
        break;
      }
      const nextRepair: ContextualReviewRepair = {
        diagnostic:
          error instanceof ModelRequestError && error.diagnostic !== undefined
            ? error.diagnostic
            : "review_schema",
      };
      repair = nextRepair;
    }
  }
  if (
    repairCandidate !== undefined &&
    spec.jsonRepairProvider !== undefined &&
    isDeepSeekV4FlashModel(spec.provider.model)
  )
    try {
      const repaired = await repairCompletedReviewBindings({
        group,
        review: repairCandidate.review,
        diagnostic: repairCandidate.diagnostic,
        provider: spec.jsonRepairProvider,
      });
      const validated = validateCompletedGroupReview(
        group,
        repaired.review,
        spec.groups.map(({ path }) => path),
      );
      addUsage(usage, repaired.usage);
      const repairCompletionId = `jsonrepair:${repaired.completionId}`;
      completionIds.push(
        repairCompletionId.length <= 200
          ? repairCompletionId
          : `jsonrepair:${createHash("sha256")
              .update(repaired.completionId)
              .digest("hex")}`,
      );
      return validated;
    } catch {
      // JSON repair is optional and cannot replace the authoritative primary
      // failure with a repair-provider or patch error.
    }
  throw lastError;
}

type ValidatedGroupReview = ReturnType<typeof validateCompletedGroupReview>;

interface BatchGroupState {
  initialGroup: EvidenceContextGroup;
  group: EvidenceContextGroup;
  attempt: number;
  repair?: ContextualReviewRepair | undefined;
  lastError?: unknown;
  repairCandidate?:
    | {
        review: Extract<ContextualReviewResponse, { status: "complete" }>;
        diagnostic: Extract<
          ModelResponseDiagnostic,
          | "assessment_evidence_ids"
          | "observation_evidence_ids"
          | "observation_locations"
        >;
      }
    | undefined;
}

function batchUsage(
  kind: ReviewBatchUsage["kind"],
  attempt: number,
  groups: readonly EvidenceContextGroup[],
  estimatedInputTokens: number | null,
  maximumInputTokens: number,
  usage: ModelUsage,
): ReviewBatchUsage {
  return ReviewBatchUsageSchema.parse({
    kind,
    attempt,
    group_count: groups.length,
    candidate_count: groups.reduce(
      (total, group) => total + group.candidates.length,
      0,
    ),
    estimated_input_tokens: estimatedInputTokens,
    over_budget:
      estimatedInputTokens !== null &&
      estimatedInputTokens > maximumInputTokens,
    input_tokens: usage.inputTokens,
    output_tokens: usage.outputTokens,
    cache_read_tokens: usage.cacheReadTokens,
    reasoning_tokens: usage.reasoningTokens,
  });
}

function repairCompletionIdentity(completionId: string) {
  const value = `jsonrepair:${completionId}`;
  return value.length <= 200
    ? value
    : `jsonrepair:${createHash("sha256").update(completionId).digest("hex")}`;
}

function nextBatchAttempt(state: BatchGroupState, error: unknown) {
  state.lastError = error;
  state.repair = {
    diagnostic:
      error instanceof ModelRequestError && error.diagnostic !== undefined
        ? error.diagnostic
        : "review_schema",
  };
  state.attempt += 1;
}

function estimatedStructuredOutputTokens(schema: Record<string, unknown>) {
  return Math.ceil(Buffer.byteLength(JSON.stringify(schema), "utf8") / 3);
}

async function reviewBatch(
  initialGroups: readonly EvidenceContextGroup[],
  spec: ReviewEvidenceGroupsSpec,
  usage: ModelUsage,
  completionIds: string[],
  reviewBatches: ReviewBatchUsage[],
) {
  const states = new Map<string, BatchGroupState>(
    initialGroups.map(
      (group) =>
        [
          group.group_id,
          {
            initialGroup: group,
            group,
            attempt: 1,
          },
        ] as [string, BatchGroupState],
    ),
  );
  const reviewed = new Map<string, ValidatedGroupReview>();
  while (states.size > 0) {
    const currentStates = [...states.values()];
    const attempt = currentStates[0]!.attempt;
    if (currentStates.some((state) => state.attempt !== attempt))
      throw new Error("Contextual batch attempts diverged unexpectedly.");
    const finalAttempt = attempt === spec.policy.maxImmediateAttempts;
    const currentGroups = currentStates.map(({ group }) => group);
    const repairs = new Map(
      currentStates.flatMap((state) =>
        state.repair === undefined
          ? []
          : [[state.group.group_id, state.repair] as const],
      ),
    );
    const prompt = buildContextualReviewBatchPrompt(
      currentGroups,
      repairs,
      finalAttempt,
    );
    const responseSchema = contextualReviewResponseJsonSchemaForBatch(
      currentGroups,
      finalAttempt,
    );
    const estimatedInputTokens =
      prompt.estimatedInputTokens +
      estimatedStructuredOutputTokens(responseSchema);
    let responses: Map<string, ContextualReviewResponse | Error> | undefined;
    try {
      const request = spec.provider.requestCompletion ?? requestTextCompletion;
      const completion = await request({
        endpoint: spec.provider.endpoint,
        apiKey: spec.provider.apiKey,
        model: spec.provider.model,
        maxOutputTokens: spec.policy.maxOutputTokens,
        maxResponseBytes: spec.policy.maxResponseBytes,
        timeoutMs: spec.policy.timeoutMs,
        systemContent: prompt.systemContent,
        userContent: prompt.userContent,
        responseJsonSchema: {
          name: "tavernkeeper_contextual_review_batch",
          schema: responseSchema,
        },
        ...(spec.provider.fetchImpl === undefined
          ? {}
          : { fetchImpl: spec.provider.fetchImpl }),
        ...(spec.provider.resolveAddresses === undefined
          ? {}
          : { resolveAddresses: spec.provider.resolveAddresses }),
      });
      const endpoint = new URL(spec.provider.endpoint);
      if (
        completion.endpointOrigin !== endpoint.origin ||
        completion.provider !== endpoint.hostname
      )
        throw new ModelRequestError(
          "MODEL_INVALID_RESPONSE",
          "system",
          "Contextual reviewer returned a mismatched provider identity.",
          "response_envelope",
        );
      addUsage(usage, completion.usage);
      completionIds.push(completion.completionId);
      reviewBatches.push(
        batchUsage(
          "contextual_review",
          attempt,
          currentGroups,
          estimatedInputTokens,
          spec.policy.maxBatchInputTokens,
          completion.usage,
        ),
      );
      responses = parseBatchResponse(
        completion.content,
        currentGroups,
        finalAttempt,
      );
    } catch (error) {
      if (!retryable(error)) throw error;
      for (const state of currentStates) {
        if (finalAttempt) state.lastError = error;
        else nextBatchAttempt(state, error);
      }
    }

    if (responses !== undefined)
      for (const state of currentStates) {
        const response = responses.get(state.group.group_id);
        let completedResponse:
          Extract<ContextualReviewResponse, { status: "complete" }> | undefined;
        try {
          if (response instanceof Error) throw response;
          if (response === undefined)
            throw new ModelRequestError(
              "MODEL_INVALID_RESPONSE",
              "repository",
              "Contextual reviewer omitted a batch group.",
              "review_schema",
            );
          if (response.status === "needs_more_context") {
            const candidateIds = new Set(
              state.group.candidates.map(({ candidate_id }) => candidate_id),
            );
            if (
              new Set(response.candidate_ids).size !==
                response.candidate_ids.length ||
              response.candidate_ids.some(
                (candidateId) => !candidateIds.has(candidateId),
              )
            )
              throw new ModelRequestError(
                "MODEL_EVIDENCE_INVALID",
                "repository",
                "Contextual reviewer requested context for an unknown candidate.",
                "assessment_candidate_id",
              );
            if (!spec.expandContext)
              throw new ModelRequestError(
                "MODEL_CONTEXT_INCOMPLETE",
                "repository",
                "Contextual review requires more source context.",
              );
            if (finalAttempt)
              throw new ModelRequestError(
                "MODEL_CONTEXT_INCOMPLETE",
                "repository",
                "Contextual review remained unresolved after context expansion.",
              );
            const expanded = await spec.expandContext(
              state.group,
              response,
              attempt,
            );
            if (
              expanded.group_id !== state.group.group_id ||
              expanded.repository !== state.group.repository ||
              expanded.path !== state.group.path ||
              expanded.target_sha !== state.group.target_sha ||
              expanded.evidence_sha !== state.group.evidence_sha ||
              JSON.stringify(
                expanded.candidates.map((candidate) => [
                  candidate.candidate_id,
                  candidate.evidence_id,
                ]),
              ) !==
                JSON.stringify(
                  state.group.candidates.map((candidate) => [
                    candidate.candidate_id,
                    candidate.evidence_id,
                  ]),
                )
            )
              throw new ModelRequestError(
                "MODEL_EVIDENCE_INVALID",
                "repository",
                "Expanded context changed immutable evidence identity.",
              );
            state.group = expanded;
            state.repair = undefined;
            state.attempt += 1;
            continue;
          }
          completedResponse = response;
          reviewed.set(
            state.initialGroup.group_id,
            validateCompletedGroupReview(
              state.group,
              response,
              spec.groups.map(({ path }) => path),
            ),
          );
          states.delete(state.initialGroup.group_id);
        } catch (error) {
          if (!retryable(error)) throw error;
          if (finalAttempt) {
            state.lastError = error;
            if (
              completedResponse !== undefined &&
              error instanceof ModelRequestError &&
              isJsonRepairDiagnostic(error.diagnostic)
            )
              state.repairCandidate = {
                review: completedResponse,
                diagnostic: error.diagnostic,
              };
          } else nextBatchAttempt(state, error);
        }
      }

    const exhausted = finalAttempt ? [...states.values()] : [];
    for (const state of exhausted) {
      if (
        state.repairCandidate !== undefined &&
        spec.jsonRepairProvider !== undefined &&
        isDeepSeekV4FlashModel(spec.provider.model)
      )
        try {
          const repaired = await repairCompletedReviewBindings({
            group: state.group,
            review: state.repairCandidate.review,
            diagnostic: state.repairCandidate.diagnostic,
            provider: spec.jsonRepairProvider,
          });
          reviewed.set(
            state.initialGroup.group_id,
            validateCompletedGroupReview(
              state.group,
              repaired.review,
              spec.groups.map(({ path }) => path),
            ),
          );
          addUsage(usage, repaired.usage);
          completionIds.push(repairCompletionIdentity(repaired.completionId));
          reviewBatches.push(
            batchUsage(
              "json_repair",
              1,
              [state.group],
              null,
              spec.policy.maxBatchInputTokens,
              repaired.usage,
            ),
          );
          states.delete(state.initialGroup.group_id);
          continue;
        } catch {
          // Preserve the authoritative primary failure below.
        }
      throw state.lastError;
    }
  }
  return reviewed;
}

function takeReviewBatch(
  groups: readonly EvidenceContextGroup[],
  start: number,
  policy: ContextualReviewPolicy,
) {
  const batch: EvidenceContextGroup[] = [];
  const maximumEstimatedCandidates = Math.max(
    1,
    Math.floor(policy.maxOutputTokens / 2_048),
  );
  for (
    let index = start;
    index < groups.length && batch.length < policy.maxBatchGroups;
    index += 1
  ) {
    const next = [...batch, groups[index]!];
    const worstCaseRepairs = new Map(
      next.map((group) => [
        group.group_id,
        { diagnostic: "assessment_developer_action" } as const,
      ]),
    );
    const prompt = buildContextualReviewBatchPrompt(
      next,
      worstCaseRepairs,
      true,
    );
    const responseSchema = contextualReviewResponseJsonSchemaForBatch(
      next,
      true,
    );
    const estimate =
      prompt.estimatedInputTokens +
      estimatedStructuredOutputTokens(responseSchema);
    const candidateCount = next.reduce(
      (total, group) => total + group.candidates.length,
      0,
    );
    if (
      batch.length > 0 &&
      (estimate > policy.maxBatchInputTokens ||
        candidateCount > maximumEstimatedCandidates)
    )
      break;
    batch.push(groups[index]!);
  }
  return batch;
}

export async function reviewEvidenceGroups(
  spec: ReviewEvidenceGroupsSpec,
): Promise<CompletedContextualReview> {
  validatePolicy(spec.policy);
  const endpoint = validateModelEndpoint(spec.provider.endpoint);
  if (
    spec.provider.apiKey.trim() === "" ||
    spec.provider.model.trim() === "" ||
    spec.provider.model.length > 200
  )
    throw new ModelRequestError(
      "MODEL_CONFIGURATION",
      "system",
      "Contextual review provider configuration is invalid.",
    );
  const groupIds = new Set<string>();
  const candidateIds = new Set<string>();
  for (const group of spec.groups) {
    if (groupIds.has(group.group_id))
      throw new ModelRequestError(
        "MODEL_EVIDENCE_INVALID",
        "repository",
        "Contextual evidence group identities must be unique.",
      );
    groupIds.add(group.group_id);
    for (const candidate of group.candidates) {
      if (candidateIds.has(candidate.candidate_id))
        throw new ModelRequestError(
          "MODEL_EVIDENCE_INVALID",
          "repository",
          "Contextual candidate identities must be unique.",
        );
      candidateIds.add(candidate.candidate_id);
    }
  }
  const assessments: ContextualAssessment[] = [];
  const observations: ContextualObservation[] = [];
  const usage = zeroUsage();
  const completionIds: string[] = [];
  const reviewUnits: ReviewUnit[] = [];
  const reviewBatches: ReviewBatchUsage[] = [];
  const validated = validatedProgress(spec.progress, spec, endpoint);
  const progress = validated?.progress;
  const batchUsageComplete =
    progress === undefined || progress.review_batches !== undefined;
  const publishBatchUsage =
    spec.policy.maxBatchGroups > 1 && batchUsageComplete;
  if (validated !== undefined) {
    assessments.push(...validated.assessments);
    observations.push(...validated.observations);
    addUsage(usage, validated.progress.usage);
    completionIds.push(...validated.progress.completion_ids);
    reviewUnits.push(...validated.reviewUnits);
    reviewBatches.push(...validated.reviewBatches);
  }
  const completedGroupIds = [...(progress?.completed_group_ids ?? [])];
  const checkpoint = async () => {
    if (spec.onProgress === undefined) return;
    await spec.onProgress(
      ContextualReviewProgressSchema.parse({
        policy_version: "5",
        prompt_version: CONTEXTUAL_PROMPT_VERSION,
        schema_version: CONTEXTUAL_SCHEMA_VERSION,
        model: spec.provider.model,
        provider: endpoint.hostname,
        endpoint_origin: endpoint.origin,
        completed_group_ids: completedGroupIds,
        assessments: assessments.map(
          ({ locations: _locations, ...assessment }) => assessment,
        ),
        observations: observations.map(
          ({ observation_id: _observationId, locations, ...observation }) => ({
            ...observation,
            locations: locations.map(
              ({ path: _path, ...location }) => location,
            ),
          }),
        ),
        usage,
        completion_ids: completionIds,
        review_units: reviewUnits,
        ...(publishBatchUsage ? { review_batches: reviewBatches } : {}),
      }),
    );
  };
  const remainingGroups = spec.groups.slice(completedGroupIds.length);
  if (spec.policy.maxBatchGroups === 1)
    for (const group of remainingGroups) {
      const reviewInputDigest =
        spec.reviewInputDigests?.get(group.group_id) ?? group.group_id;
      const reusable = spec.reusableGroups?.get(group.group_id);
      if (
        reusable !== undefined &&
        reusable.review_input_digest !== reviewInputDigest
      )
        throw new ModelRequestError(
          "MODEL_EVIDENCE_INVALID",
          "repository",
          "Reusable contextual review identity changed.",
        );
      const reviewed =
        reusable === undefined
          ? await reviewGroup(group, spec, usage, completionIds)
          : validateCompletedGroupReview(
              group,
              reusable.response,
              spec.groups.map(({ path }) => path),
            );
      assessments.push(...reviewed.assessments);
      observations.push(...reviewed.observations);
      completedGroupIds.push(group.group_id);
      reviewUnits.push(
        ReviewUnitSchema.parse({
          group_id: group.group_id,
          review_input_digest: reviewInputDigest,
          candidate_ids: group.candidates.map(
            ({ candidate_id }) => candidate_id,
          ),
          reused: reusable !== undefined,
          origin_report_id: reusable?.origin_report_id ?? null,
        }),
      );
      await checkpoint();
    }
  else {
    const resolved = new Map<
      string,
      {
        reviewed: ValidatedGroupReview;
        reusable: ReusableReviewGroup | undefined;
      }
    >();
    const freshGroups: EvidenceContextGroup[] = [];
    for (const group of remainingGroups) {
      const reviewInputDigest =
        spec.reviewInputDigests?.get(group.group_id) ?? group.group_id;
      const reusable = spec.reusableGroups?.get(group.group_id);
      if (
        reusable !== undefined &&
        reusable.review_input_digest !== reviewInputDigest
      )
        throw new ModelRequestError(
          "MODEL_EVIDENCE_INVALID",
          "repository",
          "Reusable contextual review identity changed.",
        );
      if (reusable === undefined) freshGroups.push(group);
      else
        resolved.set(group.group_id, {
          reviewed: validateCompletedGroupReview(
            group,
            reusable.response,
            spec.groups.map(({ path }) => path),
          ),
          reusable,
        });
    }
    let nextGroupIndex = 0;
    const flushResolvedPrefix = async () => {
      let changed = false;
      while (nextGroupIndex < remainingGroups.length) {
        const group = remainingGroups[nextGroupIndex]!;
        const value = resolved.get(group.group_id);
        if (value === undefined) break;
        const reviewInputDigest =
          spec.reviewInputDigests?.get(group.group_id) ?? group.group_id;
        assessments.push(...value.reviewed.assessments);
        observations.push(...value.reviewed.observations);
        completedGroupIds.push(group.group_id);
        reviewUnits.push(
          ReviewUnitSchema.parse({
            group_id: group.group_id,
            review_input_digest: reviewInputDigest,
            candidate_ids: group.candidates.map(
              ({ candidate_id }) => candidate_id,
            ),
            reused: value.reusable !== undefined,
            origin_report_id: value.reusable?.origin_report_id ?? null,
          }),
        );
        resolved.delete(group.group_id);
        nextGroupIndex += 1;
        changed = true;
      }
      if (changed) await checkpoint();
    };
    await flushResolvedPrefix();
    for (let start = 0; start < freshGroups.length;) {
      const batch = takeReviewBatch(freshGroups, start, spec.policy);
      const batchReviewed = await reviewBatch(
        batch,
        spec,
        usage,
        completionIds,
        reviewBatches,
      );
      for (const group of batch)
        resolved.set(group.group_id, {
          reviewed: batchReviewed.get(group.group_id)!,
          reusable: undefined,
        });
      start += batch.length;
      await flushResolvedPrefix();
    }
    await flushResolvedPrefix();
  }
  if (
    new Set(observations.map((item) => item.observation_id)).size !==
    observations.length
  )
    throw new ModelRequestError(
      "MODEL_EVIDENCE_INVALID",
      "repository",
      "Contextual observation identities must be unique.",
    );
  return CompletedContextualReviewSchema.parse({
    policy_version: "5",
    prompt_version: CONTEXTUAL_PROMPT_VERSION,
    schema_version: CONTEXTUAL_SCHEMA_VERSION,
    model: spec.provider.model,
    provider: endpoint.hostname,
    endpoint_origin: endpoint.origin,
    coverage: { required: candidateIds.size, completed: assessments.length },
    assessments,
    observations,
    usage,
    completion_ids: completionIds,
    review_units: reviewUnits,
    ...(publishBatchUsage ? { review_batches: reviewBatches } : {}),
  });
}
