import { createHash } from "node:crypto";

import type { EvidenceContextGroup } from "../context/evidence-context.js";
import { z } from "zod";
import {
  ContextualAssessmentInputSchema,
  ContextualAssessmentSchema,
  ContextualObservationProgressSchema,
  ContextualObservationSchema,
  ContextualReviewResponseSchema,
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

export interface ContextualReviewPolicy {
  version: "3";
  promptVersion: typeof CONTEXTUAL_PROMPT_VERSION;
  schemaVersion: typeof CONTEXTUAL_SCHEMA_VERSION;
  maxImmediateAttempts: number;
  maxOutputTokens: number;
  maxResponseBytes: number;
  timeoutMs: number;
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
export const CompletedContextualReviewSchema = z
  .strictObject({
    policy_version: z.literal("3"),
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
  });

export type CompletedContextualReview = z.infer<
  typeof CompletedContextualReviewSchema
>;

export const ContextualReviewProgressSchema = z
  .strictObject({
    policy_version: z.literal("3"),
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
  });

export type ContextualReviewProgress = z.infer<
  typeof ContextualReviewProgressSchema
>;

interface ValidatedContextualReviewProgress {
  progress: ContextualReviewProgress;
  assessments: ContextualAssessment[];
  observations: ContextualObservation[];
}

export interface ReviewEvidenceGroupsSpec {
  groups: readonly EvidenceContextGroup[];
  provider: ContextualReviewProvider;
  jsonRepairProvider?: JsonRepairProvider | undefined;
  policy: ContextualReviewPolicy;
  progress?: ContextualReviewProgress | undefined;
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

function parseReviewResponse(
  content: string,
  sanitizeUnsafeNarratives = false,
) {
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
  const wireEnvelope = z
    .strictObject({ review: z.unknown() })
    .safeParse(extracted);
  if (!wireEnvelope.success)
    throw new ModelRequestError(
      "MODEL_INVALID_RESPONSE",
      "repository",
      "Contextual reviewer returned an invalid response envelope.",
      "review_schema",
    );
  const parsed = ContextualReviewResponseSchema.safeParse(
    sanitizeUnsafeNarratives
      ? sanitizeContextualReviewNarratives(wireEnvelope.data.review)
      : wireEnvelope.data.review,
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
    policy.version !== "3" ||
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
    policy.timeoutMs < 1
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
  return {
    progress,
    assessments: expectedAssessments,
    observations: expectedObservations,
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
  const validated = validatedProgress(spec.progress, spec, endpoint);
  const progress = validated?.progress;
  if (validated !== undefined) {
    assessments.push(...validated.assessments);
    observations.push(...validated.observations);
    addUsage(usage, validated.progress.usage);
    completionIds.push(...validated.progress.completion_ids);
  }
  const completedGroupIds = [...(progress?.completed_group_ids ?? [])];
  for (const group of spec.groups.slice(completedGroupIds.length)) {
    const reviewed = await reviewGroup(group, spec, usage, completionIds);
    assessments.push(...reviewed.assessments);
    observations.push(...reviewed.observations);
    completedGroupIds.push(group.group_id);
    if (spec.onProgress !== undefined)
      await spec.onProgress(
        ContextualReviewProgressSchema.parse({
          policy_version: "3",
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
            ({
              observation_id: _observationId,
              locations,
              ...observation
            }) => ({
              ...observation,
              locations: locations.map(
                ({ path: _path, ...location }) => location,
              ),
            }),
          ),
          usage,
          completion_ids: completionIds,
        }),
      );
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
    policy_version: "3",
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
  });
}
