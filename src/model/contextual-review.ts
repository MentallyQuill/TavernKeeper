import type { EvidenceContextGroup } from "../context/evidence-context.js";
import { z } from "zod";
import {
  ContextualCompletedReviewResponseJsonSchema,
  ContextualAssessmentInputSchema,
  ContextualAssessmentSchema,
  ContextualObservationProgressSchema,
  ContextualObservationSchema,
  ContextualReviewResponseJsonSchema,
  ContextualReviewResponseSchema,
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
  type ModelUsage,
  requestTextCompletion,
  type TextCompletionRequest,
  validateModelEndpoint,
} from "./openai-compatible-client.js";
import { redactSource } from "./redaction.js";
import { validateCompletedGroupReview } from "./review-coverage.js";

export interface ContextualReviewPolicy {
  version: "2";
  promptVersion: typeof CONTEXTUAL_PROMPT_VERSION;
  schemaVersion: typeof CONTEXTUAL_SCHEMA_VERSION;
  maxImmediateAttempts: number;
  maxOutputTokens: number;
  maxResponseBytes: number;
  timeoutMs: number;
  maxModelCandidates?: number;
  maxReviewMs?: number;
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
    policy_version: z.literal("2"),
    prompt_version: z.literal(CONTEXTUAL_PROMPT_VERSION),
    schema_version: z.literal(CONTEXTUAL_SCHEMA_VERSION),
    model: z.string().trim().min(1).max(200),
    provider: z.string().regex(/^[A-Za-z0-9.-]{1,253}$/u),
    endpoint_origin: z.url(),
    coverage: z.strictObject({
      required: CountSchema,
      completed: CountSchema,
      model_completed: CountSchema.optional(),
      deterministic_fallback: CountSchema.optional(),
    }),
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
    if (
      (review.coverage.model_completed === undefined) !==
        (review.coverage.deterministic_fallback === undefined) ||
      (review.coverage.model_completed !== undefined &&
        review.coverage.deterministic_fallback !== undefined &&
        review.coverage.model_completed +
          review.coverage.deterministic_fallback !==
          review.coverage.completed)
    )
      context.addIssue({
        code: "custom",
        path: ["coverage"],
        message: "Review method coverage must account for every assessment.",
      });
    if (
      (review.coverage.deterministic_fallback ?? 0) >
      review.assessments.filter(
        (assessment) =>
          assessment.disposition === "material_vulnerability" &&
          assessment.impact === "medium" &&
          assessment.exploitability === "plausible" &&
          assessment.confidence === "low" &&
          assessment.recommended_risk === "material",
      ).length
    )
      context.addIssue({
        code: "custom",
        path: ["coverage", "deterministic_fallback"],
        message:
          "Deterministic fallback coverage must remain conservatively material.",
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
    policy_version: z.literal("2"),
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
  policy: ContextualReviewPolicy;
  progress?: ContextualReviewProgress | undefined;
  onProgress?:
    ((progress: ContextualReviewProgress) => Promise<void>) | undefined;
  allowDeterministicFallback?: boolean | undefined;
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
    policy.version !== "2" ||
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
    (policy.maxModelCandidates !== undefined &&
      (!Number.isInteger(policy.maxModelCandidates) ||
        policy.maxModelCandidates < 1)) ||
    (policy.maxReviewMs !== undefined &&
      (!Number.isInteger(policy.maxReviewMs) || policy.maxReviewMs < 1))
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

function progressError(message: string): never {
  throw new ContextualReviewProgressError(message);
}

const highValueCategories = new Set([
  "code-execution",
  "credential-exposure",
  "credential-theft",
  "data-exfiltration",
  "dynamic-execution",
  "install-hook",
  "obfuscation",
  "persistence",
  "supply-chain-risk",
]);

function evidencePriority(group: EvidenceContextGroup) {
  const originWeight: Record<string, number | undefined> = {
    "javascript-analysis": 1_000,
    malcontent: 800,
    tavernkeeper: 700,
    opengrep: 600,
    gitleaks: 500,
    "osv-scanner": 300,
    zizmor: 100,
  };
  const severityWeight = {
    critical: 300,
    high: 200,
    medium: 100,
    low: 20,
    info: 0,
  } as const;
  const confidenceWeight = { high: 60, medium: 30, low: 0 } as const;
  const candidateScore = Math.max(
    ...group.candidates.map(
      (candidate) =>
        (originWeight[candidate.origin] ?? 0) +
        severityWeight[candidate.scanner_severity] +
        confidenceWeight[candidate.scanner_confidence] +
        (highValueCategories.has(candidate.category) ? 250 : 0),
    ),
  );
  const javascriptPath = /(?:\.min)?\.(?:c|m)?js(?:x)?$/iu.test(group.path)
    ? 200
    : 0;
  return candidateScore + javascriptPath;
}

function boundedReviewPlan(
  groups: readonly EvidenceContextGroup[],
  policy: ContextualReviewPolicy,
) {
  const candidateLimit = policy.maxModelCandidates ?? 128;
  const ranked = groups
    .filter((group) => group.source_kind === "text")
    .map((group) => ({ group, priority: evidencePriority(group) }))
    .sort(
      (left, right) =>
        right.priority - left.priority ||
        left.group.group_id.localeCompare(right.group.group_id),
    );
  const modelGroups: EvidenceContextGroup[] = [];
  const fallbackGroups = groups.filter(
    (group) => group.source_kind === "metadata-only",
  );
  let selectedCandidates = 0;
  for (const { group } of ranked) {
    if (selectedCandidates + group.candidates.length <= candidateLimit) {
      modelGroups.push(group);
      selectedCandidates += group.candidates.length;
    } else fallbackGroups.push(group);
  }
  return { modelGroups, fallbackGroups };
}

function conservativeFallback(
  group: EvidenceContextGroup,
  repositoryPaths: readonly string[],
) {
  return validateCompletedGroupReview(
    group,
    {
      status: "complete",
      assessments: group.candidates.map((candidate) => ({
        candidate_id: candidate.candidate_id,
        evidence_ids: [candidate.evidence_id],
        disposition: "material_vulnerability" as const,
        impact: "medium" as const,
        exploitability: "plausible" as const,
        confidence: "low" as const,
        recommended_risk: "material" as const,
        technical_explanation:
          "Contextual model assessment was unavailable within the bounded review window. The scanner evidence remains unresolved and is conservatively retained.",
        layman_explanation:
          "Automated contextual review could not resolve this scanner warning, so it remains a material concern.",
        developer_action:
          "Manually inspect the cited evidence and confirm the intended behavior before release.",
      })),
      observations: [],
    },
    repositoryPaths,
  );
}

function validatedProgress(
  input: ContextualReviewProgress | undefined,
  spec: ReviewEvidenceGroupsSpec,
  endpoint: URL,
  modelGroups: readonly EvidenceContextGroup[],
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
  const completedGroups = modelGroups.slice(
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
  deadline: number,
) {
  let group = initialGroup;
  let repair: ContextualReviewRepair | undefined;
  let lastError: unknown;
  for (
    let attempt = 1;
    attempt <= spec.policy.maxImmediateAttempts;
    attempt += 1
  ) {
    try {
      const remainingMs = deadline - Date.now();
      if (remainingMs < 1)
        throw new ModelRequestError(
          "MODEL_PROVIDER",
          "system",
          "Contextual model review reached its bounded time limit.",
        );
      const finalAttempt = attempt === spec.policy.maxImmediateAttempts;
      const prompt = buildContextualReviewPrompt(group, repair, finalAttempt);
      const request = spec.provider.requestCompletion ?? requestTextCompletion;
      const completion = await request({
        endpoint: spec.provider.endpoint,
        apiKey: spec.provider.apiKey,
        model: spec.provider.model,
        maxOutputTokens: spec.policy.maxOutputTokens,
        maxResponseBytes: spec.policy.maxResponseBytes,
        timeoutMs: Math.min(spec.policy.timeoutMs, remainingMs),
        systemContent: prompt.systemContent,
        userContent: prompt.userContent,
        responseJsonSchema: {
          name: "tavernkeeper_contextual_review",
          schema: finalAttempt
            ? ContextualCompletedReviewResponseJsonSchema
            : ContextualReviewResponseJsonSchema,
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
      return validateCompletedGroupReview(
        group,
        response,
        spec.groups.map(({ path }) => path),
      );
    } catch (error) {
      lastError = error;
      if (!retryable(error) || attempt === spec.policy.maxImmediateAttempts)
        throw error;
      const nextRepair: ContextualReviewRepair = {
        diagnostic:
          error instanceof ModelRequestError && error.diagnostic !== undefined
            ? error.diagnostic
            : "review_schema",
      };
      repair = nextRepair;
    }
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
  const fallbackEnabled = spec.allowDeterministicFallback === true;
  const plan = fallbackEnabled
    ? boundedReviewPlan(spec.groups, spec.policy)
    : { modelGroups: [...spec.groups], fallbackGroups: [] };
  const validated = validatedProgress(
    spec.progress,
    spec,
    endpoint,
    plan.modelGroups,
  );
  const progress = validated?.progress;
  if (validated !== undefined) {
    assessments.push(...validated.assessments);
    observations.push(...validated.observations);
    addUsage(usage, validated.progress.usage);
    completionIds.push(...validated.progress.completion_ids);
  }
  const completedGroupIds = [...(progress?.completed_group_ids ?? [])];
  let modelCompleted = assessments.length;
  let deterministicFallback = 0;
  const fallbackGroups = [...plan.fallbackGroups];
  const deadline = Date.now() + (spec.policy.maxReviewMs ?? 1_200_000);
  for (
    let index = completedGroupIds.length;
    index < plan.modelGroups.length;
    index += 1
  ) {
    const group = plan.modelGroups[index]!;
    let reviewed;
    try {
      reviewed = await reviewGroup(group, spec, usage, completionIds, deadline);
    } catch (error) {
      if (
        !fallbackEnabled ||
        !(error instanceof ModelRequestError) ||
        error.code === "MODEL_CONFIGURATION"
      )
        throw error;
      fallbackGroups.push(...plan.modelGroups.slice(index));
      break;
    }
    assessments.push(...reviewed.assessments);
    observations.push(...reviewed.observations);
    modelCompleted += reviewed.assessments.length;
    completedGroupIds.push(group.group_id);
    if (spec.onProgress !== undefined)
      await spec.onProgress(
        ContextualReviewProgressSchema.parse({
          policy_version: "2",
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
  const repositoryPaths = spec.groups.map(({ path }) => path);
  for (const group of fallbackGroups) {
    const reviewed = conservativeFallback(group, repositoryPaths);
    assessments.push(...reviewed.assessments);
    deterministicFallback += reviewed.assessments.length;
  }
  const candidateOrder = new Map(
    spec.groups
      .flatMap((group) =>
        group.candidates.map((candidate) => candidate.candidate_id),
      )
      .map((candidateId, index) => [candidateId, index]),
  );
  assessments.sort(
    (left, right) =>
      candidateOrder.get(left.candidate_id)! -
      candidateOrder.get(right.candidate_id)!,
  );
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
    policy_version: "2",
    prompt_version: CONTEXTUAL_PROMPT_VERSION,
    schema_version: CONTEXTUAL_SCHEMA_VERSION,
    model: spec.provider.model,
    provider: endpoint.hostname,
    endpoint_origin: endpoint.origin,
    coverage: {
      required: candidateIds.size,
      completed: assessments.length,
      model_completed: modelCompleted,
      deterministic_fallback: deterministicFallback,
    },
    assessments,
    observations,
    usage,
    completion_ids: completionIds,
  });
}
