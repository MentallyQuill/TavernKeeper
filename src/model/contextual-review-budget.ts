import type { EvidenceContextGroup } from "../context/evidence-context.js";
import { contextualReviewResponseJsonSchemaForBatch } from "./contextual-review-contract.js";
import { buildContextualReviewBatchPrompt } from "./contextual-prompt.js";
import {
  ModelRequestError,
  type ModelUsage,
} from "./openai-compatible-client.js";

export interface ContextualReviewBudgetPolicy {
  maxImmediateAttempts: number;
  maxOutputTokens: number;
  maxBatchGroups: number;
  maxBatchInputTokens: number;
  maxFreshBehaviorCases: number;
  maxProviderCalls: number;
  maxEstimatedInputTokens: number;
  maxActualInputTokens: number;
  maxActualOutputTokens: number;
}

interface ReusableGroupIdentity {
  review_input_digest: string;
}

interface ReviewBudgetProgress {
  completed_group_ids: readonly string[];
  completion_ids: readonly string[];
  usage: ModelUsage;
  review_units?: readonly { reused: boolean }[] | undefined;
  review_batches?:
    readonly { estimated_input_tokens: number | null }[] | undefined;
}

export interface PlannedContextualBatch {
  groups: EvidenceContextGroup[];
  estimatedInputTokens: number;
}

export interface ContextualReviewPlan {
  freshGroups: EvidenceContextGroup[];
  batches: PlannedContextualBatch[];
  freshBehaviorCases: number;
  estimatedInputTokens: number;
}

export interface ContextualReviewWavePlan extends ContextualReviewPlan {
  selectedGroups: EvidenceContextGroup[];
  pendingGroups: number;
  complete: boolean;
}

function budgetError(message: string): never {
  throw new ModelRequestError(
    "MODEL_REVIEW_BUDGET_EXCEEDED",
    "repository",
    message,
  );
}

function estimatedStructuredOutputTokens(schema: Record<string, unknown>) {
  return Math.ceil(Buffer.byteLength(JSON.stringify(schema), "utf8") / 3);
}

function estimatedBatchInput(groups: readonly EvidenceContextGroup[]) {
  const repairs = new Map(
    groups.map((group) => [
      group.group_id,
      { diagnostic: "assessment_developer_action" } as const,
    ]),
  );
  const prompt = buildContextualReviewBatchPrompt(groups, repairs, true);
  const schema = contextualReviewResponseJsonSchemaForBatch(groups, true);
  return prompt.estimatedInputTokens + estimatedStructuredOutputTokens(schema);
}

export function takeContextualReviewBatch(
  groups: readonly EvidenceContextGroup[],
  start: number,
  policy: ContextualReviewBudgetPolicy,
): PlannedContextualBatch {
  const batch: EvidenceContextGroup[] = [];
  let estimate = 0;
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
    const nextEstimate = estimatedBatchInput(next);
    const candidateCount = next.reduce(
      (total, group) => total + group.candidates.length,
      0,
    );
    if (
      batch.length > 0 &&
      (nextEstimate > policy.maxBatchInputTokens ||
        candidateCount > maximumEstimatedCandidates)
    )
      break;
    batch.push(groups[index]!);
    estimate = nextEstimate;
  }
  return { groups: batch, estimatedInputTokens: estimate };
}

export function planContextualReview(
  groups: readonly EvidenceContextGroup[],
  reusableGroups: ReadonlyMap<string, ReusableGroupIdentity> = new Map(),
  progress: ReviewBudgetProgress | undefined,
  policy: ContextualReviewBudgetPolicy,
): ContextualReviewPlan {
  const remaining = groups.slice(progress?.completed_group_ids.length ?? 0);
  const freshGroups = remaining.filter(
    ({ group_id }) => !reusableGroups.has(group_id),
  );
  const priorFresh =
    progress?.review_units === undefined
      ? (progress?.completed_group_ids.length ?? 0)
      : progress.review_units.filter(({ reused }) => !reused).length;
  const freshBehaviorCases = priorFresh + freshGroups.length;
  if (freshBehaviorCases > policy.maxFreshBehaviorCases)
    budgetError(
      "Contextual review exceeds the per-target behavior-case budget.",
    );

  const batches: PlannedContextualBatch[] = [];
  for (let start = 0; start < freshGroups.length;) {
    const batch = takeContextualReviewBatch(freshGroups, start, policy);
    if (batch.groups.length === 0)
      budgetError("Contextual review could not form a bounded provider batch.");
    batches.push(batch);
    start += batch.groups.length;
  }
  const persistedEstimate =
    progress?.review_batches?.reduce(
      (total, batch) => total + (batch.estimated_input_tokens ?? 0),
      0,
    ) ?? 0;
  const estimatedInputTokens =
    persistedEstimate +
    batches.reduce((total, batch) => total + batch.estimatedInputTokens, 0);
  if (estimatedInputTokens > policy.maxEstimatedInputTokens)
    budgetError("Contextual review exceeds the estimated input-token budget.");
  return {
    freshGroups,
    batches,
    freshBehaviorCases,
    estimatedInputTokens,
  };
}

function batchesFor(
  freshGroups: readonly EvidenceContextGroup[],
  policy: ContextualReviewBudgetPolicy,
) {
  const batches: PlannedContextualBatch[] = [];
  for (let start = 0; start < freshGroups.length;) {
    const batch = takeContextualReviewBatch(freshGroups, start, policy);
    if (batch.groups.length === 0)
      budgetError("Contextual review could not form a bounded provider batch.");
    batches.push(batch);
    start += batch.groups.length;
  }
  return batches;
}

export function planContextualReviewWave(
  groups: readonly EvidenceContextGroup[],
  reusableGroups: ReadonlyMap<string, ReusableGroupIdentity> = new Map(),
  progress: ReviewBudgetProgress | undefined,
  policy: ContextualReviewBudgetPolicy,
): ContextualReviewWavePlan {
  const remaining = groups.slice(progress?.completed_group_ids.length ?? 0);
  let selectedGroups: EvidenceContextGroup[] = [];
  let freshGroups: EvidenceContextGroup[] = [];
  let batches: PlannedContextualBatch[] = [];
  let estimatedInputTokens = 0;

  for (let length = 1; length <= remaining.length; length += 1) {
    const candidateGroups = remaining.slice(0, length);
    const candidateFresh = candidateGroups.filter(
      ({ group_id }) => !reusableGroups.has(group_id),
    );
    if (candidateFresh.length > policy.maxFreshBehaviorCases) break;
    const candidateBatches = batchesFor(candidateFresh, policy);
    const candidateEstimate = candidateBatches.reduce(
      (total, batch) => total + batch.estimatedInputTokens,
      0,
    );
    if (
      candidateBatches.length * policy.maxImmediateAttempts >
        policy.maxProviderCalls ||
      candidateEstimate * policy.maxImmediateAttempts >
        policy.maxEstimatedInputTokens
    )
      break;
    selectedGroups = candidateGroups;
    freshGroups = candidateFresh;
    batches = candidateBatches;
    estimatedInputTokens = candidateEstimate;
  }

  if (remaining.length > 0 && selectedGroups.length === 0)
    budgetError(
      "One indivisible contextual group exceeds an empty review wave budget.",
    );

  return {
    selectedGroups,
    freshGroups,
    batches,
    freshBehaviorCases: freshGroups.length,
    estimatedInputTokens,
    pendingGroups: remaining.length - selectedGroups.length,
    complete: selectedGroups.length === remaining.length,
  };
}

export class ReviewBudgetLedger {
  private providerCalls: number;
  private inputTokens: number;
  private outputTokens: number;

  constructor(
    private readonly policy: ContextualReviewBudgetPolicy,
    progress?: Pick<
      ReviewBudgetProgress,
      "completion_ids" | "usage" | "review_batches"
    >,
  ) {
    this.providerCalls = Math.max(
      progress?.completion_ids.length ?? 0,
      progress?.review_batches?.length ?? 0,
    );
    this.inputTokens = progress?.usage.inputTokens ?? 0;
    this.outputTokens = progress?.usage.outputTokens ?? 0;
  }

  assertBeforeProviderCall() {
    if (this.providerCalls >= this.policy.maxProviderCalls)
      budgetError("Contextual review exhausted its provider-call budget.");
    if (this.inputTokens >= this.policy.maxActualInputTokens)
      budgetError("Contextual review exhausted its actual input-token budget.");
    if (this.outputTokens >= this.policy.maxActualOutputTokens)
      budgetError(
        "Contextual review exhausted its actual output-token budget.",
      );
  }

  recordCompletion(usage: ModelUsage) {
    this.providerCalls += 1;
    this.inputTokens += usage.inputTokens;
    this.outputTokens += usage.outputTokens;
    if (
      this.providerCalls > this.policy.maxProviderCalls ||
      this.inputTokens > this.policy.maxActualInputTokens ||
      this.outputTokens > this.policy.maxActualOutputTokens
    )
      budgetError("Contextual review exceeded its cumulative model budget.");
  }

  snapshot() {
    return {
      providerCalls: this.providerCalls,
      inputTokens: this.inputTokens,
      outputTokens: this.outputTokens,
    };
  }
}
