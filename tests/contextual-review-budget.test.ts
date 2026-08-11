import { createHash } from "node:crypto";

import { describe, expect, test, vi } from "vitest";

import type { EvidenceContextGroup } from "../src/context/evidence-context.js";
import {
  type ContextualReviewProvider,
  ContextualReviewProgressSchema,
  reviewEvidenceGroups,
} from "../src/model/contextual-review.js";
import {
  planContextualReviewWave,
  ReviewBudgetLedger,
} from "../src/model/contextual-review-budget.js";
import type {
  ModelCompletionResult,
  TextCompletionRequest,
} from "../src/model/openai-compatible-client.js";

function digest(value: string) {
  return createHash("sha256").update(value).digest("hex");
}

function group(index: number): EvidenceContextGroup {
  const candidateId = digest(`candidate:${index}`);
  const path = `src/${index}.js`;
  return {
    group_id: digest(`group:${index}`),
    repository: "owner/project",
    project_kinds: ["extension"],
    path,
    file_role: "production",
    execution_scope: "runtime",
    target_sha: "a".repeat(40),
    evidence_sha: "a".repeat(40),
    source_kind: "text",
    source_bytes: 20,
    source_sha256: digest(`source:${index}`),
    ecosystem_context_version: "sillytavern-community-v1",
    ecosystem_context: "Trusted ecosystem context.",
    candidates: [
      {
        candidate_id: candidateId,
        evidence_id: candidateId,
        origin: "opengrep",
        rule_id: `rule-${index}`,
        category: "network-access",
        scanner_severity: "medium",
        scanner_confidence: "medium",
        title: "Network access",
        explanation: "A request is made.",
        line_start: 1,
        line_end: 1,
      },
    ],
    context: {
      imports: "",
      source: "     1 | fetch(endpoint);",
      expansions: [],
      representations: [
        { stage: "raw", sha256: digest(`raw:${index}`), transform_depth: 0 },
      ],
      project_purpose: "A model helper.",
    },
  };
}

const policy = {
  version: "5",
  promptVersion: "contextual-review-v7",
  schemaVersion: "contextual-assessment-v2",
  maxImmediateAttempts: 3,
  maxOutputTokens: 32_768,
  maxResponseBytes: 5_000_000,
  timeoutMs: 300_000,
  maxBatchGroups: 5,
  maxBatchInputTokens: 64_000,
  maxFreshBehaviorCases: 12,
  maxProviderCalls: 6,
  maxEstimatedInputTokens: 200_000,
  maxActualInputTokens: 250_000,
  maxActualOutputTokens: 40_000,
} as const;

function progress(input: {
  calls: number;
  inputTokens: number;
  outputTokens: number;
}) {
  const batches = Array.from({ length: input.calls }, (_, index) => ({
    kind: "contextual_review" as const,
    attempt: 1,
    group_count: 1,
    candidate_count: 1,
    estimated_input_tokens: 1,
    over_budget: false,
    input_tokens: index === 0 ? input.inputTokens : 0,
    output_tokens: index === 0 ? input.outputTokens : 0,
    cache_read_tokens: 0,
    reasoning_tokens: 0,
  }));
  return ContextualReviewProgressSchema.parse({
    policy_version: "5",
    prompt_version: "contextual-review-v7",
    schema_version: "contextual-assessment-v2",
    model: "configured/model:thinking",
    provider: "provider.example",
    endpoint_origin: "https://provider.example",
    completed_group_ids: [],
    assessments: [],
    observations: [],
    usage: {
      inputTokens: input.inputTokens,
      outputTokens: input.outputTokens,
      cacheReadTokens: 0,
      reasoningTokens: 0,
    },
    completion_ids: Array.from(
      { length: input.calls },
      (_, index) => `completion-${index}`,
    ),
    review_units: [],
    ...(input.calls === 0 ? {} : { review_batches: batches }),
  });
}

function reviewSpec(
  requestCompletion: NonNullable<ContextualReviewProvider["requestCompletion"]>,
  priorProgress?: ReturnType<typeof progress>,
) {
  return {
    groups: [group(1)],
    provider: {
      endpoint: "https://provider.example/v1/chat/completions",
      apiKey: "test-key",
      model: "configured/model:thinking",
      requestCompletion,
    },
    policy,
    ...(priorProgress === undefined ? {} : { progress: priorProgress }),
  };
}

function completedResponse(
  item: EvidenceContextGroup,
  completionId: string,
  inputTokens: number,
  outputTokens: number,
): ModelCompletionResult {
  const candidate = item.candidates[0]!;
  return {
    completionId,
    endpointOrigin: "https://provider.example",
    provider: "provider.example",
    content: JSON.stringify({
      review: {
        status: "complete",
        assessments: [
          {
            candidate_id: candidate.candidate_id,
            evidence_ids: [candidate.evidence_id],
            disposition: "expected_behavior",
            impact: "none",
            exploitability: "unlikely",
            confidence: "high",
            risk_exposure: "not_demonstrated",
            recommended_risk: "low",
            technical_explanation:
              "The request matches the documented model helper.",
            layman_explanation: "This request appears to be expected.",
            developer_action: "none",
          },
        ],
        observations: [],
      },
    }),
    usage: {
      inputTokens,
      outputTokens,
      cacheReadTokens: 0,
      reasoningTokens: 0,
    },
  };
}

describe("contextual review budget", () => {
  test("plans a large target as stable bounded waves", () => {
    const groups = Array.from({ length: 24 }, (_, index) => group(index));

    const first = planContextualReviewWave(
      groups,
      new Map(),
      undefined,
      policy,
    );

    expect(first.selectedGroups.map(({ group_id }) => group_id)).toEqual(
      groups.slice(0, 12).map(({ group_id }) => group_id),
    );
    expect(first.freshBehaviorCases).toBe(12);
    expect(first.pendingGroups).toBe(12);
    expect(first.complete).toBe(false);

    const second = planContextualReviewWave(
      groups,
      new Map(),
      {
        completed_group_ids: groups
          .slice(0, 12)
          .map(({ group_id }) => group_id),
        completion_ids: Array.from(
          { length: first.batches.length },
          (_, index) => `completion-${index}`,
        ),
        usage: {
          inputTokens: 249_999,
          outputTokens: 39_999,
          cacheReadTokens: 0,
          reasoningTokens: 0,
        },
      },
      policy,
    );

    expect(second.selectedGroups.map(({ group_id }) => group_id)).toEqual(
      groups.slice(12).map(({ group_id }) => group_id),
    );
    expect(second.complete).toBe(true);
    expect(new ReviewBudgetLedger(policy).snapshot()).toEqual({
      providerCalls: 0,
      inputTokens: 0,
      outputTokens: 0,
    });
  });

  test("reused groups do not consume fresh wave capacity", () => {
    const groups = Array.from({ length: 16 }, (_, index) => group(index));
    const reusable = new Map(
      groups
        .slice(0, 4)
        .map(({ group_id }) => [group_id, { review_input_digest: group_id }]),
    );

    const wave = planContextualReviewWave(groups, reusable, undefined, policy);

    expect(wave.selectedGroups).toHaveLength(16);
    expect(wave.freshGroups).toHaveLength(12);
    expect(wave.pendingGroups).toBe(0);
    expect(wave.complete).toBe(true);
  });

  test("classifies one indivisible oversized group before a provider request", () => {
    const oversized = group(99);
    oversized.context.source = `     1 | ${"x".repeat(900_000)}`;

    expect(() =>
      planContextualReviewWave([oversized], new Map(), undefined, policy),
    ).toThrow(/indivisible contextual group/iu);
  });

  test("rejects thirteen fresh behavior cases before a provider request", async () => {
    const requestCompletion = vi.fn();

    await expect(
      reviewEvidenceGroups({
        groups: Array.from({ length: 13 }, (_, index) => group(index)),
        provider: {
          endpoint: "https://provider.example/v1/chat/completions",
          apiKey: "test-key",
          model: "configured/model:thinking",
          requestCompletion,
        },
        policy,
      }),
    ).rejects.toMatchObject({
      code: "MODEL_REVIEW_BUDGET_EXCEEDED",
      scope: "repository",
    });
    expect(requestCompletion).not.toHaveBeenCalled();
  });

  test.each([
    ["provider calls", progress({ calls: 6, inputTokens: 6, outputTokens: 6 })],
    [
      "actual input tokens",
      progress({ calls: 0, inputTokens: 250_000, outputTokens: 0 }),
    ],
    [
      "actual output tokens",
      progress({ calls: 0, inputTokens: 0, outputTokens: 40_000 }),
    ],
  ])("does not request after exhausting %s", async (_name, priorProgress) => {
    const requestCompletion = vi.fn(async () => {
      throw new Error("Provider request was not expected.");
    });

    await expect(
      reviewEvidenceGroups(reviewSpec(requestCompletion, priorProgress)),
    ).rejects.toMatchObject({ code: "MODEL_REVIEW_BUDGET_EXCEEDED" });
    expect(requestCompletion).not.toHaveBeenCalled();
  });

  test("never makes a seventh live provider call", async () => {
    const groups = Array.from({ length: 7 }, (_, index) => group(index));
    const requestCompletion = vi.fn(async (_request: TextCompletionRequest) => {
      const index = requestCompletion.mock.calls.length - 1;
      return completedResponse(groups[index]!, `completion-${index}`, 100, 20);
    });

    await expect(
      reviewEvidenceGroups({
        groups,
        provider: {
          endpoint: "https://provider.example/v1/chat/completions",
          apiKey: "test-key",
          model: "configured/model:thinking",
          requestCompletion,
        },
        policy: { ...policy, maxBatchGroups: 1 },
      }),
    ).rejects.toMatchObject({ code: "MODEL_REVIEW_BUDGET_EXCEEDED" });
    expect(requestCompletion).toHaveBeenCalledTimes(6);
  });

  test.each([
    ["input", 250_000, 10],
    ["output", 10, 40_000],
  ] as const)(
    "stops after a completion exhausts the actual %s-token budget",
    async (_name, inputTokens, outputTokens) => {
      const groups = [group(20), group(21)];
      const requestCompletion = vi.fn(async (_request: TextCompletionRequest) =>
        completedResponse(
          groups[0]!,
          "completion-limit",
          inputTokens,
          outputTokens,
        ),
      );

      await expect(
        reviewEvidenceGroups({
          groups,
          provider: {
            endpoint: "https://provider.example/v1/chat/completions",
            apiKey: "test-key",
            model: "configured/model:thinking",
            requestCompletion,
          },
          policy: { ...policy, maxBatchGroups: 1 },
        }),
      ).rejects.toMatchObject({ code: "MODEL_REVIEW_BUDGET_EXCEEDED" });
      expect(requestCompletion).toHaveBeenCalledTimes(1);
    },
  );

  test("rejects an oversized estimated plan before a provider request", async () => {
    const oversized = group(30);
    oversized.context.source = `     1 | ${"x".repeat(900_000)}`;
    const requestCompletion = vi.fn();

    await expect(
      reviewEvidenceGroups({
        ...reviewSpec(requestCompletion),
        groups: [oversized],
      }),
    ).rejects.toMatchObject({ code: "MODEL_REVIEW_BUDGET_EXCEEDED" });
    expect(requestCompletion).not.toHaveBeenCalled();
  });
});
