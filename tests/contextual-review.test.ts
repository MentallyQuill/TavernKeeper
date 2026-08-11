import { describe, expect, test, vi } from "vitest";

import type { EvidenceContextGroup } from "../src/context/evidence-context.js";
import {
  CompletedContextualReviewSchema,
  reviewEvidenceGroups,
  type ContextualReviewProgress,
} from "../src/model/contextual-review.js";
import {
  ModelRequestError,
  type ModelCompletionResult,
  type TextCompletionRequest,
} from "../src/model/openai-compatible-client.js";

const ids = ["a", "b", "c"].map((character) => character.repeat(64));
const policy = {
  version: "5",
  promptVersion: "contextual-review-v7",
  schemaVersion: "contextual-assessment-v2",
  maxImmediateAttempts: 3,
  maxOutputTokens: 8_192,
  maxResponseBytes: 5_000_000,
  timeoutMs: 600_000,
  maxBatchGroups: 1,
  maxBatchInputTokens: 64_000,
  maxFreshBehaviorCases: 12,
  maxProviderCalls: 6,
  maxEstimatedInputTokens: 200_000,
  maxActualInputTokens: 250_000,
  maxActualOutputTokens: 40_000,
} as const;

function group(
  path: string,
  candidateIds: readonly string[],
): EvidenceContextGroup {
  return {
    group_id: candidateIds[0]!,
    repository: "owner/project",
    project_kinds: ["extension"],
    path,
    file_role: "production",
    execution_scope: "runtime",
    target_sha: "d".repeat(40),
    evidence_sha: "d".repeat(40),
    source_kind: "text",
    source_bytes: 1,
    source_sha256: "e".repeat(64),
    ecosystem_context_version: "sillytavern-community-v1",
    ecosystem_context: "Trusted ecosystem context.",
    candidates: candidateIds.map((candidateId, index) => ({
      candidate_id: candidateId,
      evidence_id: candidateId,
      origin: "opengrep",
      rule_id: `rule-${index}`,
      category: "network-access",
      scanner_severity: "medium",
      scanner_confidence: "medium",
      title: "Network access",
      explanation: "A request is made.",
      line_start: index + 2,
      line_end: index + 2,
    })),
    context: {
      imports: '     1 | import { fetch } from "client";',
      source: [
        '     1 | import { fetch } from "client";',
        "     2 | fetch(endpoint);",
        "     3 | fetch(secondEndpoint);",
      ].join("\n"),
      expansions: [
        [
          '     1 | import { fetch } from "client";',
          "     2 | fetch(endpoint);",
          "     3 | fetch(secondEndpoint);",
          "     4 | const endpoint = configuredEndpoint;",
        ].join("\n"),
      ],
      representations: [
        { stage: "raw", sha256: "e".repeat(64), transform_depth: 0 },
      ],
      project_purpose: "A model helper.",
    },
  };
}

function assessment(candidateId: string, _path: string, _line: number) {
  return {
    candidate_id: candidateId,
    evidence_ids: [candidateId],
    disposition: "expected_behavior",
    impact: "none",
    exploitability: "unlikely",
    confidence: "high",
    risk_exposure: "not_demonstrated",
    recommended_risk: "low",
    technical_explanation: "The request matches the documented model helper.",
    layman_explanation: "This request appears to be expected.",
    developer_action: "none",
  } as const;
}

function reviewContent(review: unknown) {
  return JSON.stringify({ review });
}

function batchContent(
  reviews: ReadonlyArray<{ group_id: string; review: unknown }>,
) {
  return JSON.stringify({ reviews });
}

describe("contextual evidence review", () => {
  test("checkpoints one bounded wave without returning a partial review", async () => {
    const groups = Array.from({ length: 13 }, (_, index) => {
      const candidateId = (index + 1).toString(16).padStart(64, "0");
      return group(`src/wave-${index}.ts`, [candidateId]);
    });
    const checkpoints: ContextualReviewProgress[] = [];
    const requestCompletion = vi.fn(async (request: TextCompletionRequest) => {
      const included = groups.filter((item) =>
        request.userContent.includes(item.group_id),
      );
      return {
        completionId: `completion-wave-${requestCompletion.mock.calls.length}`,
        endpointOrigin: "https://provider.example",
        provider: "provider.example",
        content: batchContent(
          included.map((item) => ({
            group_id: item.group_id,
            review: {
              status: "complete",
              assessments: [
                assessment(item.candidates[0]!.candidate_id, item.path, 2),
              ],
              observations: [],
            },
          })),
        ),
        usage: {
          inputTokens: 500,
          outputTokens: 100,
          cacheReadTokens: 0,
          reasoningTokens: 10,
        },
      } satisfies ModelCompletionResult;
    });

    const result = await reviewEvidenceGroups({
      groups,
      provider: {
        endpoint: "https://provider.example/v1/chat/completions",
        apiKey: "test-key",
        model: "configured/model:thinking",
        requestCompletion,
      },
      policy: {
        ...policy,
        maxOutputTokens: 32_768,
        maxBatchGroups: 5,
        maxBatchInputTokens: 1_000_000,
      },
      stopAfterWave: true,
      onProgress: async (progress) => {
        checkpoints.push(structuredClone(progress));
      },
    });

    expect(result).toMatchObject({
      status: "review_pending",
      pending_groups: 3,
      progress: {
        review_protocol_version: 2,
        completed_group_ids: groups
          .slice(0, 10)
          .map(({ group_id }) => group_id),
      },
    });
    expect(requestCompletion).toHaveBeenCalledTimes(2);
    expect(checkpoints.at(-1)?.completed_group_ids).toHaveLength(10);
    expect(CompletedContextualReviewSchema.safeParse(result).success).toBe(
      false,
    );
    if (!("status" in result))
      throw new Error("First bounded review unexpectedly completed.");

    const resumed = await reviewEvidenceGroups({
      groups,
      provider: {
        endpoint: "https://provider.example/v1/chat/completions",
        apiKey: "test-key",
        model: "configured/model:thinking",
        requestCompletion,
      },
      policy: {
        ...policy,
        maxOutputTokens: 32_768,
        maxBatchGroups: 5,
        maxBatchInputTokens: 1_000_000,
      },
      progress: result.progress,
      stopAfterWave: true,
    });

    expect(CompletedContextualReviewSchema.parse(resumed).coverage).toEqual({
      required: 13,
      completed: 13,
    });
    expect(requestCompletion).toHaveBeenCalledTimes(3);
  });

  test("packs cache misses into ordered batches of at most five groups", async () => {
    const groups = Array.from({ length: 8 }, (_, index) => {
      const candidateId = (index + 1).toString(16).repeat(64);
      return group(`src/${index}.ts`, [candidateId]);
    });
    const requestCompletion = vi.fn(async (request: TextCompletionRequest) => {
      const included = groups.filter((item) =>
        request.userContent.includes(item.group_id),
      );
      return {
        completionId: `completion-batch-${requestCompletion.mock.calls.length}`,
        endpointOrigin: "https://provider.example",
        provider: "provider.example",
        content: batchContent(
          included.map((item) => ({
            group_id: item.group_id,
            review: {
              status: "complete",
              assessments: item.candidates.map((candidate) =>
                assessment(candidate.candidate_id, item.path, 2),
              ),
              observations: [],
            },
          })),
        ),
        usage: {
          inputTokens: 500,
          outputTokens: 100,
          cacheReadTokens: 0,
          reasoningTokens: 10,
        },
      } satisfies ModelCompletionResult;
    });

    const result = await reviewEvidenceGroups({
      groups,
      provider: {
        endpoint: "https://provider.example/v1/chat/completions",
        apiKey: "test-key",
        model: "configured/model:thinking",
        requestCompletion,
      },
      policy: {
        ...policy,
        maxOutputTokens: 32_768,
        maxBatchGroups: 5,
        maxBatchInputTokens: 1_000_000,
      },
      reusableGroups: new Map([
        [
          groups[0]!.group_id,
          {
            review_input_digest: groups[0]!.group_id,
            origin_report_id: "f".repeat(64),
            response: {
              status: "complete" as const,
              assessments: [
                assessment(
                  groups[0]!.candidates[0]!.candidate_id,
                  groups[0]!.path,
                  2,
                ),
              ],
              observations: [],
            },
          },
        ],
      ]) as never,
    });

    expect(requestCompletion).toHaveBeenCalledTimes(2);
    const firstBatchSchema = requestCompletion.mock.calls[0]![0]
      .responseJsonSchema!.schema as {
      properties?: {
        reviews?: {
          minItems?: number;
          maxItems?: number;
          items?: { anyOf?: unknown[] };
        };
      };
    };
    expect(firstBatchSchema.properties?.reviews).toMatchObject({
      minItems: 5,
      maxItems: 5,
    });
    expect(firstBatchSchema.properties?.reviews?.items?.anyOf).toHaveLength(5);
    expect(JSON.stringify(firstBatchSchema)).not.toContain('"$ref"');
    const firstRequest = requestCompletion.mock.calls[0]![0];
    const messageOnlyEstimate = Math.ceil(
      (Buffer.byteLength(firstRequest.systemContent, "utf8") +
        Buffer.byteLength(firstRequest.userContent, "utf8")) /
        3,
    );
    expect(
      requestCompletion.mock.calls.map(
        ([request]) =>
          groups.filter((item) => request.userContent.includes(item.group_id))
            .length,
      ),
    ).toEqual([5, 2]);
    expect(requestCompletion.mock.calls[0]![0].userContent).not.toContain(
      groups[0]!.group_id,
    );
    expect(result.coverage).toEqual({ required: 8, completed: 8 });
    expect(result.review_batches).toMatchObject([
      { group_count: 5, candidate_count: 5, input_tokens: 500 },
      { group_count: 2, candidate_count: 2, input_tokens: 500 },
    ]);
    expect(result.review_batches![0]!.estimated_input_tokens).toBeGreaterThan(
      messageOnlyEstimate,
    );
  });

  test("uses the input-token budget to split otherwise eligible groups", async () => {
    const groups = [
      group("src/a.ts", [ids[0]!]),
      group("src/b.ts", [ids[1]!]),
      group("src/c.ts", [ids[2]!]),
    ];
    const requestCompletion = vi.fn(async (request: TextCompletionRequest) => {
      const current = groups.find((item) =>
        request.userContent.includes(item.group_id),
      )!;
      return {
        completionId: `completion-token-batch-${requestCompletion.mock.calls.length}`,
        endpointOrigin: "https://provider.example",
        provider: "provider.example",
        content: batchContent([
          {
            group_id: current.group_id,
            review: {
              status: "complete",
              assessments: [
                assessment(
                  current.candidates[0]!.candidate_id,
                  current.path,
                  2,
                ),
              ],
              observations: [],
            },
          },
        ]),
        usage: {
          inputTokens: 100,
          outputTokens: 20,
          cacheReadTokens: 0,
          reasoningTokens: 0,
        },
      } satisfies ModelCompletionResult;
    });

    const result = await reviewEvidenceGroups({
      groups,
      provider: {
        endpoint: "https://provider.example/v1/chat/completions",
        apiKey: "test-key",
        model: "configured/model:thinking",
        requestCompletion,
      },
      policy: { ...policy, maxBatchGroups: 5, maxBatchInputTokens: 1 },
    });

    expect(requestCompletion).toHaveBeenCalledTimes(3);
    expect(
      result.review_batches!.map(({ group_count }) => group_count),
    ).toEqual([1, 1, 1]);
    expect(result.review_batches!.every(({ over_budget }) => over_budget)).toBe(
      true,
    );
  });

  test("splits dense groups before their estimated output can exceed the response budget", async () => {
    const candidateIds = Array.from({ length: 20 }, (_, index) =>
      (index + 1).toString(16).padStart(64, "0"),
    );
    const groups = [
      group("src/a.ts", candidateIds.slice(0, 10)),
      group("src/b.ts", candidateIds.slice(10)),
    ];
    const requestCompletion = vi.fn(async (request: TextCompletionRequest) => {
      const included = groups.filter((item) =>
        request.userContent.includes(item.group_id),
      );
      return {
        completionId: `completion-dense-${requestCompletion.mock.calls.length}`,
        endpointOrigin: "https://provider.example",
        provider: "provider.example",
        content: batchContent(
          included.map((item) => ({
            group_id: item.group_id,
            review: {
              status: "complete",
              assessments: item.candidates.map((candidate) =>
                assessment(candidate.candidate_id, item.path, 2),
              ),
              observations: [],
            },
          })),
        ),
        usage: {
          inputTokens: 200,
          outputTokens: 100,
          cacheReadTokens: 0,
          reasoningTokens: 0,
        },
      } satisfies ModelCompletionResult;
    });

    const result = await reviewEvidenceGroups({
      groups,
      provider: {
        endpoint: "https://provider.example/v1/chat/completions",
        apiKey: "test-key",
        model: "configured/model:thinking",
        requestCompletion,
      },
      policy: {
        ...policy,
        maxBatchGroups: 5,
        maxBatchInputTokens: 1_000_000,
      },
    });

    expect(requestCompletion).toHaveBeenCalledTimes(2);
    expect(result.coverage).toEqual({ required: 20, completed: 20 });
  });

  test("checkpoints valid cards and retries only a missing batch result", async () => {
    const groups = [
      group("src/a.ts", [ids[0]!]),
      group("src/b.ts", [ids[1]!]),
      group("src/c.ts", [ids[2]!]),
    ];
    const checkpoints: ContextualReviewProgress[] = [];
    const requestCompletion = vi.fn(async (request: TextCompletionRequest) => {
      const included = groups.filter((item) =>
        request.userContent.includes(item.group_id),
      );
      const returned =
        requestCompletion.mock.calls.length === 1
          ? included.slice(0, 2)
          : included;
      return {
        completionId: `completion-partial-${requestCompletion.mock.calls.length}`,
        endpointOrigin: "https://provider.example",
        provider: "provider.example",
        content: batchContent(
          returned.map((item) => ({
            group_id: item.group_id,
            review: {
              status: "complete",
              assessments: [
                assessment(item.candidates[0]!.candidate_id, item.path, 2),
              ],
              observations: [],
            },
          })),
        ),
        usage: {
          inputTokens: 300,
          outputTokens: 60,
          cacheReadTokens: 0,
          reasoningTokens: 5,
        },
      } satisfies ModelCompletionResult;
    });

    const result = await reviewEvidenceGroups({
      groups,
      provider: {
        endpoint: "https://provider.example/v1/chat/completions",
        apiKey: "test-key",
        model: "configured/model:thinking",
        requestCompletion,
      },
      policy: {
        ...policy,
        maxBatchGroups: 5,
        maxBatchInputTokens: 1_000_000,
      },
      onProgress: async (progress) => {
        checkpoints.push(structuredClone(progress));
      },
    });

    expect(requestCompletion).toHaveBeenCalledTimes(2);
    expect(
      groups.filter((item) =>
        requestCompletion.mock.calls[1]![0].userContent.includes(item.group_id),
      ),
    ).toEqual([groups[2]]);
    expect(requestCompletion.mock.calls[1]![0].systemContent).toContain(
      `For group_id ${groups[2]!.group_id}`,
    );
    expect(requestCompletion.mock.calls[1]![0].systemContent).not.toContain(
      "The top-level object must contain exactly one key named review.",
    );
    expect(
      checkpoints.map(({ completed_group_ids }) => completed_group_ids),
    ).toEqual([groups.map(({ group_id }) => group_id)]);
    expect(result.completion_ids).toEqual([
      "completion-partial-1",
      "completion-partial-2",
    ]);
  });

  test("retries only the batch card containing secret-shaped output", async () => {
    const groups = [group("src/a.ts", [ids[0]!]), group("src/b.ts", [ids[1]!])];
    const requestCompletion = vi.fn(async (request: TextCompletionRequest) => {
      const included = groups.filter((item) =>
        request.userContent.includes(item.group_id),
      );
      return {
        completionId: `completion-secret-batch-${requestCompletion.mock.calls.length}`,
        endpointOrigin: "https://provider.example",
        provider: "provider.example",
        content: batchContent(
          included.map((item) => ({
            group_id: item.group_id,
            review: {
              status: "complete",
              assessments: [
                {
                  ...assessment(item.candidates[0]!.candidate_id, item.path, 2),
                  ...(requestCompletion.mock.calls.length === 1 &&
                  item === groups[1]
                    ? {
                        layman_explanation: `The key was sk-nano-${"z".repeat(32)}.`,
                      }
                    : {}),
                },
              ],
              observations: [],
            },
          })),
        ),
        usage: {
          inputTokens: 200,
          outputTokens: 50,
          cacheReadTokens: 0,
          reasoningTokens: 0,
        },
      } satisfies ModelCompletionResult;
    });

    const result = await reviewEvidenceGroups({
      groups,
      provider: {
        endpoint: "https://provider.example/v1/chat/completions",
        apiKey: "test-key",
        model: "configured/model:thinking",
        requestCompletion,
      },
      policy: {
        ...policy,
        maxBatchGroups: 5,
        maxBatchInputTokens: 1_000_000,
      },
    });

    expect(requestCompletion).toHaveBeenCalledTimes(2);
    expect(requestCompletion.mock.calls[1]![0].userContent).not.toContain(
      groups[0]!.group_id,
    );
    expect(requestCompletion.mock.calls[1]![0].userContent).toContain(
      groups[1]!.group_id,
    );
    expect(result.coverage).toEqual({ required: 2, completed: 2 });
  });

  test("reuses one validated low group and calls the model only for the miss", async () => {
    const groups = [group("src/a.ts", [ids[0]!]), group("src/b.ts", [ids[1]!])];
    const requestCompletion = vi.fn(async () => ({
      completionId: "completion-fresh",
      endpointOrigin: "https://provider.example",
      provider: "provider.example",
      content: reviewContent({
        status: "complete",
        assessments: [assessment(ids[1]!, groups[1]!.path, 2)],
        observations: [],
      }),
      usage: {
        inputTokens: 100,
        outputTokens: 40,
        cacheReadTokens: 0,
        reasoningTokens: 10,
      },
    }));
    const reusedDigest = "f".repeat(64);
    const freshDigest = "0".repeat(64);

    const result = await reviewEvidenceGroups({
      groups,
      provider: {
        endpoint: "https://provider.example/v1/chat/completions",
        apiKey: "test-key",
        model: "configured/model:thinking",
        requestCompletion,
      },
      policy,
      reviewInputDigests: new Map([
        [groups[0]!.group_id, reusedDigest],
        [groups[1]!.group_id, freshDigest],
      ]),
      reusableGroups: new Map([
        [
          groups[0]!.group_id,
          {
            review_input_digest: reusedDigest,
            origin_report_id: "1".repeat(64),
            response: {
              status: "complete" as const,
              assessments: [assessment(ids[0]!, groups[0]!.path, 2)],
              observations: [],
            },
          },
        ],
      ]) as never,
    });

    expect(requestCompletion).toHaveBeenCalledTimes(1);
    expect(result.coverage).toEqual({ required: 2, completed: 2 });
    expect(result.usage).toEqual({
      inputTokens: 100,
      outputTokens: 40,
      cacheReadTokens: 0,
      reasoningTokens: 10,
    });
    expect(result.completion_ids).toEqual(["completion-fresh"]);
    expect(result.review_units).toEqual([
      {
        group_id: groups[0]!.group_id,
        review_input_digest: reusedDigest,
        candidate_ids: [ids[0]!],
        reused: true,
        origin_report_id: "1".repeat(64),
      },
      {
        group_id: groups[1]!.group_id,
        review_input_digest: freshDigest,
        candidate_ids: [ids[1]!],
        reused: false,
        origin_report_id: null,
      },
    ]);
  });

  test("reviews every file group and covers every candidate exactly once", async () => {
    const groups = [
      group("src/a.ts", ids.slice(0, 2)),
      group("src/b.ts", [ids[2]!]),
    ];
    const requestCompletion = vi.fn(async (request) => {
      const current = groups.find((item) =>
        request.userContent.includes(item.group_id),
      )!;
      return {
        completionId: `completion-${current.path.replaceAll("/", "-")}`,
        endpointOrigin: "https://provider.example",
        provider: "provider.example",
        content: reviewContent({
          status: "complete",
          assessments: current.candidates.map((candidate) =>
            assessment(
              candidate.candidate_id,
              current.path,
              candidate.line_start ?? 1,
            ),
          ),
          observations: [],
        }),
        usage: {
          inputTokens: 100,
          outputTokens: 40,
          cacheReadTokens: 0,
          reasoningTokens: 10,
        },
      } satisfies ModelCompletionResult;
    });

    const result = await reviewEvidenceGroups({
      groups,
      provider: {
        endpoint: "https://provider.example/v1/chat/completions",
        apiKey: "test-key",
        model: "configured/model:thinking",
        requestCompletion,
      },
      policy,
    });

    expect(requestCompletion).toHaveBeenCalledTimes(2);
    const firstSchema = requestCompletion.mock.calls[0]?.[0].responseJsonSchema
      ?.schema as {
      properties?: {
        review?: {
          anyOf?: Array<{
            properties?: {
              assessments?: {
                minItems?: number;
                maxItems?: number;
                items?: {
                  properties?: {
                    candidate_id?: { enum?: string[] };
                    evidence_ids?: { items?: { enum?: string[] } };
                  };
                };
              };
              observations?: {
                items?: {
                  properties?: {
                    locations?: {
                      items?: { properties?: { path?: { const?: string } } };
                    };
                  };
                };
              };
            };
          }>;
        };
      };
    };
    const firstCompleted = firstSchema.properties?.review?.anyOf?.[0];
    expect(firstCompleted?.properties?.assessments).toMatchObject({
      minItems: 2,
      maxItems: 2,
    });
    expect(
      firstCompleted?.properties?.assessments?.items?.properties?.candidate_id
        ?.enum,
    ).toEqual(ids.slice(0, 2));
    expect(
      firstCompleted?.properties?.assessments?.items?.properties?.evidence_ids
        ?.items?.enum,
    ).toEqual(ids.slice(0, 2));
    expect(
      firstCompleted?.properties?.observations?.items?.properties?.locations
        ?.items?.properties?.path?.const,
    ).toBe("src/a.ts");
    expect(result.coverage).toEqual({ required: 3, completed: 3 });
    expect(result.assessments.map((item) => item.candidate_id)).toEqual(ids);
    expect(result.assessments.map((item) => item.locations)).toEqual([
      [{ path: "src/a.ts", line_start: 2, line_end: 2 }],
      [{ path: "src/a.ts", line_start: 3, line_end: 3 }],
      [{ path: "src/b.ts", line_start: 2, line_end: 2 }],
    ]);
    expect(CompletedContextualReviewSchema.parse(result)).toEqual(result);
    expect(
      CompletedContextualReviewSchema.safeParse({
        ...result,
        raw_response: "must never persist",
      }).success,
    ).toBe(false);
  });

  test("replaces unsafe narrative strings without discarding a valid assessment", async () => {
    const current = group("src/a.ts", [ids[0]!]);
    const requestCompletion = vi.fn(
      async () =>
        ({
          completionId: `completion-unsafe-narrative-${requestCompletion.mock.calls.length}`,
          endpointOrigin: "https://provider.example",
          provider: "provider.example",
          content: reviewContent({
            status: "complete",
            assessments: [
              {
                ...assessment(ids[0]!, current.path, 2),
                technical_explanation:
                  "const leakedValue = sourceValue; see https://example.invalid/details",
                layman_explanation: "A".repeat(601),
                developer_action: "Keep onload = handler for this path.",
              },
            ],
            observations: [],
          }),
          usage: {
            inputTokens: 100,
            outputTokens: 40,
            cacheReadTokens: 0,
            reasoningTokens: 10,
          },
        }) satisfies ModelCompletionResult,
    );

    const result = await reviewEvidenceGroups({
      groups: [current],
      provider: {
        endpoint: "https://provider.example/v1/chat/completions",
        apiKey: "test-key",
        model: "configured/model:thinking",
        requestCompletion,
      },
      policy,
    });

    expect(requestCompletion).toHaveBeenCalledTimes(3);
    expect(result.assessments[0]?.technical_explanation).toBe(
      "Detailed technical wording was omitted by the public report safety filter.",
    );
    expect(result.assessments[0]?.layman_explanation).toBe(
      "Detailed wording was omitted by the public report safety filter.",
    );
    expect(result.assessments[0]?.developer_action).toBe(
      "Review the cited evidence and confirm the intended behavior.",
    );
    expect(JSON.stringify(result)).not.toContain("leakedValue");
    expect(JSON.stringify(result)).not.toContain("example.invalid");
  });

  test("accepts one fenced JSON object from a non-strict provider", async () => {
    const current = group("src/a.ts", [ids[0]!]);
    const requestCompletion = vi.fn(async () => ({
      completionId: "completion-fenced",
      endpointOrigin: "https://provider.example",
      provider: "provider.example",
      content: `\`\`\`json\n${reviewContent({
        status: "complete",
        assessments: [assessment(ids[0]!, current.path, 2)],
        observations: [],
      })}\n\`\`\``,
      usage: {
        inputTokens: 100,
        outputTokens: 40,
        cacheReadTokens: 0,
        reasoningTokens: 10,
      },
    }));

    await expect(
      reviewEvidenceGroups({
        groups: [current],
        provider: {
          endpoint: "https://provider.example/v1/chat/completions",
          apiKey: "test-key",
          model: "configured/model:thinking",
          requestCompletion,
        },
        policy,
      }),
    ).resolves.toMatchObject({ coverage: { required: 1, completed: 1 } });
  });

  test("retries public safety claims before report finalization", async () => {
    const current = group("src/a.ts", [ids[0]!]);
    const requestCompletion = vi.fn(async (_request: TextCompletionRequest) => {
      const item = assessment(ids[0]!, current.path, 2);
      return {
        completionId: `completion-${requestCompletion.mock.calls.length}`,
        endpointOrigin: "https://provider.example",
        provider: "provider.example",
        content: reviewContent({
          status: "complete",
          assessments: [
            requestCompletion.mock.calls.length === 1
              ? { ...item, layman_explanation: "This repository is safe." }
              : item,
          ],
          observations: [],
        }),
        usage: {
          inputTokens: 100,
          outputTokens: 40,
          cacheReadTokens: 0,
          reasoningTokens: 10,
        },
      } satisfies ModelCompletionResult;
    });

    await expect(
      reviewEvidenceGroups({
        groups: [current],
        provider: {
          endpoint: "https://provider.example/v1/chat/completions",
          apiKey: "test-key",
          model: "configured/model:thinking",
          requestCompletion,
        },
        policy,
      }),
    ).resolves.toMatchObject({ coverage: { required: 1, completed: 1 } });
    expect(requestCompletion).toHaveBeenCalledTimes(2);
    expect(requestCompletion.mock.calls[0]?.[0].systemContent).not.toContain(
      "assessment_layman_explanation",
    );
    expect(requestCompletion.mock.calls[1]?.[0].systemContent).toContain(
      "assessment_layman_explanation",
    );
    expect(requestCompletion.mock.calls[1]?.[0].systemContent).not.toContain(
      "This repository is safe.",
    );
  });

  test("retries malformed JSON immediately and then accepts complete coverage", async () => {
    const current = group("src/a.ts", [ids[0]!]);
    const requestCompletion = vi.fn(async () => ({
      completionId: `completion-${requestCompletion.mock.calls.length}`,
      endpointOrigin: "https://provider.example",
      provider: "provider.example",
      content:
        requestCompletion.mock.calls.length === 1
          ? "not usable JSON"
          : reviewContent({
              status: "complete",
              assessments: [assessment(ids[0]!, current.path, 2)],
              observations: [],
            }),
      usage: {
        inputTokens: 100,
        outputTokens: 40,
        cacheReadTokens: 0,
        reasoningTokens: 10,
      },
    }));

    const result = await reviewEvidenceGroups({
      groups: [current],
      provider: {
        endpoint: "https://provider.example/v1/chat/completions",
        apiKey: "test-key",
        model: "configured/model:thinking",
        requestCompletion,
      },
      policy,
    });

    expect(requestCompletion).toHaveBeenCalledTimes(2);
    expect(result.coverage).toEqual({ required: 1, completed: 1 });
  });

  test("classifies a schema-invalid assessment without exposing model text", async () => {
    const current = group("src/a.ts", [ids[0]!]);
    const requestCompletion = vi.fn(async () => ({
      completionId: `completion-invalid-${requestCompletion.mock.calls.length}`,
      endpointOrigin: "https://provider.example",
      provider: "provider.example",
      content: reviewContent({
        status: "complete",
        assessments: [
          {
            ...assessment(ids[0]!, current.path, 2),
            developer_action: "",
          },
        ],
        observations: [],
      }),
      usage: {
        inputTokens: 100,
        outputTokens: 40,
        cacheReadTokens: 0,
        reasoningTokens: 10,
      },
    }));

    await expect(
      reviewEvidenceGroups({
        groups: [current],
        provider: {
          endpoint: "https://provider.example/v1/chat/completions",
          apiKey: "test-key",
          model: "configured/model:thinking",
          requestCompletion,
        },
        policy: { ...policy, maxImmediateAttempts: 1 },
      }),
    ).rejects.toMatchObject({
      code: "MODEL_INVALID_RESPONSE",
      scope: "repository",
      diagnostic: "assessment_developer_action",
    });
  });

  test("repairs an omitted exposure field with precise guidance", async () => {
    const current = group("src/a.ts", [ids[0]!]);
    const requestCompletion = vi.fn(async (_request: TextCompletionRequest) => {
      const complete = assessment(ids[0]!, current.path, 2);
      const { risk_exposure: _riskExposure, ...missingExposure } = complete;
      return {
        completionId: `completion-exposure-${requestCompletion.mock.calls.length}`,
        endpointOrigin: "https://provider.example",
        provider: "provider.example",
        content: reviewContent({
          status: "complete",
          assessments: [
            requestCompletion.mock.calls.length === 1
              ? missingExposure
              : complete,
          ],
          observations: [],
        }),
        usage: {
          inputTokens: 100,
          outputTokens: 40,
          cacheReadTokens: 0,
          reasoningTokens: 10,
        },
      } satisfies ModelCompletionResult;
    });

    await expect(
      reviewEvidenceGroups({
        groups: [current],
        provider: {
          endpoint: "https://provider.example/v1/chat/completions",
          apiKey: "test-key",
          model: "configured/model:thinking",
          requestCompletion,
        },
        policy,
      }),
    ).resolves.toMatchObject({ coverage: { required: 1, completed: 1 } });
    expect(requestCompletion).toHaveBeenCalledTimes(2);
    expect(requestCompletion.mock.calls[1]?.[0].systemContent).toContain(
      "assessment_risk_exposure",
    );
  });

  test("repairs demonstrated assessment exposure for metadata-only evidence", async () => {
    const current = {
      ...group("dist/bundle.js", [ids[0]!]),
      source_kind: "metadata-only" as const,
    };
    const requestCompletion = vi.fn(
      async (_request: TextCompletionRequest) => ({
        completionId: `completion-metadata-assessment-${requestCompletion.mock.calls.length}`,
        endpointOrigin: "https://provider.example",
        provider: "provider.example",
        content: reviewContent({
          status: "complete",
          assessments: [
            {
              ...assessment(ids[0]!, current.path, 2),
              risk_exposure:
                requestCompletion.mock.calls.length === 1
                  ? "demonstrated"
                  : "not_demonstrated",
            },
          ],
          observations: [],
        }),
        usage: {
          inputTokens: 100,
          outputTokens: 40,
          cacheReadTokens: 0,
          reasoningTokens: 10,
        },
      }),
    );

    await expect(
      reviewEvidenceGroups({
        groups: [current],
        provider: {
          endpoint: "https://provider.example/v1/chat/completions",
          apiKey: "test-key",
          model: "configured/model:thinking",
          requestCompletion,
        },
        policy,
      }),
    ).resolves.toMatchObject({ coverage: { required: 1, completed: 1 } });
    expect(requestCompletion).toHaveBeenCalledTimes(2);
    expect(requestCompletion.mock.calls[1]?.[0].systemContent).toContain(
      "assessment_risk_exposure",
    );
  });

  test("repairs demonstrated observation exposure for metadata-only evidence", async () => {
    const current = {
      ...group("dist/bundle.js", [ids[0]!]),
      source_kind: "metadata-only" as const,
    };
    const requestCompletion = vi.fn(
      async (_request: TextCompletionRequest) => ({
        completionId: `completion-metadata-observation-${requestCompletion.mock.calls.length}`,
        endpointOrigin: "https://provider.example",
        provider: "provider.example",
        content: reviewContent({
          status: "complete",
          assessments: [assessment(ids[0]!, current.path, 2)],
          observations: [
            {
              related_candidate_ids: [ids[0]!],
              evidence_ids: [ids[0]!],
              disposition: "minor_weakness",
              impact: "low",
              exploitability: "unlikely",
              confidence: "medium",
              risk_exposure:
                requestCompletion.mock.calls.length === 1
                  ? "demonstrated"
                  : "not_demonstrated",
              recommended_risk: "low",
              title: "Metadata-only observation",
              technical_explanation:
                "The metadata cannot establish a concrete activation path.",
              layman_explanation:
                "The available metadata does not show this behavior running.",
              developer_action: "Inspect the executable artifact contents.",
              locations: [{ path: current.path, line_start: 2, line_end: 2 }],
            },
          ],
        }),
        usage: {
          inputTokens: 100,
          outputTokens: 40,
          cacheReadTokens: 0,
          reasoningTokens: 10,
        },
      }),
    );

    await expect(
      reviewEvidenceGroups({
        groups: [current],
        provider: {
          endpoint: "https://provider.example/v1/chat/completions",
          apiKey: "test-key",
          model: "configured/model:thinking",
          requestCompletion,
        },
        policy,
      }),
    ).resolves.toMatchObject({ coverage: { required: 1, completed: 1 } });
    expect(requestCompletion).toHaveBeenCalledTimes(2);
    expect(requestCompletion.mock.calls[1]?.[0].systemContent).toContain(
      "observation_risk_exposure",
    );
  });

  test("uses every configured attempt when corrective feedback repeats", async () => {
    const current = group("src/a.ts", [ids[0]!]);
    const requestCompletion = vi.fn(async () => ({
      completionId: `completion-repeat-${requestCompletion.mock.calls.length}`,
      endpointOrigin: "https://provider.example",
      provider: "provider.example",
      content: reviewContent({
        status: "complete",
        assessments: [
          {
            ...assessment(ids[0]!, current.path, 2),
            developer_action: "",
          },
        ],
        observations: [],
      }),
      usage: {
        inputTokens: 100,
        outputTokens: 40,
        cacheReadTokens: 0,
        reasoningTokens: 10,
      },
    }));

    await expect(
      reviewEvidenceGroups({
        groups: [current],
        provider: {
          endpoint: "https://provider.example/v1/chat/completions",
          apiKey: "test-key",
          model: "configured/model:thinking",
          requestCompletion,
        },
        policy,
      }),
    ).rejects.toMatchObject({
      code: "MODEL_INVALID_RESPONSE",
      diagnostic: "assessment_developer_action",
    });
    expect(requestCompletion).toHaveBeenCalledTimes(3);
  });

  test("resumes a completed group prefix after a transient provider failure", async () => {
    const groups = [group("src/a.ts", [ids[0]!]), group("src/b.ts", [ids[1]!])];
    let progress: ContextualReviewProgress | undefined;
    const firstRequest = vi.fn(async (request: TextCompletionRequest) => {
      const current = groups.find((item) =>
        request.userContent.includes(item.group_id),
      )!;
      if (current === groups[1])
        throw new ModelRequestError(
          "MODEL_PROVIDER",
          "system",
          "Provider temporarily unavailable.",
        );
      return {
        completionId: "completion-first-group",
        endpointOrigin: "https://provider.example",
        provider: "provider.example",
        content: reviewContent({
          status: "complete",
          assessments: [assessment(ids[0]!, current.path, 2)],
          observations: [
            {
              related_candidate_ids: [ids[0]!],
              evidence_ids: [ids[0]!],
              disposition: "minor_weakness",
              impact: "low",
              exploitability: "unlikely",
              confidence: "medium",
              risk_exposure: "not_demonstrated",
              recommended_risk: "low",
              title: "Destination validation",
              technical_explanation:
                "The destination deserves an explicit validation boundary.",
              layman_explanation: "The destination should be checked.",
              developer_action: "Validate the destination before use.",
              locations: [{ path: current.path, line_start: 2, line_end: 2 }],
            },
          ],
        }),
        usage: {
          inputTokens: 100,
          outputTokens: 40,
          cacheReadTokens: 0,
          reasoningTokens: 10,
        },
      } satisfies ModelCompletionResult;
    });

    await expect(
      reviewEvidenceGroups({
        groups,
        provider: {
          endpoint: "https://provider.example/v1/chat/completions",
          apiKey: "test-key",
          model: "configured/model:thinking",
          requestCompletion: firstRequest,
        },
        policy,
        onProgress: async (value) => {
          progress = structuredClone(value);
        },
      }),
    ).rejects.toMatchObject({ code: "MODEL_PROVIDER" });
    expect(progress?.completed_group_ids).toEqual([groups[0]!.group_id]);
    const serializedProgress = JSON.stringify(progress);
    expect(serializedProgress).not.toContain(groups[0]!.path);
    expect(serializedProgress).not.toMatch(/"path":/u);
    expect(progress?.assessments[0]).not.toHaveProperty("locations");
    expect(progress?.observations[0]?.locations).toEqual([
      { line_start: 2, line_end: 2 },
    ]);

    const resumedRequest = vi.fn(async () => ({
      completionId: "completion-second-group",
      endpointOrigin: "https://provider.example",
      provider: "provider.example",
      content: reviewContent({
        status: "complete",
        assessments: [assessment(ids[1]!, groups[1]!.path, 2)],
        observations: [],
      }),
      usage: {
        inputTokens: 80,
        outputTokens: 30,
        cacheReadTokens: 0,
        reasoningTokens: 5,
      },
    }));
    const result = await reviewEvidenceGroups({
      groups,
      provider: {
        endpoint: "https://provider.example/v1/chat/completions",
        apiKey: "test-key",
        model: "configured/model:thinking",
        requestCompletion: resumedRequest,
      },
      policy,
      progress,
    });

    expect(resumedRequest).toHaveBeenCalledTimes(1);
    expect(result.assessments.map(({ candidate_id }) => candidate_id)).toEqual([
      ids[0],
      ids[1],
    ]);
    expect(result.observations[0]?.locations).toEqual([
      { path: groups[0]!.path, line_start: 2, line_end: 2 },
    ]);
    expect(result.usage).toEqual({
      inputTokens: 180,
      outputTokens: 70,
      cacheReadTokens: 0,
      reasoningTokens: 15,
    });
  });

  test("redacts every known repository path without retrying short filenames", async () => {
    const groups = [group("a", [ids[0]!]), group("src/b.ts", [ids[1]!])];
    const progress: ContextualReviewProgress[] = [];
    const requestCompletion = vi.fn(async (request: TextCompletionRequest) => {
      const current = groups.find((item) =>
        request.userContent.includes(item.group_id),
      )!;
      const reviewed = assessment(
        current.candidates[0]!.candidate_id,
        current.path,
        2,
      );
      return {
        completionId: `completion-${progress.length + 1}`,
        endpointOrigin: "https://provider.example",
        provider: "provider.example",
        content: reviewContent({
          status: "complete",
          assessments: [
            {
              ...reviewed,
              technical_explanation:
                current === groups[0]
                  ? "The issue is in src/b.ts and not inside data."
                  : reviewed.technical_explanation,
            },
          ],
          observations: [],
        }),
        usage: {
          inputTokens: 80,
          outputTokens: 30,
          cacheReadTokens: 0,
          reasoningTokens: 5,
        },
      } satisfies ModelCompletionResult;
    });

    const result = await reviewEvidenceGroups({
      groups,
      provider: {
        endpoint: "https://provider.example/v1/chat/completions",
        apiKey: "test-key",
        model: "configured/model:thinking",
        requestCompletion,
      },
      policy,
      onProgress: async (value) => {
        progress.push(structuredClone(value));
      },
    });

    expect(requestCompletion).toHaveBeenCalledTimes(2);
    expect(result.assessments[0]?.technical_explanation).toBe(
      "The issue is in file and not inside data.",
    );
    expect(JSON.stringify(progress)).not.toContain("src/b.ts");
    expect(JSON.stringify(progress)).not.toMatch(/"path":/u);
  });

  test("rejects progress that is not the exact completed group prefix", async () => {
    const groups = [group("src/a.ts", [ids[0]!]), group("src/b.ts", [ids[1]!])];
    const invalidProgress: ContextualReviewProgress = {
      policy_version: "5",
      prompt_version: "contextual-review-v7",
      schema_version: "contextual-assessment-v2",
      model: "configured/model:thinking",
      provider: "provider.example",
      endpoint_origin: "https://provider.example",
      completed_group_ids: [groups[1]!.group_id],
      assessments: [
        {
          ...assessment(ids[1]!, groups[1]!.path, 2),
          evidence_ids: [ids[1]!],
        },
      ],
      observations: [],
      usage: {
        inputTokens: 100,
        outputTokens: 40,
        cacheReadTokens: 0,
        reasoningTokens: 10,
      },
      completion_ids: ["completion-second-group"],
    };

    await expect(
      reviewEvidenceGroups({
        groups,
        provider: {
          endpoint: "https://provider.example/v1/chat/completions",
          apiKey: "test-key",
          model: "configured/model:thinking",
          requestCompletion: vi.fn(),
        },
        policy,
        progress: invalidProgress,
      }),
    ).rejects.toMatchObject({
      code: "MODEL_EVIDENCE_INVALID",
      scope: "repository",
    });
  });

  test("clears corrective feedback after a valid context request", async () => {
    const current = group("src/a.ts", [ids[0]!]);
    const requestCompletion = vi.fn(async (_request: TextCompletionRequest) => {
      const call = requestCompletion.mock.calls.length;
      return {
        completionId: `completion-repair-context-${call}`,
        endpointOrigin: "https://provider.example",
        provider: "provider.example",
        content: reviewContent(
          call === 1
            ? {
                status: "complete",
                assessments: [
                  {
                    ...assessment(ids[0]!, current.path, 2),
                    layman_explanation: "This repository is safe.",
                  },
                ],
                observations: [],
              }
            : call === 2
              ? {
                  status: "needs_more_context",
                  candidate_ids: [ids[0]!],
                  requested_context: "Include destination configuration.",
                }
              : {
                  status: "complete",
                  assessments: [assessment(ids[0]!, current.path, 2)],
                  observations: [],
                },
        ),
        usage: {
          inputTokens: 100,
          outputTokens: 40,
          cacheReadTokens: 0,
          reasoningTokens: 10,
        },
      } satisfies ModelCompletionResult;
    });
    const expandContext = vi.fn(async (evidence: EvidenceContextGroup) => ({
      ...evidence,
      context: {
        ...evidence.context,
        source: `${evidence.context.source}\n     4 | const endpoint = configuredEndpoint;`,
      },
    }));

    await expect(
      reviewEvidenceGroups({
        groups: [current],
        provider: {
          endpoint: "https://provider.example/v1/chat/completions",
          apiKey: "test-key",
          model: "configured/model:thinking",
          requestCompletion,
        },
        policy,
        expandContext,
      }),
    ).resolves.toMatchObject({ coverage: { required: 1, completed: 1 } });
    expect(requestCompletion.mock.calls[1]?.[0].systemContent).toContain(
      "assessment_layman_explanation",
    );
    expect(requestCompletion.mock.calls[2]?.[0].systemContent).not.toContain(
      "assessment_layman_explanation",
    );
    expect(
      JSON.stringify(
        requestCompletion.mock.calls[1]?.[0].responseJsonSchema?.schema,
      ),
    ).toContain("needs_more_context");
    expect(
      JSON.stringify(
        requestCompletion.mock.calls[2]?.[0].responseJsonSchema?.schema,
      ),
    ).not.toContain("needs_more_context");
    expect(requestCompletion.mock.calls[1]?.[0].systemContent).not.toContain(
      "needs_more_context is not permitted",
    );
    expect(requestCompletion.mock.calls[2]?.[0].systemContent).toContain(
      "needs_more_context is not permitted",
    );
  });

  test("expands requested context instead of treating uncertainty as low risk", async () => {
    const current = group("src/a.ts", [ids[0]!]);
    const requestCompletion = vi.fn(async () => ({
      completionId: `completion-${requestCompletion.mock.calls.length}`,
      endpointOrigin: "https://provider.example",
      provider: "provider.example",
      content: batchContent([
        {
          group_id: current.group_id,
          review:
            requestCompletion.mock.calls.length === 1
              ? {
                  status: "needs_more_context",
                  candidate_ids: [ids[0]!],
                  requested_context: "Include the destination configuration.",
                }
              : {
                  status: "complete",
                  assessments: [assessment(ids[0]!, current.path, 2)],
                  observations: [],
                },
        },
      ]),
      usage: {
        inputTokens: 100,
        outputTokens: 40,
        cacheReadTokens: 0,
        reasoningTokens: 10,
      },
    }));
    const expandContext = vi.fn(async (evidence: EvidenceContextGroup) => ({
      ...evidence,
      context: {
        ...evidence.context,
        source: `${evidence.context.source}\n     4 | const endpoint = configuredEndpoint;`,
      },
    }));

    const result = await reviewEvidenceGroups({
      groups: [current],
      provider: {
        endpoint: "https://provider.example/v1/chat/completions",
        apiKey: "test-key",
        model: "configured/model:thinking",
        requestCompletion,
      },
      policy: {
        ...policy,
        maxBatchGroups: 5,
        maxBatchInputTokens: 1_000_000,
      },
      expandContext,
    });

    expect(requestCompletion).toHaveBeenCalledTimes(2);
    expect(expandContext).toHaveBeenCalledOnce();
    expect(result.assessments[0]?.recommended_risk).toBe("low");
    expect(result.review_batches?.map(({ attempt }) => attempt)).toEqual([
      1, 2,
    ]);
  });

  test("refuses a response that omits a supplied candidate", async () => {
    const current = group("src/a.ts", ids.slice(0, 2));
    const requestCompletion = vi.fn(
      async (_request: TextCompletionRequest) => ({
        completionId: "completion-incomplete",
        endpointOrigin: "https://provider.example",
        provider: "provider.example",
        content: reviewContent({
          status: "complete",
          assessments: [assessment(ids[0]!, current.path, 2)],
          observations: [],
        }),
        usage: {
          inputTokens: 100,
          outputTokens: 40,
          cacheReadTokens: 0,
          reasoningTokens: 10,
        },
      }),
    );

    await expect(
      reviewEvidenceGroups({
        groups: [current],
        provider: {
          endpoint: "https://provider.example/v1/chat/completions",
          apiKey: "test-key",
          model: "configured/model:thinking",
          requestCompletion,
        },
        policy,
      }),
    ).rejects.toMatchObject({
      code: "MODEL_EVIDENCE_INVALID",
      scope: "repository",
    });
    expect(requestCompletion).toHaveBeenCalledTimes(3);
    expect(requestCompletion.mock.calls[1]?.[0].systemContent).toContain(
      "assessment_candidate_id",
    );
  });

  test("repairs duplicate assessment candidate IDs with precise guidance", async () => {
    const current = group("src/a.ts", ids.slice(0, 2));
    const requestCompletion = vi.fn(
      async (_request: TextCompletionRequest) => ({
        completionId: "completion-duplicate-candidate",
        endpointOrigin: "https://provider.example",
        provider: "provider.example",
        content: reviewContent({
          status: "complete",
          assessments: [
            assessment(ids[0]!, current.path, 2),
            assessment(ids[0]!, current.path, 2),
          ],
          observations: [],
        }),
        usage: {
          inputTokens: 100,
          outputTokens: 40,
          cacheReadTokens: 0,
          reasoningTokens: 10,
        },
      }),
    );

    await expect(
      reviewEvidenceGroups({
        groups: [current],
        provider: {
          endpoint: "https://provider.example/v1/chat/completions",
          apiKey: "test-key",
          model: "configured/model:thinking",
          requestCompletion,
        },
        policy,
      }),
    ).rejects.toMatchObject({ code: "MODEL_INVALID_RESPONSE" });
    expect(requestCompletion).toHaveBeenCalledTimes(3);
    expect(requestCompletion.mock.calls[1]?.[0].systemContent).toContain(
      "assessment_candidate_id",
    );
  });

  test("refuses invented evidence", async () => {
    const current = group("src/a.ts", [ids[0]!]);
    const invented = {
      ...assessment(ids[0]!, current.path, 2),
      evidence_ids: ["f".repeat(64)],
    };
    const requestCompletion = vi.fn(
      async (_request: TextCompletionRequest) => ({
        completionId: "completion-invented",
        endpointOrigin: "https://provider.example",
        provider: "provider.example",
        content: reviewContent({
          status: "complete",
          assessments: [invented],
          observations: [],
        }),
        usage: {
          inputTokens: 100,
          outputTokens: 40,
          cacheReadTokens: 0,
          reasoningTokens: 10,
        },
      }),
    );

    await expect(
      reviewEvidenceGroups({
        groups: [current],
        provider: {
          endpoint: "https://provider.example/v1/chat/completions",
          apiKey: "test-key",
          model: "configured/model:thinking",
          requestCompletion,
        },
        policy,
      }),
    ).rejects.toMatchObject({ code: "MODEL_EVIDENCE_INVALID" });
    expect(requestCompletion.mock.calls[1]?.[0].systemContent).toContain(
      "assessment_evidence_ids",
    );
  });

  test("refuses invented observation locations", async () => {
    const current = group("src/a.ts", [ids[0]!]);
    const requestCompletion = vi.fn(
      async (_request: TextCompletionRequest) => ({
        completionId: "completion-invented-observation",
        endpointOrigin: "https://provider.example",
        provider: "provider.example",
        content: reviewContent({
          status: "complete",
          assessments: [assessment(ids[0]!, current.path, 2)],
          observations: [
            {
              related_candidate_ids: [ids[0]!],
              evidence_ids: [ids[0]!],
              disposition: "minor_weakness",
              impact: "low",
              exploitability: "unlikely",
              confidence: "medium",
              risk_exposure: "not_demonstrated",
              recommended_risk: "low",
              title: "Invented location",
              technical_explanation: "The location was not supplied.",
              layman_explanation: "This location cannot be trusted.",
              developer_action: "none",
              locations: [{ path: current.path, line_start: 99, line_end: 99 }],
            },
          ],
        }),
        usage: {
          inputTokens: 100,
          outputTokens: 40,
          cacheReadTokens: 0,
          reasoningTokens: 10,
        },
      }),
    );

    await expect(
      reviewEvidenceGroups({
        groups: [current],
        provider: {
          endpoint: "https://provider.example/v1/chat/completions",
          apiKey: "test-key",
          model: "configured/model:thinking",
          requestCompletion,
        },
        policy: { ...policy, maxImmediateAttempts: 2 },
      }),
    ).rejects.toMatchObject({
      code: "MODEL_EVIDENCE_INVALID",
      diagnostic: "observation_locations",
    });
    expect(requestCompletion.mock.calls[1]?.[0].systemContent).toContain(
      "observation_locations",
    );
  });

  test("uses one Luna binding patch only after DeepSeek exhausts evidence repair", async () => {
    const current = group("src/a.ts", [ids[0]!]);
    let primaryCalls = 0;
    const requestCompletion = vi.fn(async () => {
      primaryCalls += 1;
      return {
        completionId: `completion-primary-${primaryCalls}`,
        endpointOrigin: "https://provider.example",
        provider: "provider.example",
        content: batchContent([
          {
            group_id: current.group_id,
            review: {
              status: "complete",
              assessments: [assessment(ids[0]!, current.path, 2)],
              observations: [
                {
                  related_candidate_ids: [ids[0]!],
                  evidence_ids: [ids[0]!],
                  disposition: "minor_weakness",
                  impact: "low",
                  exploitability: "unlikely",
                  confidence: "medium",
                  risk_exposure: "not_demonstrated",
                  recommended_risk: "low",
                  title: "Bounded observation",
                  technical_explanation: "The behavior should remain bounded.",
                  layman_explanation: "This deserves a small caution.",
                  developer_action: "Document the intended boundary.",
                  locations: [
                    { path: current.path, line_start: 99, line_end: 99 },
                  ],
                },
              ],
            },
          },
        ]),
        usage: {
          inputTokens: 100,
          outputTokens: 40,
          cacheReadTokens: 0,
          reasoningTokens: 10,
        },
      } satisfies ModelCompletionResult;
    });
    const requestRepair = vi.fn(async () => ({
      completionId: "completion-luna-repair",
      endpointOrigin: "https://api.openai.com",
      provider: "api.openai.com",
      content: JSON.stringify({
        repair: {
          assessment_evidence_ids: [],
          observations: [
            {
              index: 0,
              action: "drop",
            },
          ],
        },
      }),
      usage: {
        inputTokens: 25,
        outputTokens: 10,
        cacheReadTokens: 0,
        reasoningTokens: 0,
      },
    }));

    const result = await reviewEvidenceGroups({
      groups: [current],
      provider: {
        endpoint: "https://provider.example/v1/chat/completions",
        apiKey: "test-key",
        model: "deepseek-v4-flash",
        requestCompletion,
      },
      jsonRepairProvider: {
        endpoint: "https://api.openai.com/v1/chat/completions",
        apiKey: "repair-key",
        model: "gpt-5.6-luna",
        requestCompletion: requestRepair,
      },
      policy: {
        ...policy,
        maxBatchGroups: 5,
        maxBatchInputTokens: 1_000_000,
      },
    });

    expect(primaryCalls).toBe(3);
    expect(requestRepair).toHaveBeenCalledOnce();
    expect(result.model).toBe("deepseek-v4-flash");
    expect(result.observations).toEqual([]);
    expect(result.usage).toEqual({
      inputTokens: 325,
      outputTokens: 130,
      cacheReadTokens: 0,
      reasoningTokens: 30,
    });
    expect(result.completion_ids).toEqual([
      "completion-primary-1",
      "completion-primary-2",
      "completion-primary-3",
      "jsonrepair:completion-luna-repair",
    ]);
    expect(result.review_batches?.map(({ kind }) => kind)).toEqual([
      "contextual_review",
      "contextual_review",
      "contextual_review",
      "json_repair",
    ]);

    primaryCalls = 0;
    requestCompletion.mockClear();
    requestRepair.mockClear();
    await expect(
      reviewEvidenceGroups({
        groups: [current],
        provider: {
          endpoint: "https://provider.example/v1/chat/completions",
          apiKey: "test-key",
          model: "deepseek-v4-flash",
          requestCompletion,
        },
        jsonRepairProvider: {
          endpoint: "https://api.openai.com/v1/chat/completions",
          apiKey: "repair-key",
          model: "gpt-5.6-luna",
          requestCompletion: requestRepair,
        },
        policy: {
          ...policy,
          maxBatchGroups: 5,
          maxBatchInputTokens: 1_000_000,
          maxProviderCalls: 3,
        },
      }),
    ).rejects.toMatchObject({ code: "MODEL_REVIEW_BUDGET_EXCEEDED" });
    expect(primaryCalls).toBe(3);
    expect(requestRepair).not.toHaveBeenCalled();
  });

  test("does not send malformed or semantically invalid output to Luna", async () => {
    const current = group("src/a.ts", [ids[0]!]);
    const requestRepair = vi.fn();
    const malformedPrimary = vi.fn(async () => ({
      completionId: `malformed-${malformedPrimary.mock.calls.length}`,
      endpointOrigin: "https://provider.example",
      provider: "provider.example",
      content: "not-json",
      usage: {
        inputTokens: 10,
        outputTokens: 2,
        cacheReadTokens: 0,
        reasoningTokens: 0,
      },
    }));

    await expect(
      reviewEvidenceGroups({
        groups: [current],
        provider: {
          endpoint: "https://provider.example/v1/chat/completions",
          apiKey: "test-key",
          model: "deepseek-v4-flash",
          requestCompletion: malformedPrimary,
        },
        jsonRepairProvider: {
          endpoint: "https://api.openai.com/v1/chat/completions",
          apiKey: "repair-key",
          model: "gpt-5.6-luna",
          requestCompletion: requestRepair,
        },
        policy,
      }),
    ).rejects.toMatchObject({ code: "MODEL_INVALID_RESPONSE" });
    expect(requestRepair).not.toHaveBeenCalled();

    const metadata = { ...current, source_kind: "metadata-only" as const };
    const semanticPrimary = vi.fn(async () => ({
      completionId: `semantic-${semanticPrimary.mock.calls.length}`,
      endpointOrigin: "https://provider.example",
      provider: "provider.example",
      content: reviewContent({
        status: "complete",
        assessments: [
          {
            ...assessment(ids[0]!, current.path, 2),
            risk_exposure: "demonstrated",
            disposition: "material_vulnerability",
            impact: "medium",
            exploitability: "plausible",
            confidence: "high",
            recommended_risk: "material",
          },
        ],
        observations: [],
      }),
      usage: {
        inputTokens: 10,
        outputTokens: 2,
        cacheReadTokens: 0,
        reasoningTokens: 0,
      },
    }));
    await expect(
      reviewEvidenceGroups({
        groups: [metadata],
        provider: {
          endpoint: "https://provider.example/v1/chat/completions",
          apiKey: "test-key",
          model: "deepseek-v4-flash",
          requestCompletion: semanticPrimary,
        },
        jsonRepairProvider: {
          endpoint: "https://api.openai.com/v1/chat/completions",
          apiKey: "repair-key",
          model: "gpt-5.6-luna",
          requestCompletion: requestRepair,
        },
        policy,
      }),
    ).rejects.toMatchObject({
      code: "MODEL_EVIDENCE_INVALID",
      diagnostic: "assessment_risk_exposure",
    });
    expect(requestRepair).not.toHaveBeenCalled();
  });

  test("preserves the final DeepSeek failure when Luna repair fails", async () => {
    const current = group("src/a.ts", [ids[0]!]);
    const requestCompletion = vi.fn(async () => ({
      completionId: "completion-primary-invalid-location",
      endpointOrigin: "https://provider.example",
      provider: "provider.example",
      content: reviewContent({
        status: "complete",
        assessments: [assessment(ids[0]!, current.path, 2)],
        observations: [
          {
            related_candidate_ids: [ids[0]!],
            evidence_ids: [ids[0]!],
            disposition: "minor_weakness",
            impact: "low",
            exploitability: "unlikely",
            confidence: "medium",
            risk_exposure: "not_demonstrated",
            recommended_risk: "low",
            title: "Bounded observation",
            technical_explanation: "The behavior should remain bounded.",
            layman_explanation: "This deserves a small caution.",
            developer_action: "Document the intended boundary.",
            locations: [{ path: current.path, line_start: 99, line_end: 99 }],
          },
        ],
      }),
      usage: {
        inputTokens: 100,
        outputTokens: 40,
        cacheReadTokens: 0,
        reasoningTokens: 10,
      },
    }));
    const requestRepair = vi.fn(async () => {
      throw new ModelRequestError(
        "MODEL_PROVIDER",
        "system",
        "Repair provider unavailable.",
      );
    });

    await expect(
      reviewEvidenceGroups({
        groups: [current],
        provider: {
          endpoint: "https://provider.example/v1/chat/completions",
          apiKey: "test-key",
          model: "deepseek-v4-flash",
          requestCompletion,
        },
        jsonRepairProvider: {
          endpoint: "https://api.openai.com/v1/chat/completions",
          apiKey: "repair-key",
          model: "gpt-5.6-luna",
          requestCompletion: requestRepair,
        },
        policy: { ...policy, maxImmediateAttempts: 1 },
      }),
    ).rejects.toMatchObject({
      code: "MODEL_EVIDENCE_INVALID",
      diagnostic: "observation_locations",
    });
    expect(requestRepair).toHaveBeenCalledOnce();
  });

  test("never applies the Luna patch path to a non-DeepSeek reviewer", async () => {
    const current = group("src/a.ts", [ids[0]!]);
    const requestCompletion = vi.fn(async () => ({
      completionId: "completion-other-reviewer",
      endpointOrigin: "https://provider.example",
      provider: "provider.example",
      content: reviewContent({
        status: "complete",
        assessments: [assessment(ids[0]!, current.path, 2)],
        observations: [
          {
            related_candidate_ids: [ids[0]!],
            evidence_ids: [ids[0]!],
            disposition: "minor_weakness",
            impact: "low",
            exploitability: "unlikely",
            confidence: "medium",
            risk_exposure: "not_demonstrated",
            recommended_risk: "low",
            title: "Bounded observation",
            technical_explanation: "The behavior should remain bounded.",
            layman_explanation: "This deserves a small caution.",
            developer_action: "Document the intended boundary.",
            locations: [{ path: current.path, line_start: 99, line_end: 99 }],
          },
        ],
      }),
      usage: {
        inputTokens: 100,
        outputTokens: 40,
        cacheReadTokens: 0,
        reasoningTokens: 10,
      },
    }));
    const requestRepair = vi.fn();

    await expect(
      reviewEvidenceGroups({
        groups: [current],
        provider: {
          endpoint: "https://provider.example/v1/chat/completions",
          apiKey: "test-key",
          model: "some-other-reviewer",
          requestCompletion,
        },
        jsonRepairProvider: {
          endpoint: "https://api.openai.com/v1/chat/completions",
          apiKey: "repair-key",
          model: "gpt-5.6-luna",
          requestCompletion: requestRepair,
        },
        policy: { ...policy, maxImmediateAttempts: 1 },
      }),
    ).rejects.toMatchObject({
      code: "MODEL_EVIDENCE_INVALID",
      diagnostic: "observation_locations",
    });
    expect(requestRepair).not.toHaveBeenCalled();
  });

  test("refuses secret-shaped text in otherwise valid model output", async () => {
    const current = group("src/a.ts", [ids[0]!]);
    const unsafe = {
      ...assessment(ids[0]!, current.path, 2),
      layman_explanation: `The key was sk-nano-${"z".repeat(32)}.`,
    };
    const requestCompletion = vi.fn(async () => ({
      completionId: "completion-secret",
      endpointOrigin: "https://provider.example",
      provider: "provider.example",
      content: reviewContent({
        status: "complete",
        assessments: [unsafe],
        observations: [],
      }),
      usage: {
        inputTokens: 100,
        outputTokens: 40,
        cacheReadTokens: 0,
        reasoningTokens: 10,
      },
    }));

    await expect(
      reviewEvidenceGroups({
        groups: [current],
        provider: {
          endpoint: "https://provider.example/v1/chat/completions",
          apiKey: "test-key",
          model: "configured/model:thinking",
          requestCompletion,
        },
        policy,
      }),
    ).rejects.toMatchObject({ code: "MODEL_EVIDENCE_INVALID" });
  });

  test("refuses secret-shaped narrative hidden behind JSON Unicode escapes", async () => {
    const current = group("src/a.ts", [ids[0]!]);
    const encoded = reviewContent({
      status: "complete",
      assessments: [
        {
          ...assessment(ids[0]!, current.path, 2),
          layman_explanation: `The key was sk-nano-${"z".repeat(32)}.`,
        },
      ],
      observations: [],
    }).replace("sk-", "\\u0073\\u006b\\u002d");
    expect(encoded).not.toContain("sk-");
    const requestCompletion = vi.fn(async () => ({
      completionId: `completion-escaped-secret-${requestCompletion.mock.calls.length}`,
      endpointOrigin: "https://provider.example",
      provider: "provider.example",
      content: encoded,
      usage: {
        inputTokens: 100,
        outputTokens: 40,
        cacheReadTokens: 0,
        reasoningTokens: 10,
      },
    }));

    await expect(
      reviewEvidenceGroups({
        groups: [current],
        provider: {
          endpoint: "https://provider.example/v1/chat/completions",
          apiKey: "test-key",
          model: "configured/model:thinking",
          requestCompletion,
        },
        policy,
      }),
    ).rejects.toMatchObject({ code: "MODEL_EVIDENCE_INVALID" });
  });

  test("refuses generic secret assignments before report finalization", async () => {
    const current = group("src/a.ts", [ids[0]!]);
    const unsafe = {
      ...assessment(ids[0]!, current.path, 2),
      layman_explanation:
        "The fixture contains token: fixturetoken123 for test coverage.",
    };
    const requestCompletion = vi.fn(async () => ({
      completionId: "completion-generic-secret",
      endpointOrigin: "https://provider.example",
      provider: "provider.example",
      content: reviewContent({
        status: "complete",
        assessments: [unsafe],
        observations: [],
      }),
      usage: {
        inputTokens: 100,
        outputTokens: 40,
        cacheReadTokens: 0,
        reasoningTokens: 10,
      },
    }));

    await expect(
      reviewEvidenceGroups({
        groups: [current],
        provider: {
          endpoint: "https://provider.example/v1/chat/completions",
          apiKey: "test-key",
          model: "configured/model:thinking",
          requestCompletion,
        },
        policy: { ...policy, maxImmediateAttempts: 1 },
      }),
    ).rejects.toMatchObject({ code: "MODEL_EVIDENCE_INVALID" });
    expect(requestCompletion).toHaveBeenCalledTimes(1);
  });

  test("propagates quota failures without changing models or retrying", async () => {
    const current = group("src/a.ts", [ids[0]!]);
    const requestCompletion = vi.fn(async (_request: TextCompletionRequest) => {
      throw new ModelRequestError(
        "MODEL_QUOTA",
        "system",
        "Configured model quota is unavailable.",
      );
    });

    await expect(
      reviewEvidenceGroups({
        groups: [current],
        provider: {
          endpoint: "https://provider.example/v1/chat/completions",
          apiKey: "test-key",
          model: "configured/model:thinking",
          requestCompletion,
        },
        policy,
      }),
    ).rejects.toMatchObject({ code: "MODEL_QUOTA", scope: "system" });
    expect(requestCompletion).toHaveBeenCalledOnce();
    expect(requestCompletion.mock.calls[0]?.[0]).toMatchObject({
      model: "configured/model:thinking",
    });
  });

  test("fails a provider identity mismatch without repository retries", async () => {
    const current = group("src/a.ts", [ids[0]!]);
    const requestCompletion = vi.fn(async () => ({
      completionId: "completion-mismatch",
      endpointOrigin: "https://attacker.example",
      provider: "attacker.example",
      content: reviewContent({
        status: "complete",
        assessments: [assessment(ids[0]!, current.path, 2)],
        observations: [],
      }),
      usage: {
        inputTokens: 100,
        outputTokens: 40,
        cacheReadTokens: 0,
        reasoningTokens: 10,
      },
    }));

    await expect(
      reviewEvidenceGroups({
        groups: [current],
        provider: {
          endpoint: "https://provider.example/v1/chat/completions",
          apiKey: "test-key",
          model: "configured/model:thinking",
          requestCompletion,
        },
        policy,
      }),
    ).rejects.toMatchObject({
      code: "MODEL_INVALID_RESPONSE",
      scope: "system",
    });
    expect(requestCompletion).toHaveBeenCalledOnce();
  });

  test("publishes nothing when more context is requested but unavailable", async () => {
    const current = group("src/a.ts", [ids[0]!]);
    const requestCompletion = vi.fn(async () => ({
      completionId: "completion-context-required",
      endpointOrigin: "https://provider.example",
      provider: "provider.example",
      content: reviewContent({
        status: "needs_more_context",
        candidate_ids: [ids[0]!],
        requested_context: "Include the destination configuration.",
      }),
      usage: {
        inputTokens: 100,
        outputTokens: 40,
        cacheReadTokens: 0,
        reasoningTokens: 10,
      },
    }));

    await expect(
      reviewEvidenceGroups({
        groups: [current],
        provider: {
          endpoint: "https://provider.example/v1/chat/completions",
          apiKey: "test-key",
          model: "configured/model:thinking",
          requestCompletion,
        },
        policy,
      }),
    ).rejects.toMatchObject({
      code: "MODEL_CONTEXT_INCOMPLETE",
      scope: "repository",
    });
    expect(requestCompletion).toHaveBeenCalledOnce();
  });

  test("fails cleanly when expanded context remains unresolved", async () => {
    const current = group("src/a.ts", [ids[0]!]);
    const requestCompletion = vi.fn(async () => ({
      completionId: `completion-unresolved-${requestCompletion.mock.calls.length}`,
      endpointOrigin: "https://provider.example",
      provider: "provider.example",
      content: reviewContent({
        status: "needs_more_context",
        candidate_ids: [ids[0]!],
        requested_context: "More context is still required.",
      }),
      usage: {
        inputTokens: 100,
        outputTokens: 40,
        cacheReadTokens: 0,
        reasoningTokens: 10,
      },
    }));
    const expandContext = vi.fn(async (evidence: EvidenceContextGroup) =>
      Promise.resolve(evidence),
    );

    await expect(
      reviewEvidenceGroups({
        groups: [current],
        provider: {
          endpoint: "https://provider.example/v1/chat/completions",
          apiKey: "test-key",
          model: "configured/model:thinking",
          requestCompletion,
        },
        policy,
        expandContext,
      }),
    ).rejects.toMatchObject({ code: "MODEL_CONTEXT_INCOMPLETE" });
    expect(requestCompletion).toHaveBeenCalledTimes(3);
    expect(expandContext).toHaveBeenCalledTimes(2);
  });

  test("assigns a stable identity to a supported contextual observation", async () => {
    const current = group("src/a.ts", [ids[0]!]);
    const requestCompletion = vi.fn(async () => ({
      completionId: "completion-observation",
      endpointOrigin: "https://provider.example",
      provider: "provider.example",
      content: reviewContent({
        status: "complete",
        assessments: [assessment(ids[0]!, current.path, 2)],
        observations: [
          {
            related_candidate_ids: [ids[0]!],
            evidence_ids: [ids[0]!],
            disposition: "minor_weakness",
            impact: "low",
            exploitability: "unlikely",
            confidence: "medium",
            risk_exposure: "not_demonstrated",
            recommended_risk: "low",
            title: "Endpoint validation could be clearer",
            technical_explanation:
              "The configured endpoint is used without a visible allowlist.",
            layman_explanation:
              "A mistaken endpoint could send a request to the wrong service.",
            developer_action: "Document and validate the configured endpoint.",
            locations: [{ path: current.path, line_start: 2, line_end: 2 }],
          },
        ],
      }),
      usage: {
        inputTokens: 100,
        outputTokens: 40,
        cacheReadTokens: 0,
        reasoningTokens: 10,
      },
    }));

    const result = await reviewEvidenceGroups({
      groups: [current],
      provider: {
        endpoint: "https://provider.example/v1/chat/completions",
        apiKey: "test-key",
        model: "configured/model:thinking",
        requestCompletion,
      },
      policy,
    });

    expect(result.observations).toEqual([
      expect.objectContaining({
        observation_id: expect.stringMatching(/^[a-f0-9]{64}$/u),
      }),
    ]);
  });

  test("binds observation identity to risk exposure", async () => {
    const current = group("src/a.ts", [ids[0]!]);
    const reviewWithExposure = async (
      riskExposure: "not_demonstrated" | "demonstrated",
    ) =>
      reviewEvidenceGroups({
        groups: [current],
        provider: {
          endpoint: "https://provider.example/v1/chat/completions",
          apiKey: "test-key",
          model: "configured/model:thinking",
          requestCompletion: async () => ({
            completionId: `completion-observation-${riskExposure}`,
            endpointOrigin: "https://provider.example",
            provider: "provider.example",
            content: reviewContent({
              status: "complete",
              assessments: [assessment(ids[0]!, current.path, 2)],
              observations: [
                {
                  related_candidate_ids: [ids[0]!],
                  evidence_ids: [ids[0]!],
                  disposition: "minor_weakness",
                  impact: "low",
                  exploitability: "unlikely",
                  confidence: "medium",
                  risk_exposure: riskExposure,
                  recommended_risk: "low",
                  title: "Endpoint validation could be clearer",
                  technical_explanation:
                    "The configured endpoint is used without a visible allowlist.",
                  layman_explanation:
                    "A mistaken endpoint could send a request to the wrong service.",
                  developer_action:
                    "Document and validate the configured endpoint.",
                  locations: [
                    { path: current.path, line_start: 2, line_end: 2 },
                  ],
                },
              ],
            }),
            usage: {
              inputTokens: 100,
              outputTokens: 40,
              cacheReadTokens: 0,
              reasoningTokens: 10,
            },
          }),
        },
        policy,
      });

    const [notDemonstrated, demonstrated] = await Promise.all([
      reviewWithExposure("not_demonstrated"),
      reviewWithExposure("demonstrated"),
    ]);

    expect(notDemonstrated.observations[0]?.observation_id).not.toBe(
      demonstrated.observations[0]?.observation_id,
    );
  });
});
