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
  version: "2",
  promptVersion: "contextual-review-v3",
  schemaVersion: "contextual-assessment-v1",
  maxImmediateAttempts: 3,
  maxOutputTokens: 8_192,
  maxResponseBytes: 5_000_000,
  timeoutMs: 600_000,
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
    target_sha: "d".repeat(40),
    evidence_sha: "d".repeat(40),
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
    recommended_risk: "low",
    technical_explanation: "The request matches the documented model helper.",
    layman_explanation: "This request appears to be expected.",
    developer_action: "none",
  } as const;
}

function reviewContent(review: unknown) {
  return JSON.stringify({ review });
}

describe("contextual evidence review", () => {
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
      policy_version: "2",
      prompt_version: "contextual-review-v3",
      schema_version: "contextual-assessment-v1",
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
  });

  test("expands requested context instead of treating uncertainty as low risk", async () => {
    const current = group("src/a.ts", [ids[0]!]);
    const requestCompletion = vi.fn(async () => ({
      completionId: `completion-${requestCompletion.mock.calls.length}`,
      endpointOrigin: "https://provider.example",
      provider: "provider.example",
      content: reviewContent(
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
      ),
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
      policy,
      expandContext,
    });

    expect(requestCompletion).toHaveBeenCalledTimes(2);
    expect(expandContext).toHaveBeenCalledOnce();
    expect(result.assessments[0]?.recommended_risk).toBe("low");
  });

  test("refuses a response that omits a supplied candidate", async () => {
    const current = group("src/a.ts", ids.slice(0, 2));
    const requestCompletion = vi.fn(async () => ({
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
      code: "MODEL_EVIDENCE_INVALID",
      scope: "repository",
    });
    expect(requestCompletion).toHaveBeenCalledTimes(3);
  });

  test("refuses invented evidence", async () => {
    const current = group("src/a.ts", [ids[0]!]);
    const invented = {
      ...assessment(ids[0]!, current.path, 2),
      evidence_ids: ["f".repeat(64)],
    };
    const requestCompletion = vi.fn(async () => ({
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

  test("refuses invented observation locations", async () => {
    const current = group("src/a.ts", [ids[0]!]);
    const requestCompletion = vi.fn(async () => ({
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
});
