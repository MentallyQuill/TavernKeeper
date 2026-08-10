import { describe, expect, test, vi } from "vitest";

import type { EvidenceContextGroup } from "../src/context/evidence-context.js";
import type { ContextualReviewResponse } from "../src/model/contextual-review-contract.js";
import {
  checkJsonRepairProvider,
  repairCompletedReviewBindings,
} from "../src/model/json-repair.js";
import type {
  ModelCompletionResult,
  TextCompletionRequest,
} from "../src/model/openai-compatible-client.js";

const candidateA = "a".repeat(64);
const candidateB = "b".repeat(64);
const evidenceA = "c".repeat(64);
const evidenceB = "d".repeat(64);
const invented = "f".repeat(64);

const group: EvidenceContextGroup = {
  group_id: "e".repeat(64),
  repository: "owner/private-project-name",
  project_kinds: ["extension"],
  path: "src/a.ts",
  file_role: "production",
  execution_scope: "runtime",
  target_sha: "1".repeat(40),
  evidence_sha: "2".repeat(40),
  source_kind: "text",
  source_bytes: 100,
  source_sha256: "3".repeat(64),
  ecosystem_context_version: "sillytavern-community-v1",
  ecosystem_context: "PRIVATE ECOSYSTEM CONTEXT",
  candidates: [
    {
      candidate_id: candidateA,
      evidence_id: evidenceA,
      origin: "opengrep",
      rule_id: "network-a",
      category: "network-access",
      scanner_severity: "medium",
      scanner_confidence: "medium",
      title: "PRIVATE FINDING A",
      explanation: "PRIVATE FINDING EXPLANATION A",
      line_start: 2,
      line_end: 2,
    },
    {
      candidate_id: candidateB,
      evidence_id: evidenceB,
      origin: "opengrep",
      rule_id: "network-b",
      category: "network-access",
      scanner_severity: "medium",
      scanner_confidence: "medium",
      title: "PRIVATE FINDING B",
      explanation: "PRIVATE FINDING EXPLANATION B",
      line_start: 3,
      line_end: 3,
    },
  ],
  context: {
    imports: "     1 | PRIVATE IMPORT SOURCE",
    source: [
      "     1 | PRIVATE SOURCE ONE",
      "     2 | PRIVATE SOURCE TWO",
      "     3 | PRIVATE SOURCE THREE",
    ].join("\n"),
    expansions: ["PRIVATE EXPANDED SOURCE"],
    representations: [
      { stage: "raw", sha256: "3".repeat(64), transform_depth: 0 },
    ],
    project_purpose: "PRIVATE PROJECT PURPOSE",
  },
};

type CompletedResponse = Extract<
  ContextualReviewResponse,
  { status: "complete" }
>;

const failedReview: CompletedResponse = {
  status: "complete",
  assessments: [
    {
      candidate_id: candidateA,
      evidence_ids: [evidenceA],
      disposition: "material_vulnerability",
      impact: "medium",
      exploitability: "plausible",
      confidence: "high",
      risk_exposure: "demonstrated",
      recommended_risk: "material",
      technical_explanation: "The supplied behavior has a reachable input.",
      layman_explanation: "A user-controlled value can reach this behavior.",
      developer_action: "Validate the input before use.",
    },
    {
      candidate_id: candidateB,
      evidence_ids: [evidenceB],
      disposition: "expected_behavior",
      impact: "none",
      exploitability: "unlikely",
      confidence: "high",
      risk_exposure: "not_demonstrated",
      recommended_risk: "low",
      technical_explanation: "The behavior matches the declared purpose.",
      layman_explanation: "This behavior is expected for this feature.",
      developer_action: "none",
    },
  ],
  observations: [
    {
      related_candidate_ids: [candidateA],
      evidence_ids: [evidenceA],
      disposition: "material_vulnerability",
      impact: "medium",
      exploitability: "plausible",
      confidence: "high",
      risk_exposure: "demonstrated",
      recommended_risk: "material",
      title: "Related reachable behavior",
      technical_explanation: "The related behavior shares the same input.",
      layman_explanation: "The two behaviors are connected.",
      developer_action: "Validate the shared input.",
      locations: [{ path: "src/a.ts", line_start: 99, line_end: 99 }],
    },
  ],
};

const usage = {
  inputTokens: 210,
  outputTokens: 45,
  cacheReadTokens: 0,
  reasoningTokens: 0,
};

function completion(content: unknown): ModelCompletionResult {
  return {
    completionId: "repair-completion-1",
    endpointOrigin: "https://api.openai.com",
    provider: "api.openai.com",
    content: JSON.stringify(content),
    usage,
  };
}

describe("bounded Luna JSON binding repair", () => {
  test("checks repair compatibility with one synthetic patch request", async () => {
    let calls = 0;
    const result = await checkJsonRepairProvider({
      endpoint: "https://api.openai.com/v1/chat/completions",
      apiKey: "repair-key",
      model: "gpt-5.6-luna",
      requestCompletion: async () => {
        calls += 1;
        return completion({
          repair: {
            assessment_evidence_ids: [
              { index: 0, evidence_ids: ["2".repeat(64)] },
            ],
            observations: [],
          },
        });
      },
    });

    expect(result).toEqual({ status: "passed" });
    expect(calls).toBe(1);
  });

  test("maps assessment evidence by the failed response order", async () => {
    const reversed: CompletedResponse = {
      ...failedReview,
      assessments: [
        { ...failedReview.assessments[1]!, evidence_ids: [invented] },
        failedReview.assessments[0]!,
      ],
      observations: [],
    };
    const requestCompletion = async (request: TextCompletionRequest) => {
      expect(JSON.parse(request.userContent)).toMatchObject({
        allowed_assessment_bindings: [
          {
            index: 0,
            candidate_id: candidateB,
            required_evidence_id: evidenceB,
          },
        ],
      });
      return completion({
        repair: {
          assessment_evidence_ids: [{ index: 0, evidence_ids: [evidenceB] }],
          observations: [],
        },
      });
    };

    const result = await repairCompletedReviewBindings({
      group,
      review: reversed,
      diagnostic: "assessment_evidence_ids",
      provider: {
        endpoint: "https://api.openai.com/v1/chat/completions",
        apiKey: "repair-key",
        model: "gpt-5.6-luna",
        requestCompletion,
      },
    });

    expect(result.review.assessments[0]?.evidence_ids).toEqual([evidenceB]);
  });

  test("repairs only bindings with one source-free minimal request", async () => {
    const requestCompletion = vi.fn(async (request: TextCompletionRequest) =>
      completion({
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
    );

    const result = await repairCompletedReviewBindings({
      group,
      review: failedReview,
      diagnostic: "observation_locations",
      provider: {
        endpoint: "https://api.openai.com/v1/chat/completions",
        apiKey: "repair-key",
        model: "gpt-5.6-luna",
        requestCompletion,
      },
    });

    expect(result.review.assessments[0]?.evidence_ids).toEqual([evidenceA]);
    expect(result.review.observations).toEqual([]);
    expect(result.review.assessments[0]?.recommended_risk).toBe("material");
    expect(result.review.assessments[0]?.technical_explanation).toBe(
      failedReview.assessments[0]?.technical_explanation,
    );
    expect(result.usage).toEqual(usage);
    expect(result.completionId).toBe("repair-completion-1");

    expect(requestCompletion).toHaveBeenCalledOnce();
    const request = requestCompletion.mock.calls[0]?.[0];
    expect(request?.maxOutputTokens).toBeLessThanOrEqual(2_048);
    expect(request?.maxResponseBytes).toBeLessThanOrEqual(16 * 1_024);
    expect(request?.responseJsonSchema?.name).toBe(
      "tavernkeeper_json_binding_repair",
    );
    expect(JSON.stringify(request?.responseJsonSchema?.schema)).not.toMatch(
      /disposition|impact|exploitability|confidence|risk_exposure|recommended_risk|technical_explanation|layman_explanation|developer_action/u,
    );
    expect(request?.userContent).toContain("observation_locations");
    expect(request?.userContent).not.toContain(candidateA);
    expect(request?.userContent).not.toContain(evidenceA);
    expect(request?.userContent).not.toContain("src/a.ts");
    expect(request?.userContent).not.toMatch(/location_(?:path|lines)/u);
    expect(request?.userContent.length).toBeLessThan(1_000);
    for (const forbidden of [
      "owner/private-project-name",
      "PRIVATE ECOSYSTEM CONTEXT",
      "PRIVATE FINDING",
      "PRIVATE IMPORT SOURCE",
      "PRIVATE SOURCE",
      "PRIVATE EXPANDED SOURCE",
      "PRIVATE PROJECT PURPOSE",
      "The supplied behavior has a reachable input.",
      "A user-controlled value can reach this behavior.",
      "Related reachable behavior",
      "The related behavior shares the same input.",
      '"disposition"',
      '"recommended_risk"',
      '"technical_explanation"',
    ])
      expect(request?.userContent).not.toContain(forbidden);
  });

  test("rejects a patch that attempts to add a security judgment", async () => {
    let calls = 0;
    const requestCompletion = async () => {
      calls += 1;
      return completion({
        repair: {
          assessment_evidence_ids: [],
          observations: [],
          recommended_risk: "low",
        },
      });
    };

    await expect(
      repairCompletedReviewBindings({
        group,
        review: failedReview,
        diagnostic: "observation_locations",
        provider: {
          endpoint: "https://api.openai.com/v1/chat/completions",
          apiKey: "repair-key",
          model: "gpt-5.6-luna",
          requestCompletion,
        },
      }),
    ).rejects.toThrow();
    expect(calls).toBe(1);
  });

  test("rejects invented bindings and locations", async () => {
    const requestCompletion = async () =>
      completion({
        repair: {
          assessment_evidence_ids: [],
          observations: [
            {
              index: 0,
              action: "replace",
              related_candidate_ids: [invented],
              evidence_ids: [invented],
              locations: [{ path: "src/a.ts", line_start: 4, line_end: 4 }],
            },
          ],
        },
      });

    await expect(
      repairCompletedReviewBindings({
        group,
        review: failedReview,
        diagnostic: "observation_locations",
        provider: {
          endpoint: "https://api.openai.com/v1/chat/completions",
          apiKey: "repair-key",
          model: "gpt-5.6-luna",
          requestCompletion,
        },
      }),
    ).rejects.toThrow();
  });

  test("rejects a repair outside the failed binding category", async () => {
    const requestCompletion = async () =>
      completion({
        repair: {
          assessment_evidence_ids: [{ index: 0, evidence_ids: [evidenceA] }],
          observations: [],
        },
      });

    await expect(
      repairCompletedReviewBindings({
        group,
        review: failedReview,
        diagnostic: "observation_locations",
        provider: {
          endpoint: "https://api.openai.com/v1/chat/completions",
          apiKey: "repair-key",
          model: "gpt-5.6-luna",
          requestCompletion,
        },
      }),
    ).rejects.toThrow();
  });

  test("does not let a location repair rebind observation evidence", async () => {
    const requestCompletion = async () =>
      completion({
        repair: {
          assessment_evidence_ids: [],
          observations: [
            {
              index: 0,
              action: "replace",
              related_candidate_ids: [candidateB],
              evidence_ids: [evidenceB],
              locations: [{ path: "src/a.ts", line_start: 2, line_end: 2 }],
            },
          ],
        },
      });

    await expect(
      repairCompletedReviewBindings({
        group,
        review: failedReview,
        diagnostic: "observation_locations",
        provider: {
          endpoint: "https://api.openai.com/v1/chat/completions",
          apiKey: "repair-key",
          model: "gpt-5.6-luna",
          requestCompletion,
        },
      }),
    ).rejects.toThrow();
  });

  test("does not let Luna invent a replacement observation location", async () => {
    const requestCompletion = async () =>
      completion({
        repair: {
          assessment_evidence_ids: [],
          observations: [
            {
              index: 0,
              action: "replace",
              related_candidate_ids: [candidateA],
              evidence_ids: [evidenceA],
              locations: [{ path: "src/a.ts", line_start: 2, line_end: 2 }],
            },
          ],
        },
      });

    await expect(
      repairCompletedReviewBindings({
        group,
        review: failedReview,
        diagnostic: "observation_locations",
        provider: {
          endpoint: "https://api.openai.com/v1/chat/completions",
          apiKey: "repair-key",
          model: "gpt-5.6-luna",
          requestCompletion,
        },
      }),
    ).rejects.toThrow();
  });

  test("can only remove an unsupported optional observation", async () => {
    const requestCompletion = async () =>
      completion({
        repair: {
          assessment_evidence_ids: [],
          observations: [
            {
              index: 0,
              action: "drop",
            },
          ],
        },
      });

    const result = await repairCompletedReviewBindings({
      group,
      review: failedReview,
      diagnostic: "observation_locations",
      provider: {
        endpoint: "https://api.openai.com/v1/chat/completions",
        apiKey: "repair-key",
        model: "gpt-5.6-luna",
        requestCompletion,
      },
    });

    expect(result.review.assessments).toEqual(failedReview.assessments);
    expect(result.review.observations).toEqual([]);
  });

  test("rejects dropping an observation that already satisfies the diagnostic", async () => {
    const review: CompletedResponse = {
      ...failedReview,
      observations: [
        failedReview.observations[0]!,
        {
          ...failedReview.observations[0]!,
          title: "Valid optional observation",
          locations: [{ path: "src/a.ts", line_start: 2, line_end: 2 }],
        },
      ],
    };
    const requestCompletion = vi.fn(async (_request: TextCompletionRequest) =>
      completion({
        repair: {
          assessment_evidence_ids: [],
          observations: [{ index: 1, action: "drop" }],
        },
      }),
    );

    await expect(
      repairCompletedReviewBindings({
        group,
        review,
        diagnostic: "observation_locations",
        provider: {
          endpoint: "https://api.openai.com/v1/chat/completions",
          apiKey: "repair-key",
          model: "gpt-5.6-luna",
          requestCompletion,
        },
      }),
    ).rejects.toThrow(/outside the failed binding/iu);
    const prompt = JSON.parse(
      requestCompletion.mock.calls[0]?.[0].userContent ?? "null",
    ) as { invalid_observation_indices: number[] };
    expect(prompt.invalid_observation_indices).toEqual([0]);
  });
});
