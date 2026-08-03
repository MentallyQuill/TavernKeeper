import { describe, expect, test } from "vitest";

import {
  ContextualAssessmentSchema,
  ContextualReviewResponseSchema,
} from "../src/model/contextual-review-contract.js";

const id = "a".repeat(64);

describe("contextual review contract", () => {
  test("accepts a complete expected-behavior assessment", () => {
    expect(
      ContextualAssessmentSchema.parse({
        candidate_id: id,
        evidence_ids: [id],
        disposition: "expected_behavior",
        impact: "none",
        exploitability: "unlikely",
        confidence: "high",
        recommended_risk: "low",
        technical_explanation:
          "The request sends selected lore text to the configured model endpoint.",
        layman_explanation: "This is the extension's expected model request.",
        developer_action: "none",
        locations: [{ path: "src/client.ts", line_start: 20, line_end: 25 }],
      }),
    ).toMatchObject({
      candidate_id: id,
      disposition: "expected_behavior",
      recommended_risk: "low",
    });
  });

  test("rejects a risk recommendation that contradicts the disposition", () => {
    expect(() =>
      ContextualAssessmentSchema.parse({
        candidate_id: id,
        evidence_ids: [id],
        disposition: "expected_behavior",
        impact: "none",
        exploitability: "unlikely",
        confidence: "high",
        recommended_risk: "high",
        technical_explanation: "The behavior is expected for this extension.",
        layman_explanation: "This is normal extension behavior.",
        developer_action: "none",
        locations: [{ path: "src/client.ts", line_start: 20, line_end: 25 }],
      }),
    ).toThrow(/risk.*disposition/iu);
  });

  test("requires unique candidate assessments in a completed response", () => {
    const assessment = {
      candidate_id: id,
      evidence_ids: [id],
      disposition: "expected_behavior",
      impact: "none",
      exploitability: "unlikely",
      confidence: "high",
      recommended_risk: "low",
      technical_explanation: "The behavior matches the stated project purpose.",
      layman_explanation: "This behavior appears expected.",
      developer_action: "none",
    } as const;

    expect(() =>
      ContextualReviewResponseSchema.parse({
        status: "complete",
        assessments: [assessment, assessment],
        observations: [],
      }),
    ).toThrow(/unique/iu);
  });

  test("rejects a contextual observation with a contradictory risk", () => {
    expect(() =>
      ContextualReviewResponseSchema.parse({
        status: "complete",
        assessments: [
          {
            candidate_id: id,
            evidence_ids: [id],
            disposition: "expected_behavior",
            impact: "none",
            exploitability: "unlikely",
            confidence: "high",
            recommended_risk: "low",
            technical_explanation: "The behavior is expected.",
            layman_explanation: "This appears normal.",
            developer_action: "none",
          },
        ],
        observations: [
          {
            related_candidate_ids: [id],
            evidence_ids: [id],
            disposition: "expected_behavior",
            impact: "none",
            exploitability: "unlikely",
            confidence: "high",
            recommended_risk: "high",
            title: "Expected request",
            technical_explanation: "The behavior is expected.",
            layman_explanation: "This appears normal.",
            developer_action: "none",
            locations: [
              { path: "src/client.ts", line_start: 20, line_end: 20 },
            ],
          },
        ],
      }),
    ).toThrow(/risk.*disposition/iu);
  });
});
