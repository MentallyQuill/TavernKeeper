import { describe, expect, test } from "vitest";

import {
  ContextualAssessmentSchema,
  ContextualCompletedReviewResponseJsonSchema,
  PublishedContextualAssessmentSchema,
  ContextualReviewResponseJsonSchema,
  ContextualReviewResponseSchema,
} from "../src/model/contextual-review-contract.js";

const id = "a".repeat(64);

const materialAssessment = {
  candidate_id: id,
  evidence_ids: [id],
  disposition: "material_vulnerability" as const,
  impact: "critical" as const,
  exploitability: "readily_exploitable" as const,
  confidence: "high" as const,
  risk_exposure: "demonstrated" as const,
  recommended_risk: "high" as const,
  technical_explanation:
    "The shipped path exposes a critical vulnerability to attacker-controlled input.",
  layman_explanation: "An attacker can readily trigger serious harm.",
  developer_action: "Upgrade or remove the affected dependency.",
  locations: [{ path: "src/client.ts", line_start: 20, line_end: 25 }],
};

describe("contextual review contract", () => {
  test("exports a strict object-root wire schema for structured output", () => {
    expect(ContextualReviewResponseJsonSchema).toMatchObject({
      type: "object",
      properties: { review: { anyOf: expect.any(Array) } },
      required: ["review"],
      additionalProperties: false,
    });
    expect(
      (
        ContextualReviewResponseJsonSchema.properties as Record<
          string,
          Record<string, unknown>
        >
      ).review,
    ).not.toHaveProperty("oneOf");
    expect(ContextualReviewResponseJsonSchema).not.toHaveProperty("$schema");
    expect(ContextualCompletedReviewResponseJsonSchema).not.toHaveProperty(
      "$schema",
    );
    expect(JSON.stringify(ContextualReviewResponseJsonSchema)).toContain(
      '"risk_exposure"',
    );
  });

  test("accepts a complete expected-behavior assessment", () => {
    expect(
      ContextualAssessmentSchema.parse({
        candidate_id: id,
        evidence_ids: [id],
        disposition: "expected_behavior",
        impact: "none",
        exploitability: "unlikely",
        confidence: "high",
        risk_exposure: "not_demonstrated",
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
        risk_exposure: "not_demonstrated",
        recommended_risk: "high",
        technical_explanation: "The behavior is expected for this extension.",
        layman_explanation: "This is normal extension behavior.",
        developer_action: "none",
        locations: [{ path: "src/client.ts", line_start: 20, line_end: 25 }],
      }),
    ).toThrow(/risk.*disposition/iu);
  });

  test("accepts high risk only for a high-confidence critical readily exploitable material vulnerability", () => {
    expect(ContextualAssessmentSchema.parse(materialAssessment)).toMatchObject({
      disposition: "material_vulnerability",
      impact: "critical",
      exploitability: "readily_exploitable",
      confidence: "high",
      recommended_risk: "high",
    });

    for (const invalid of [
      { ...materialAssessment, confidence: "medium" as const },
      { ...materialAssessment, impact: "high" as const },
      { ...materialAssessment, exploitability: "plausible" as const },
    ]) {
      expect(() => ContextualAssessmentSchema.parse(invalid)).toThrow(
        /risk.*disposition/iu,
      );
    }
  });

  test("accepts material risk only for demonstrated high-confidence exploitable harm", () => {
    const yellowAssessment = {
      ...materialAssessment,
      impact: "medium" as const,
      exploitability: "plausible" as const,
      recommended_risk: "material" as const,
    };

    expect(ContextualAssessmentSchema.parse(yellowAssessment)).toMatchObject({
      risk_exposure: "demonstrated",
      confidence: "high",
      recommended_risk: "material",
    });

    for (const invalid of [
      { ...yellowAssessment, risk_exposure: "not_demonstrated" as const },
      { ...yellowAssessment, confidence: "medium" as const },
      { ...yellowAssessment, impact: "low" as const },
      { ...yellowAssessment, exploitability: "unlikely" as const },
    ]) {
      expect(() => ContextualAssessmentSchema.parse(invalid)).toThrow(
        /risk.*assessment|demonstrated/iu,
      );
    }
  });

  test("accepts unresolved evidence only as non-demonstrated low risk", () => {
    const uncertainAssessment = {
      ...materialAssessment,
      disposition: "minor_weakness" as const,
      impact: "medium" as const,
      exploitability: "plausible" as const,
      confidence: "low" as const,
      risk_exposure: "not_demonstrated" as const,
      recommended_risk: "low" as const,
    };

    expect(ContextualAssessmentSchema.parse(uncertainAssessment)).toMatchObject(
      {
        risk_exposure: "not_demonstrated",
        recommended_risk: "low",
      },
    );
    expect(() =>
      ContextualAssessmentSchema.parse({
        ...uncertainAssessment,
        recommended_risk: "material",
      }),
    ).toThrow(/risk.*assessment|demonstrated/iu);
  });

  test("retains backward-compatible parsing for published legacy assessments", () => {
    const { risk_exposure: _riskExposure, ...legacyAssessment } =
      materialAssessment;

    expect(PublishedContextualAssessmentSchema.parse(legacyAssessment)).toEqual(
      legacyAssessment,
    );
  });

  test("requires high confidence before credible malicious behavior can be reported", () => {
    const maliciousAssessment = {
      ...materialAssessment,
      disposition: "credible_malicious_behavior" as const,
      impact: "critical" as const,
      exploitability: "readily_exploitable" as const,
      confidence: "high" as const,
      recommended_risk: "high" as const,
      technical_explanation:
        "The code deliberately sends private content to an attacker-controlled destination.",
      layman_explanation: "The extension deliberately steals private content.",
      developer_action: "Remove the extension and investigate exposure.",
    };

    expect(ContextualAssessmentSchema.parse(maliciousAssessment)).toMatchObject(
      {
        disposition: "credible_malicious_behavior",
        confidence: "high",
        recommended_risk: "high",
      },
    );
    expect(() =>
      ContextualAssessmentSchema.parse({
        ...maliciousAssessment,
        confidence: "medium",
      }),
    ).toThrow(/high confidence/iu);
    expect(() =>
      ContextualAssessmentSchema.parse({
        ...maliciousAssessment,
        risk_exposure: "not_demonstrated",
      }),
    ).toThrow(/demonstrated/iu);
  });

  test("requires unique candidate assessments in a completed response", () => {
    const assessment = {
      candidate_id: id,
      evidence_ids: [id],
      disposition: "expected_behavior",
      impact: "none",
      exploitability: "unlikely",
      confidence: "high",
      risk_exposure: "not_demonstrated",
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
            risk_exposure: "not_demonstrated",
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
            risk_exposure: "not_demonstrated",
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

  test("applies the immediate-danger threshold to contextual observations", () => {
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
            risk_exposure: "not_demonstrated",
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
            disposition: "material_vulnerability",
            impact: "critical",
            exploitability: "plausible",
            confidence: "high",
            risk_exposure: "demonstrated",
            recommended_risk: "high",
            title: "Dependency advisory",
            technical_explanation:
              "A critical advisory affects a dependency but runtime exploitation is only plausible.",
            layman_explanation:
              "The dependency needs attention, but immediate exploitation was not shown.",
            developer_action: "Upgrade the dependency.",
            locations: [
              { path: "package-lock.json", line_start: 20, line_end: 20 },
            ],
          },
        ],
      }),
    ).toThrow(/risk.*disposition/iu);
  });
});
