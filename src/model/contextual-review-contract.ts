import { z } from "zod";

const IdentifierSchema = z.string().regex(/^[0-9a-f]{64}$/u);
const RepositoryPathSchema = z
  .string()
  .min(1)
  .max(500)
  .refine(
    (value) =>
      !value.includes("\\") &&
      !value.startsWith("/") &&
      !/^[A-Za-z]:/u.test(value) &&
      value
        .split("/")
        .every(
          (segment) => segment !== "" && segment !== "." && segment !== "..",
        ),
    "Location path must be repository-relative.",
  );

const SafeTextSchema = (maximum: number) =>
  z
    .string()
    .trim()
    .min(1)
    .max(maximum)
    .refine(
      (value) =>
        !/[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069<>]/u.test(
          value,
        ),
      "Assessment text contains unsafe characters.",
    );

const LocationSchema = z
  .strictObject({
    path: RepositoryPathSchema,
    line_start: z.number().int().positive(),
    line_end: z.number().int().positive(),
  })
  .refine((location) => location.line_end >= location.line_start, {
    path: ["line_end"],
    message: "Location end must be at least its start.",
  });

export const DispositionSchema = z.enum([
  "expected_behavior",
  "minor_weakness",
  "material_vulnerability",
  "credible_malicious_behavior",
]);
export const ImpactSchema = z.enum([
  "none",
  "low",
  "medium",
  "high",
  "critical",
]);
export const ExploitabilitySchema = z.enum([
  "unlikely",
  "plausible",
  "readily_exploitable",
]);
export const AssessmentConfidenceSchema = z.enum(["low", "medium", "high"]);
export const ItemRiskSchema = z.enum(["low", "material", "high"]);

function riskContradictsDisposition(assessment: {
  disposition: z.infer<typeof DispositionSchema>;
  recommended_risk: z.infer<typeof ItemRiskSchema>;
}) {
  const lowDisposition = ["expected_behavior", "minor_weakness"].includes(
    assessment.disposition,
  );
  return (
    (lowDisposition && assessment.recommended_risk !== "low") ||
    (assessment.disposition === "material_vulnerability" &&
      assessment.recommended_risk === "low") ||
    (assessment.disposition === "credible_malicious_behavior" &&
      assessment.recommended_risk !== "high")
  );
}

const AssessmentFields = {
  candidate_id: IdentifierSchema,
  evidence_ids: z.array(IdentifierSchema).min(1).max(16),
  disposition: DispositionSchema,
  impact: ImpactSchema,
  exploitability: ExploitabilitySchema,
  confidence: AssessmentConfidenceSchema,
  recommended_risk: ItemRiskSchema,
  technical_explanation: SafeTextSchema(1_200),
  layman_explanation: SafeTextSchema(600),
  developer_action: SafeTextSchema(600),
};

function validateAssessment(
  assessment: {
    disposition: z.infer<typeof DispositionSchema>;
    recommended_risk: z.infer<typeof ItemRiskSchema>;
  },
  context: z.core.$RefinementCtx,
) {
  if (riskContradictsDisposition(assessment))
    context.addIssue({
      code: "custom",
      path: ["recommended_risk"],
      message: "Recommended risk contradicts the assessment disposition.",
    });
}

export const ContextualAssessmentInputSchema = z
  .strictObject(AssessmentFields)
  .superRefine(validateAssessment);

export const ContextualAssessmentSchema = z
  .strictObject({
    ...AssessmentFields,
    locations: z.array(LocationSchema).min(1).max(16),
  })
  .superRefine((assessment, context) => {
    validateAssessment(assessment, context);
  });

const ObservationFields = {
  related_candidate_ids: z.array(IdentifierSchema).min(1).max(16),
  evidence_ids: z.array(IdentifierSchema).min(1).max(16),
  disposition: DispositionSchema,
  impact: ImpactSchema,
  exploitability: ExploitabilitySchema,
  confidence: AssessmentConfidenceSchema,
  recommended_risk: ItemRiskSchema,
  title: SafeTextSchema(200),
  technical_explanation: SafeTextSchema(1_200),
  layman_explanation: SafeTextSchema(600),
  developer_action: SafeTextSchema(600),
  locations: z.array(LocationSchema).min(1).max(16),
};

function validateObservation(
  observation: {
    related_candidate_ids: string[];
    evidence_ids: string[];
    disposition: z.infer<typeof DispositionSchema>;
    recommended_risk: z.infer<typeof ItemRiskSchema>;
  },
  context: z.core.$RefinementCtx,
) {
  if (riskContradictsDisposition(observation))
    context.addIssue({
      code: "custom",
      path: ["recommended_risk"],
      message: "Recommended risk contradicts the assessment disposition.",
    });
  if (
    new Set(observation.related_candidate_ids).size !==
      observation.related_candidate_ids.length ||
    new Set(observation.evidence_ids).size !== observation.evidence_ids.length
  )
    context.addIssue({
      code: "custom",
      message: "Observation identifiers must be unique.",
    });
}

export const ContextualObservationInputSchema = z
  .strictObject(ObservationFields)
  .superRefine(validateObservation);

export const ContextualObservationSchema = z
  .strictObject({ observation_id: IdentifierSchema, ...ObservationFields })
  .superRefine(validateObservation);

const CompleteReviewResponseSchema = z
  .strictObject({
    status: z.literal("complete"),
    assessments: z.array(ContextualAssessmentInputSchema).min(1).max(256),
    observations: z.array(ContextualObservationInputSchema).max(64),
  })
  .superRefine((response, context) => {
    const candidateIds = response.assessments.map(
      (assessment) => assessment.candidate_id,
    );
    if (new Set(candidateIds).size !== candidateIds.length) {
      context.addIssue({
        code: "custom",
        path: ["assessments"],
        message: "Completed response candidate IDs must be unique.",
      });
    }
    for (const [index, assessment] of response.assessments.entries()) {
      if (
        new Set(assessment.evidence_ids).size !== assessment.evidence_ids.length
      )
        context.addIssue({
          code: "custom",
          path: ["assessments", index, "evidence_ids"],
          message: "Assessment evidence IDs must be unique.",
        });
    }
  });

const MoreContextResponseSchema = z.strictObject({
  status: z.literal("needs_more_context"),
  candidate_ids: z.array(IdentifierSchema).min(1).max(256),
  requested_context: SafeTextSchema(600),
});

export const ContextualReviewResponseSchema = z.discriminatedUnion("status", [
  CompleteReviewResponseSchema,
  MoreContextResponseSchema,
]);

export type ContextualAssessment = z.infer<typeof ContextualAssessmentSchema>;
export type ContextualAssessmentInput = z.infer<
  typeof ContextualAssessmentInputSchema
>;
export type ContextualObservation = z.infer<typeof ContextualObservationSchema>;
export type ContextualObservationInput = z.infer<
  typeof ContextualObservationInputSchema
>;
export type ContextualReviewResponse = z.infer<
  typeof ContextualReviewResponseSchema
>;
