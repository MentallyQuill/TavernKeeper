import { z } from "zod";

import { publicNarrativeIsSafe } from "../contracts/public-narrative.js";

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
      publicNarrativeIsSafe,
      "Assessment text contains unsafe characters.",
    );

const NarrativeFallbacks = {
  title: "Additional contextual observation",
  technical_explanation:
    "Detailed technical wording was omitted by the public report safety filter.",
  layman_explanation:
    "Detailed wording was omitted by the public report safety filter.",
  developer_action:
    "Review the cited evidence and confirm the intended behavior.",
  requested_context: "Additional source context is required.",
} as const;

function record(value: unknown): Record<string, unknown> | undefined {
  return value !== null && typeof value === "object" && !Array.isArray(value)
    ? (value as Record<string, unknown>)
    : undefined;
}

function safeNarrative(
  value: unknown,
  maximum: number,
  fallback: string,
): unknown {
  if (typeof value !== "string") return value;
  const parsed = SafeTextSchema(maximum).safeParse(value);
  if (parsed.success) return parsed.data;
  return value.trim() === "" ? value : fallback;
}

function sanitizeNarrativeObject(
  value: unknown,
  fields: ReadonlyArray<readonly [keyof typeof NarrativeFallbacks, number]>,
): unknown {
  const candidate = record(value);
  if (candidate === undefined) return value;
  const sanitized = { ...candidate };
  for (const [field, maximum] of fields)
    sanitized[field] = safeNarrative(
      sanitized[field],
      maximum,
      NarrativeFallbacks[field],
    );
  return sanitized;
}

export function sanitizeContextualReviewNarratives(input: unknown): unknown {
  const response = record(input);
  if (response === undefined) return input;
  if (response.status === "complete")
    return {
      ...response,
      assessments: Array.isArray(response.assessments)
        ? response.assessments.map((assessment) =>
            sanitizeNarrativeObject(assessment, [
              ["technical_explanation", 1_200],
              ["layman_explanation", 600],
              ["developer_action", 600],
            ]),
          )
        : response.assessments,
      observations: Array.isArray(response.observations)
        ? response.observations.map((observation) =>
            sanitizeNarrativeObject(observation, [
              ["title", 200],
              ["technical_explanation", 1_200],
              ["layman_explanation", 600],
              ["developer_action", 600],
            ]),
          )
        : response.observations,
    };
  if (response.status === "needs_more_context")
    return sanitizeNarrativeObject(response, [["requested_context", 600]]);
  return input;
}

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
export const RiskExposureSchema = z.enum(["not_demonstrated", "demonstrated"]);

function currentRecommendedRisk(assessment: {
  disposition: z.infer<typeof DispositionSchema>;
  impact: z.infer<typeof ImpactSchema>;
  exploitability: z.infer<typeof ExploitabilitySchema>;
  confidence: z.infer<typeof AssessmentConfidenceSchema>;
  risk_exposure: z.infer<typeof RiskExposureSchema>;
}) {
  if (
    assessment.disposition === "expected_behavior" ||
    assessment.disposition === "minor_weakness"
  )
    return "low";
  if (assessment.disposition === "credible_malicious_behavior") return "high";

  const impactIsMaterial = ["medium", "high", "critical"].includes(
    assessment.impact,
  );
  const exploitabilityIsMaterial = [
    "plausible",
    "readily_exploitable",
  ].includes(assessment.exploitability);
  if (
    assessment.risk_exposure !== "demonstrated" ||
    assessment.confidence !== "high" ||
    !impactIsMaterial ||
    !exploitabilityIsMaterial
  )
    return "low";
  const immediateMaterialDanger =
    assessment.impact === "critical" &&
    assessment.exploitability === "readily_exploitable";
  return immediateMaterialDanger ? "high" : "material";
}

function policy2RiskContradictsDisposition(assessment: {
  disposition: z.infer<typeof DispositionSchema>;
  impact: z.infer<typeof ImpactSchema>;
  exploitability: z.infer<typeof ExploitabilitySchema>;
  confidence: z.infer<typeof AssessmentConfidenceSchema>;
  recommended_risk: z.infer<typeof ItemRiskSchema>;
}) {
  const lowDisposition = ["expected_behavior", "minor_weakness"].includes(
    assessment.disposition,
  );
  const immediateMaterialDanger =
    assessment.disposition === "material_vulnerability" &&
    assessment.impact === "critical" &&
    assessment.exploitability === "readily_exploitable" &&
    assessment.confidence === "high";
  return (
    (lowDisposition && assessment.recommended_risk !== "low") ||
    (assessment.disposition === "material_vulnerability" &&
      assessment.recommended_risk !==
        (immediateMaterialDanger ? "high" : "material")) ||
    (assessment.disposition === "credible_malicious_behavior" &&
      assessment.recommended_risk !== "high")
  );
}

function legacyRiskContradictsDisposition(assessment: {
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
  risk_exposure: RiskExposureSchema,
  recommended_risk: ItemRiskSchema,
  technical_explanation: SafeTextSchema(1_200),
  layman_explanation: SafeTextSchema(600),
  developer_action: SafeTextSchema(600),
};

const { risk_exposure: _assessmentRiskExposure, ...LegacyAssessmentFields } =
  AssessmentFields;

function validateAssessment(
  assessment: {
    disposition: z.infer<typeof DispositionSchema>;
    impact: z.infer<typeof ImpactSchema>;
    exploitability: z.infer<typeof ExploitabilitySchema>;
    confidence: z.infer<typeof AssessmentConfidenceSchema>;
    risk_exposure: z.infer<typeof RiskExposureSchema>;
    recommended_risk: z.infer<typeof ItemRiskSchema>;
  },
  context: z.core.$RefinementCtx,
) {
  if (
    assessment.disposition === "credible_malicious_behavior" &&
    assessment.confidence !== "high"
  )
    context.addIssue({
      code: "custom",
      path: ["confidence"],
      message: "Credible malicious behavior requires high confidence.",
    });
  if (
    assessment.disposition === "credible_malicious_behavior" &&
    assessment.risk_exposure !== "demonstrated"
  )
    context.addIssue({
      code: "custom",
      path: ["risk_exposure"],
      message: "Credible malicious behavior requires demonstrated exposure.",
    });
  if (assessment.recommended_risk !== currentRecommendedRisk(assessment))
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

export const ContextualAssessmentV2Schema = z
  .strictObject({
    ...LegacyAssessmentFields,
    locations: z.array(LocationSchema).min(1).max(16),
  })
  .superRefine((assessment, context) => {
    if (
      assessment.disposition === "credible_malicious_behavior" &&
      assessment.confidence !== "high"
    )
      context.addIssue({
        code: "custom",
        path: ["confidence"],
        message: "Credible malicious behavior requires high confidence.",
      });
    if (policy2RiskContradictsDisposition(assessment))
      context.addIssue({
        code: "custom",
        path: ["recommended_risk"],
        message: "Recommended risk contradicts the assessment disposition.",
      });
  });

const LegacyPublishedContextualAssessmentSchema = z
  .strictObject({
    ...LegacyAssessmentFields,
    locations: z.array(LocationSchema).min(1).max(16),
  })
  .superRefine((assessment, context) => {
    if (legacyRiskContradictsDisposition(assessment))
      context.addIssue({
        code: "custom",
        path: ["recommended_risk"],
        message: "Recommended risk contradicts the assessment disposition.",
      });
  });

export const PublishedContextualAssessmentSchema = z.union([
  ContextualAssessmentSchema,
  LegacyPublishedContextualAssessmentSchema,
]);

const ObservationFields = {
  related_candidate_ids: z.array(IdentifierSchema).min(1).max(16),
  evidence_ids: z.array(IdentifierSchema).min(1).max(16),
  disposition: DispositionSchema,
  impact: ImpactSchema,
  exploitability: ExploitabilitySchema,
  confidence: AssessmentConfidenceSchema,
  risk_exposure: RiskExposureSchema,
  recommended_risk: ItemRiskSchema,
  title: SafeTextSchema(200),
  technical_explanation: SafeTextSchema(1_200),
  layman_explanation: SafeTextSchema(600),
  developer_action: SafeTextSchema(600),
  locations: z.array(LocationSchema).min(1).max(16),
};
const { risk_exposure: _observationRiskExposure, ...LegacyObservationFields } =
  ObservationFields;

function validateObservation(
  observation: {
    related_candidate_ids: string[];
    evidence_ids: string[];
    disposition: z.infer<typeof DispositionSchema>;
    impact: z.infer<typeof ImpactSchema>;
    exploitability: z.infer<typeof ExploitabilitySchema>;
    confidence: z.infer<typeof AssessmentConfidenceSchema>;
    risk_exposure: z.infer<typeof RiskExposureSchema>;
    recommended_risk: z.infer<typeof ItemRiskSchema>;
  },
  context: z.core.$RefinementCtx,
) {
  if (
    observation.disposition === "credible_malicious_behavior" &&
    observation.confidence !== "high"
  )
    context.addIssue({
      code: "custom",
      path: ["confidence"],
      message: "Credible malicious behavior requires high confidence.",
    });
  if (
    observation.disposition === "credible_malicious_behavior" &&
    observation.risk_exposure !== "demonstrated"
  )
    context.addIssue({
      code: "custom",
      path: ["risk_exposure"],
      message: "Credible malicious behavior requires demonstrated exposure.",
    });
  if (observation.recommended_risk !== currentRecommendedRisk(observation))
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

const ProgressLocationSchema = z
  .strictObject({
    line_start: z.number().int().positive(),
    line_end: z.number().int().positive(),
  })
  .refine((location) => location.line_end >= location.line_start, {
    path: ["line_end"],
    message: "Location end must be at least its start.",
  });
const { locations: _locations, ...ObservationProgressFields } =
  ObservationFields;
export const ContextualObservationProgressSchema = z
  .strictObject({
    ...ObservationProgressFields,
    locations: z.array(ProgressLocationSchema).min(1).max(16),
  })
  .superRefine(validateObservation);

export const ContextualObservationSchema = z
  .strictObject({ observation_id: IdentifierSchema, ...ObservationFields })
  .superRefine(validateObservation);

export const ContextualObservationV2Schema = z
  .strictObject({
    observation_id: IdentifierSchema,
    ...LegacyObservationFields,
  })
  .superRefine((observation, context) => {
    if (
      observation.disposition === "credible_malicious_behavior" &&
      observation.confidence !== "high"
    )
      context.addIssue({
        code: "custom",
        path: ["confidence"],
        message: "Credible malicious behavior requires high confidence.",
      });
    if (policy2RiskContradictsDisposition(observation))
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
  });

const LegacyPublishedContextualObservationSchema = z
  .strictObject({
    observation_id: IdentifierSchema,
    ...LegacyObservationFields,
  })
  .superRefine((observation, context) => {
    if (legacyRiskContradictsDisposition(observation))
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
  });

export const PublishedContextualObservationSchema = z.union([
  ContextualObservationSchema,
  LegacyPublishedContextualObservationSchema,
]);

const CompleteReviewResponseSchema = z
  .strictObject({
    status: z.literal("complete"),
    assessments: z.array(ContextualAssessmentInputSchema).min(1).max(256),
    observations: z.array(ContextualObservationInputSchema).max(64),
  })
  .superRefine((response, context) => {
    const seenCandidateIds = new Set<string>();
    for (const [index, assessment] of response.assessments.entries()) {
      if (seenCandidateIds.has(assessment.candidate_id))
        context.addIssue({
          code: "custom",
          path: ["assessments", index, "candidate_id"],
          message: "Completed response candidate IDs must be unique.",
        });
      seenCandidateIds.add(assessment.candidate_id);
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

export const ContextualReviewWireResponseSchema = z.strictObject({
  review: z.union([CompleteReviewResponseSchema, MoreContextResponseSchema]),
});

const ContextualCompletedReviewWireResponseSchema = z.strictObject({
  review: CompleteReviewResponseSchema,
});

function structuredOutputJsonSchema(schema: z.ZodType) {
  const generated = z.toJSONSchema(schema) as Record<string, unknown>;
  const transportSchema = { ...generated };
  delete transportSchema.$schema;
  return transportSchema;
}

export const ContextualReviewResponseJsonSchema = structuredOutputJsonSchema(
  ContextualReviewWireResponseSchema,
);

export const ContextualCompletedReviewResponseJsonSchema =
  structuredOutputJsonSchema(ContextualCompletedReviewWireResponseSchema);

type ContextualReviewSchemaGroup = {
  path: string;
  candidates: ReadonlyArray<{
    candidate_id: string;
    evidence_id: string;
  }>;
};

function jsonSchemaObject(
  value: unknown,
  label: string,
): Record<string, unknown> {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    throw new Error(`Generated contextual JSON Schema is missing ${label}.`);
  return value as Record<string, unknown>;
}

function jsonSchemaProperties(value: unknown, label: string) {
  return jsonSchemaObject(jsonSchemaObject(value, label).properties, label);
}

function constrainStringSchema(value: unknown, allowed: readonly string[]) {
  const schema = jsonSchemaObject(value, "an identifier field");
  delete schema.pattern;
  schema.enum = [...allowed];
}

function specializeCompletedReviewSchema(
  value: unknown,
  group: ContextualReviewSchemaGroup,
  candidateIds: readonly string[],
  evidenceIds: readonly string[],
) {
  const review = jsonSchemaObject(value, "the completed review branch");
  const reviewProperties = jsonSchemaProperties(
    review,
    "completed review properties",
  );
  const assessments = jsonSchemaObject(
    reviewProperties.assessments,
    "the assessments array",
  );
  assessments.minItems = candidateIds.length;
  assessments.maxItems = candidateIds.length;
  const assessmentProperties = jsonSchemaProperties(
    jsonSchemaObject(assessments.items, "the assessment item"),
    "assessment properties",
  );
  constrainStringSchema(assessmentProperties.candidate_id, candidateIds);
  constrainStringSchema(
    jsonSchemaObject(
      assessmentProperties.evidence_ids,
      "assessment evidence IDs",
    ).items,
    evidenceIds,
  );

  const observationProperties = jsonSchemaProperties(
    jsonSchemaObject(
      jsonSchemaObject(reviewProperties.observations, "the observations array")
        .items,
      "the observation item",
    ),
    "observation properties",
  );
  constrainStringSchema(
    jsonSchemaObject(
      observationProperties.related_candidate_ids,
      "observation candidate IDs",
    ).items,
    candidateIds,
  );
  constrainStringSchema(
    jsonSchemaObject(
      observationProperties.evidence_ids,
      "observation evidence IDs",
    ).items,
    evidenceIds,
  );
  const locationProperties = jsonSchemaProperties(
    jsonSchemaObject(
      jsonSchemaObject(observationProperties.locations, "observation locations")
        .items,
      "the observation location item",
    ),
    "observation location properties",
  );
  const path = jsonSchemaObject(locationProperties.path, "the location path");
  delete path.minLength;
  delete path.maxLength;
  path.const = group.path;
}

export function contextualReviewResponseJsonSchemaForGroup(
  group: ContextualReviewSchemaGroup,
  completionRequired: boolean,
) {
  if (!RepositoryPathSchema.safeParse(group.path).success)
    throw new Error("Contextual review group path is invalid.");
  if (group.candidates.length === 0)
    throw new Error("Contextual review group has no candidates.");
  const candidateIds = group.candidates.map(({ candidate_id }) => candidate_id);
  const evidenceIds = [
    ...new Set(group.candidates.map(({ evidence_id }) => evidence_id)),
  ];
  if (
    new Set(candidateIds).size !== candidateIds.length ||
    candidateIds.some((value) => !IdentifierSchema.safeParse(value).success) ||
    evidenceIds.some((value) => !IdentifierSchema.safeParse(value).success)
  )
    throw new Error("Contextual review group identities are invalid.");

  const schema = structuredClone(
    completionRequired
      ? ContextualCompletedReviewResponseJsonSchema
      : ContextualReviewResponseJsonSchema,
  );
  const rootProperties = jsonSchemaProperties(schema, "root properties");
  const review = jsonSchemaObject(rootProperties.review, "the review property");
  let completed: unknown = review;
  let needsMoreContext: unknown;
  if (!completionRequired) {
    if (!Array.isArray(review.anyOf) || review.anyOf.length !== 2)
      throw new Error("Generated contextual JSON Schema union is invalid.");
    [completed, needsMoreContext] = review.anyOf;
  }
  specializeCompletedReviewSchema(completed, group, candidateIds, evidenceIds);
  if (needsMoreContext !== undefined) {
    const moreProperties = jsonSchemaProperties(
      needsMoreContext,
      "needs-more-context properties",
    );
    const requestedCandidates = jsonSchemaObject(
      moreProperties.candidate_ids,
      "requested candidate IDs",
    );
    requestedCandidates.maxItems = candidateIds.length;
    constrainStringSchema(requestedCandidates.items, candidateIds);
  }
  return schema;
}

export type ContextualAssessment = z.infer<typeof ContextualAssessmentSchema>;
export type ContextualAssessmentInput = z.infer<
  typeof ContextualAssessmentInputSchema
>;
export type ContextualObservation = z.infer<typeof ContextualObservationSchema>;
export type ContextualObservationInput = z.infer<
  typeof ContextualObservationInputSchema
>;
export type ContextualObservationProgress = z.infer<
  typeof ContextualObservationProgressSchema
>;
export type ContextualReviewResponse = z.infer<
  typeof ContextualReviewResponseSchema
>;
