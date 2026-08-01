import { z } from "zod";

import {
  AutomatedDispositionSchema,
  ConfidenceSchema,
  SeveritySchema,
  type Finding,
} from "../contracts/reports.js";
import { FullShaSchema } from "../contracts/targets.js";
import type { ModelChunkSegment } from "./chunker.js";
import { redactSource } from "./redaction.js";

export const DigestSchema = z.string().regex(/^[0-9a-f]{64}$/u);
export const ModelRoleSchema = z.enum(["analyzer", "challenger", "arbiter"]);
export type ModelRole = z.infer<typeof ModelRoleSchema>;

export const EvidenceReferenceSchema = z.strictObject({
  path: z.string().min(1).max(500),
  line_start: z.number().int().positive().nullable(),
  line_end: z.number().int().positive().nullable(),
  segment_id: DigestSchema.nullable(),
  content_digest: DigestSchema,
  target_sha: FullShaSchema,
});
export type EvidenceReference = z.infer<typeof EvidenceReferenceSchema>;

export const AnalyzerAssessmentSchema = z.strictObject({
  fingerprint: DigestSchema,
  evidence: EvidenceReferenceSchema,
  assessment: z.enum(["concerning", "not-supported"]),
  rationale: z.string().min(1).max(1_000),
});
export const AnalyzerDiscoverySchema = z.strictObject({
  rule_id: z.string().min(1).max(120),
  category: z.string().regex(/^[a-z0-9][a-z0-9-]{0,79}$/u),
  severity: SeveritySchema,
  confidence: ConfidenceSchema,
  title: z.string().min(1).max(200),
  explanation: z.string().min(1).max(1_000),
  remediation: z.string().min(1).max(1_000).nullable(),
  evidence: EvidenceReferenceSchema,
  assessment: z.enum(["concerning", "not-supported"]),
  rationale: z.string().min(1).max(1_000),
});
export const AnalyzerPayloadSchema = z.strictObject({
  assessments: z.array(AnalyzerAssessmentSchema).max(100_000),
  discoveries: z.array(AnalyzerDiscoverySchema).max(100_000),
});

export const ChallengeSchema = z.strictObject({
  fingerprint: DigestSchema,
  evidence: EvidenceReferenceSchema,
  position: z.enum(["supports", "disputes"]),
  rationale: z.string().min(1).max(1_000),
});
export const ChallengerPayloadSchema = z.strictObject({
  challenges: z.array(ChallengeSchema).max(100_000),
});

export const ArbiterDecisionSchema = z.strictObject({
  fingerprint: DigestSchema,
  evidence: EvidenceReferenceSchema,
  disposition: AutomatedDispositionSchema,
  rationale: z.string().min(1).max(1_000),
});
export const ArbiterPayloadSchema = z.strictObject({
  decisions: z.array(ArbiterDecisionSchema).max(100_000),
});

export type AnalyzerPayload = z.infer<typeof AnalyzerPayloadSchema>;
export type ChallengerPayload = z.infer<typeof ChallengerPayloadSchema>;
export type ArbiterPayload = z.infer<typeof ArbiterPayloadSchema>;
export type ArbiterDecision = z.infer<typeof ArbiterDecisionSchema>;

export interface RolePolicies {
  analyzer: string;
  challenger: string;
  arbiter: string;
}

export interface ModelRelationship {
  from: string;
  to: string;
  kind: string;
}

export interface ReviewClaim {
  finding: Finding;
  evidence: EvidenceReference;
  analyzerAssessment: "concerning" | "not-supported";
  analyzerRationale: string;
}

export interface ChallengeRecord {
  fingerprint: string;
  evidence: EvidenceReference;
  position: "supports" | "disputes";
  rationale: string;
}

export function sanitizeModelText(
  value: string,
  segments: readonly ModelChunkSegment[],
  maximumLength: number,
) {
  let sanitized = redactSource(value);
  for (const line of segments.flatMap(({ content }) =>
    content.split(/\r?\n/gu),
  )) {
    const candidate = line.trim();
    if (candidate.length >= 12) {
      sanitized = sanitized.replaceAll(candidate, "[REDACTED_SOURCE]");
    }
  }
  return sanitized
    .replace(/[\u0000-\u0008\u000b\u000c\u000e-\u001f\u007f]/gu, " ")
    .replace(/\s+/gu, " ")
    .trim()
    .slice(0, maximumLength);
}

function requireSanitizedText(
  value: string,
  segments: readonly ModelChunkSegment[],
  maximumLength: number,
) {
  const sanitized = sanitizeModelText(value, segments, maximumLength);
  if (sanitized === "") throw new Error("Role result contains empty text.");
  return sanitized;
}

export function sanitizeRolePayload(
  role: ModelRole,
  content: string,
  segments: readonly ModelChunkSegment[],
) {
  const input = JSON.parse(content) as unknown;
  if (role === "analyzer") {
    const parsed = AnalyzerPayloadSchema.parse(input);
    return {
      role,
      result: {
        assessments: parsed.assessments.map((assessment) => ({
          ...assessment,
          rationale: requireSanitizedText(
            assessment.rationale,
            segments,
            1_000,
          ),
        })),
        discoveries: parsed.discoveries.map((discovery) => ({
          ...discovery,
          title: requireSanitizedText(discovery.title, segments, 200),
          explanation: requireSanitizedText(
            discovery.explanation,
            segments,
            1_000,
          ),
          remediation:
            discovery.remediation === null
              ? null
              : requireSanitizedText(discovery.remediation, segments, 1_000),
          rationale: requireSanitizedText(discovery.rationale, segments, 1_000),
        })),
      },
    } as const;
  }
  if (role === "challenger") {
    const parsed = ChallengerPayloadSchema.parse(input);
    return {
      role,
      result: {
        challenges: parsed.challenges.map((challenge) => ({
          ...challenge,
          rationale: requireSanitizedText(challenge.rationale, segments, 1_000),
        })),
      },
    } as const;
  }
  const parsed = ArbiterPayloadSchema.parse(input);
  return {
    role,
    result: {
      decisions: parsed.decisions.map((decision) => ({
        ...decision,
        rationale: requireSanitizedText(decision.rationale, segments, 1_000),
      })),
    },
  } as const;
}

export const roleJsonSchemas = Object.fromEntries(
  [
    ["analyzer", AnalyzerPayloadSchema],
    ["challenger", ChallengerPayloadSchema],
    ["arbiter", ArbiterPayloadSchema],
  ].map(([role, schema]) => [
    role,
    z.toJSONSchema(schema as z.ZodType, { target: "draft-7" }),
  ]),
) as Record<ModelRole, Record<string, unknown>>;
