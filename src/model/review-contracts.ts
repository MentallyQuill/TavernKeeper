import { z } from "zod";

import { ConfidenceSchema, SeveritySchema } from "../contracts/reports.js";
import type { ModelChunkSegment } from "./chunker.js";
import { redactSource } from "./redaction.js";

const NonEmptyProseSchema = z.string().trim().min(1);
const EvidenceIdSchema = z.string().regex(/^(?:source|tool)-[0-9]{6}$/u);

export const ModelConcernInputSchema = z.strictObject({
  title: NonEmptyProseSchema.max(200),
  category: z.string().regex(/^[a-z0-9][a-z0-9-]{0,79}$/u),
  severity: SeveritySchema,
  confidence: ConfidenceSchema,
  explanation: NonEmptyProseSchema.max(1_000),
  evidence_ids: z
    .array(EvidenceIdSchema)
    .min(1)
    .refine((identifiers) => new Set(identifiers).size === identifiers.length, {
      message: "Concern evidence identifiers must be unique.",
    }),
});

export const RepositorySynthesisSchema = z
  .strictObject({
    assessment: z.enum(["no_concerning_evidence", "concerning"]),
    recap: NonEmptyProseSchema.max(1_000),
    concerns: z.array(ModelConcernInputSchema),
  })
  .superRefine((synthesis, context) => {
    if (
      synthesis.assessment === "no_concerning_evidence" &&
      synthesis.concerns.length > 0
    )
      context.addIssue({
        code: "custom",
        path: ["concerns"],
        message: "A clean assessment cannot contain review-level concerns.",
      });
    if (
      synthesis.assessment === "concerning" &&
      !synthesis.concerns.some(
        (concern) =>
          ["critical", "high", "medium"].includes(concern.severity) &&
          ["high", "medium"].includes(concern.confidence),
      )
    )
      context.addIssue({
        code: "custom",
        path: ["concerns"],
        message:
          "A concerning assessment requires a medium-or-higher concern at medium-or-higher confidence.",
      });
  });

export type RepositorySynthesis = z.infer<typeof RepositorySynthesisSchema>;

export function sanitizePrivateChunkReview(
  text: string,
  segments: readonly ModelChunkSegment[],
  maximumCharacters: number,
) {
  if (!Number.isInteger(maximumCharacters) || maximumCharacters < 1)
    throw new RangeError("Private review character ceiling must be positive.");

  let sanitized = redactSource(text);
  for (const line of segments.flatMap(({ content }) =>
    content.split(/\r?\n/gu),
  )) {
    const candidate = line.trim();
    if (candidate.length >= 12) {
      sanitized = sanitized.replaceAll(candidate, "[REDACTED_SOURCE]");
      sanitized = sanitized.replaceAll(
        redactSource(candidate),
        "[REDACTED_SOURCE]",
      );
    }
  }
  const collapsed = sanitized
    .replace(/[\u0000-\u001f\u007f]/gu, " ")
    .replace(/\s+/gu, " ")
    .trim();
  return (collapsed === "" ? "Redacted review." : collapsed).slice(
    0,
    maximumCharacters,
  );
}
