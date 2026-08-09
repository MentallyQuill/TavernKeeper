import { z } from "zod";

import type { Finding } from "../contracts/reports.js";

const DigestSchema = z.string().regex(/^[0-9a-f]{64}$/u);
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
    "JavaScript analysis path must be repository-relative.",
  );

export const JavascriptRepresentationStageSchema = z.enum([
  "raw",
  "decoded",
  "normalized",
  "bundle-module",
]);

export const JavascriptTransformSchema = z.enum([
  "original",
  "base64",
  "hex",
  "percent",
  "char-code",
  "literal-concat",
  "webcrack-normalized",
  "webcrack-module",
]);

export const JavascriptRepresentationSchema = z.strictObject({
  stage: JavascriptRepresentationStageSchema,
  sha256: DigestSchema,
  parentSha256: DigestSchema.nullable(),
  transform: JavascriptTransformSchema,
  depth: z.number().int().nonnegative(),
});

export const JavascriptAnalysisStageSchema = z.enum([
  "raw-signatures",
  "raw-ast",
  "raw-opengrep",
  "literal-decode",
  "normalize",
  "bundle-extract",
  "derived-signatures",
  "derived-ast",
  "derived-opengrep",
]);

export const JavascriptUnresolvedReasonSchema = z.enum([
  "binary",
  "invalid-utf8",
  "parse",
  "timeout",
  "memory-limit",
  "input-limit",
  "output-limit",
  "candidate-limit",
  "derivative-limit",
  "recursion-limit",
  "target-limit",
  "unsupported",
]);

export const JavascriptUnresolvedSchema = z.strictObject({
  path: RepositoryPathSchema,
  stage: JavascriptAnalysisStageSchema,
  reason: JavascriptUnresolvedReasonSchema,
  recovered: z.boolean(),
});

export const JavascriptAnalysisCoverageSchema = z
  .strictObject({
    status: z.enum(["complete", "incomplete"]),
    candidates: z.number().int().nonnegative(),
    candidate_bytes: z.number().int().nonnegative(),
    representations: z.strictObject({
      raw: z.number().int().nonnegative(),
      decoded: z.number().int().nonnegative(),
      normalized: z.number().int().nonnegative(),
      bundle_modules: z.number().int().nonnegative(),
    }),
    stages: z.strictObject({
      raw_signatures: z.number().int().nonnegative(),
      raw_ast: z.number().int().nonnegative(),
      raw_opengrep: z.number().int().nonnegative(),
      derived_signatures: z.number().int().nonnegative(),
      derived_ast: z.number().int().nonnegative(),
      derived_opengrep: z.number().int().nonnegative(),
    }),
    unresolved: z.array(JavascriptUnresolvedSchema),
  })
  .superRefine((coverage, context) => {
    if (coverage.status === "complete" && coverage.unresolved.length > 0) {
      context.addIssue({
        code: "custom",
        path: ["unresolved"],
        message:
          "Complete JavaScript analysis cannot retain unresolved stages.",
      });
    }
    if (coverage.status === "incomplete" && coverage.unresolved.length === 0) {
      context.addIssue({
        code: "custom",
        path: ["unresolved"],
        message: "Incomplete JavaScript analysis requires an unresolved stage.",
      });
    }
  });

export const JavaScriptEvidenceHintSchema = z.strictObject({
  finding_fingerprint: DigestSchema,
  original_path: RepositoryPathSchema,
  stage: JavascriptRepresentationStageSchema,
  representation_sha256: DigestSchema,
  transform_depth: z.number().int().nonnegative(),
  line_start: z.number().int().positive().nullable(),
  line_end: z.number().int().positive().nullable(),
  column_start: z.number().int().positive().nullable(),
  column_end: z.number().int().positive().nullable(),
  source: z.string(),
});

export interface DecodedLiteral {
  content: string;
  transform: "base64" | "hex" | "percent" | "char-code" | "literal-concat";
  sourceStart: number;
  sourceEnd: number;
}

export interface JavascriptPrimitiveResult {
  findings: Finding[];
  evidenceHints: JavaScriptEvidenceHint[];
}

export interface JavascriptDerivativeAncestry {
  original_path: string;
  stage: z.infer<typeof JavascriptRepresentationStageSchema>;
  representation_sha256: string;
  parent_sha256: string | null;
  transform: z.infer<typeof JavascriptTransformSchema>;
  transform_depth: number;
}

export type JavascriptRepresentation = z.infer<
  typeof JavascriptRepresentationSchema
>;
export type JavascriptAnalysisStage = z.infer<
  typeof JavascriptAnalysisStageSchema
>;
export type JavascriptUnresolvedReason = z.infer<
  typeof JavascriptUnresolvedReasonSchema
>;
export type JavascriptUnresolved = z.infer<typeof JavascriptUnresolvedSchema>;
export type JavascriptAnalysisCoverage = z.infer<
  typeof JavascriptAnalysisCoverageSchema
>;
export type JavaScriptEvidenceHint = z.infer<
  typeof JavaScriptEvidenceHintSchema
>;
