import { z } from "zod";

import { FullShaSchema } from "./targets.js";

const VersionSchema = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/u);
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
    "Finding path must be a normalized repository-relative path.",
  );
const RuleReferenceUrlSchema = z.url().refine((value) => {
  const url = new URL(value);
  return (
    url.origin === "https://mentallyquill.github.io" &&
    url.username === "" &&
    url.password === "" &&
    url.search === "" &&
    url.hash === "" &&
    /^\/TavernKeeper\/rules\/[a-z0-9][a-z0-9-]{0,119}\/$/u.test(url.pathname)
  );
}, "Finding reference must identify one canonical TavernKeeper rule page.");

export const ConfidenceSchema = z.enum(["high", "medium", "low"]);
export const SeveritySchema = z.enum([
  "critical",
  "high",
  "medium",
  "low",
  "info",
]);

export const FindingSchema = z
  .strictObject({
    origin: z.string().regex(/^[a-z0-9][a-z0-9:_-]{0,79}$/u),
    rule_id: z.string().min(1).max(120),
    category: z.string().regex(/^[a-z0-9][a-z0-9-]{0,79}$/u),
    severity: SeveritySchema,
    confidence: ConfidenceSchema,
    path: RepositoryPathSchema,
    line_start: z.number().int().positive().nullable(),
    line_end: z.number().int().positive().nullable(),
    evidence_sha: FullShaSchema.nullable(),
    title: z.string().trim().min(1).max(200),
    explanation: z.string().trim().min(1).max(1_000),
    remediation: z.string().trim().min(1).max(1_000).optional(),
    reference_url: RuleReferenceUrlSchema.optional(),
    fingerprint: DigestSchema,
  })
  .refine(
    (finding) =>
      finding.line_start === null
        ? finding.line_end === null
        : finding.line_end === null || finding.line_end >= finding.line_start,
    {
      path: ["line_end"],
      message: "Line end must be null or at least line start.",
    },
  );

export const ToolCoverageSchema = z.strictObject({
  name: z.string().regex(/^[a-z0-9][a-z0-9-]{0,79}$/u),
  version: VersionSchema,
  status: z.enum(["completed", "not-applicable"]),
});

export type Severity = z.infer<typeof SeveritySchema>;
export type Confidence = z.infer<typeof ConfidenceSchema>;
export type Finding = z.infer<typeof FindingSchema>;
export type ToolCoverage = z.infer<typeof ToolCoverageSchema>;
