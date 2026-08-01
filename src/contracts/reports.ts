import { z } from "zod";

import { FullShaSchema } from "./targets.js";

export const ScanModeSchema = z.enum(["standard", "deep"]);
export const ScanStatusSchema = z.enum([
  "no-high-confidence-indicators",
  "review-suggested",
  "incomplete",
  "failed",
]);
export const SeveritySchema = z.enum([
  "critical",
  "high",
  "medium",
  "low",
  "info",
]);
export const SummarySchema = z.strictObject({
  critical: z.number().int().nonnegative(),
  high: z.number().int().nonnegative(),
  medium: z.number().int().nonnegative(),
  low: z.number().int().nonnegative(),
  info: z.number().int().nonnegative(),
});

export const FindingSchema = z.strictObject({
  detector: z.string().min(1).max(80),
  rule_id: z.string().min(1).max(120),
  severity: SeveritySchema,
  path: z.string().min(1).max(500),
  line: z.number().int().positive().nullable(),
  title: z.string().min(1).max(200),
  evidence: z.string().max(500),
  fingerprint: z.string().regex(/^[0-9a-f]{64}$/u),
});

export const ToolCoverageSchema = z.strictObject({
  name: z.string().min(1).max(80),
  status: z.enum(["completed", "unavailable", "failed", "skipped"]),
  version: z.string().min(1).max(100).nullable(),
  detail: z.string().min(1).max(300).optional(),
});

export const CoverageSchema = z.strictObject({
  complete: z.boolean(),
  history_commits: z.number().int().min(0).max(20),
  inventory: z.strictObject({
    files: z.number().int().nonnegative(),
    bytes: z.number().int().nonnegative(),
  }),
  tools: z.array(ToolCoverageSchema),
  model: z.strictObject({
    status: z.enum(["completed", "disabled", "failed", "skipped"]),
    provider: z.string().min(1).max(80).nullable(),
    model: z.string().min(1).max(120).nullable(),
  }),
});

export const ScanReportSchema = z.strictObject({
  schema_version: z.literal(1),
  scanner_version: z.string().min(1).max(80),
  source_id: z.string().regex(/^github-[1-9][0-9]*$/u),
  provider: z.literal("github"),
  repository_id: z.number().int().positive(),
  repository: z.string().regex(/^[^/\s]+\/[^/\s]+$/u),
  target_sha: FullShaSchema,
  scanned_at: z.iso.datetime(),
  mode: ScanModeSchema,
  status: ScanStatusSchema,
  summary: SummarySchema,
  coverage: CoverageSchema,
  findings: z.array(FindingSchema),
});

export const ReportIndexEntrySchema = ScanReportSchema.pick({
  source_id: true,
  provider: true,
  repository_id: true,
  repository: true,
  target_sha: true,
  scanned_at: true,
  mode: true,
  status: true,
  summary: true,
}).extend({
  coverage: z.strictObject({ complete: z.boolean() }),
  report_url: z.url().startsWith(
    "https://mentallyquill.github.io/TavernKeeper/reports/",
  ),
});

export const ReportIndexSchema = z.strictObject({
  schema_version: z.literal(1),
  generated_at: z.iso.datetime(),
  reports: z.array(ReportIndexEntrySchema),
});

export type ScanMode = z.infer<typeof ScanModeSchema>;
export type ScanStatus = z.infer<typeof ScanStatusSchema>;
export type Severity = z.infer<typeof SeveritySchema>;
export type Finding = z.infer<typeof FindingSchema>;
export type ToolCoverage = z.infer<typeof ToolCoverageSchema>;
export type ScanReport = z.infer<typeof ScanReportSchema>;
export type ReportIndex = z.infer<typeof ReportIndexSchema>;
export type ReportIndexEntry = z.infer<typeof ReportIndexEntrySchema>;
