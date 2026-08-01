import { z } from "zod";

import { FullShaSchema } from "./targets.js";

const NonNegativeIntegerSchema = z.number().int().nonnegative();
const VersionSchema = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/u);
const ReportIdSchema = z.string().regex(/^[0-9a-f]{64}$/u);
const RepositorySchema = z.string().regex(/^[^/\s]+\/[^/\s]+$/u);
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
const CategorySchema = z.string().regex(/^[a-z0-9][a-z0-9-]{0,79}$/u);

export const ScanModeSchema = z.enum(["standard", "deep"]);
export const ConfidenceSchema = z.enum(["high", "medium", "low"]);
export const DispositionSchema = z.enum(["active", "dismissed"]);
export const PublicResultSchema = z.enum(["green", "yellow"]);
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
    category: CategorySchema,
    severity: SeveritySchema,
    confidence: ConfidenceSchema,
    path: RepositoryPathSchema,
    line_start: z.number().int().positive().nullable(),
    line_end: z.number().int().positive().nullable(),
    evidence_sha: FullShaSchema.nullable(),
    title: z.string().min(1).max(200),
    explanation: z.string().min(1).max(1_000),
    remediation: z.string().min(1).max(1_000).optional(),
    reference_url: z
      .url()
      .startsWith("https://mentallyquill.github.io/TavernKeeper/rules/")
      .optional(),
    fingerprint: ReportIdSchema,
    disposition: DispositionSchema,
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

export type ScanMode = z.infer<typeof ScanModeSchema>;
export type Severity = z.infer<typeof SeveritySchema>;
export type Confidence = z.infer<typeof ConfidenceSchema>;
export type Disposition = z.infer<typeof DispositionSchema>;
export type PublicResult = z.infer<typeof PublicResultSchema>;
export type Finding = z.infer<typeof FindingSchema>;

export function deriveResult(
  findings: Array<Pick<Finding, "severity" | "confidence" | "disposition">>,
): PublicResult {
  return findings.some(
    (finding) =>
      finding.disposition === "active" &&
      ["critical", "high", "medium"].includes(finding.severity) &&
      ["high", "medium"].includes(finding.confidence),
  )
    ? "yellow"
    : "green";
}

export const ToolCoverageSchema = z.strictObject({
  name: z.string().regex(/^[a-z0-9][a-z0-9-]{0,79}$/u),
  version: VersionSchema,
  status: z.enum(["completed", "not-applicable"]),
});

const ExcludedCountsSchema = z.strictObject({
  dependency_lockfiles: NonNegativeIntegerSchema,
  vendored_dependencies: NonNegativeIntegerSchema,
  generated_bundles: NonNegativeIntegerSchema,
  minified_files: NonNegativeIntegerSchema,
  binaries: NonNegativeIntegerSchema,
  archives: NonNegativeIntegerSchema,
  oversized_files: NonNegativeIntegerSchema,
  unsafe_entries: NonNegativeIntegerSchema,
});

const InventoryCoverageSchema = z.strictObject({
  files: NonNegativeIntegerSchema,
  bytes: NonNegativeIntegerSchema,
  eligible_text_files: NonNegativeIntegerSchema,
  eligible_text_bytes: NonNegativeIntegerSchema,
  excluded: ExcludedCountsSchema,
});

const ModelCoverageSchema = z
  .strictObject({
    status: z.literal("completed"),
    provider: z.literal("minimax"),
    model: VersionSchema,
    input_chunks: NonNegativeIntegerSchema,
    completed_chunks: NonNegativeIntegerSchema,
    input_tokens: NonNegativeIntegerSchema,
    output_tokens: NonNegativeIntegerSchema,
    total_tokens: NonNegativeIntegerSchema,
  })
  .refine((coverage) => coverage.completed_chunks === coverage.input_chunks, {
    path: ["completed_chunks"],
    message: "Every model input chunk must complete.",
  })
  .refine(
    (coverage) =>
      coverage.total_tokens === coverage.input_tokens + coverage.output_tokens,
    {
      path: ["total_tokens"],
      message: "Total tokens must equal input plus output tokens.",
    },
  );

const FindingCountsSchema = z.strictObject({
  total: NonNegativeIntegerSchema,
  actionable: NonNegativeIntegerSchema,
  severity: z.strictObject({
    critical: NonNegativeIntegerSchema,
    high: NonNegativeIntegerSchema,
    medium: NonNegativeIntegerSchema,
    low: NonNegativeIntegerSchema,
    info: NonNegativeIntegerSchema,
  }),
  confidence: z.strictObject({
    high: NonNegativeIntegerSchema,
    medium: NonNegativeIntegerSchema,
    low: NonNegativeIntegerSchema,
  }),
  disposition: z.strictObject({
    active: NonNegativeIntegerSchema,
    dismissed: NonNegativeIntegerSchema,
  }),
  categories: z
    .array(
      z.strictObject({
        category: CategorySchema,
        count: NonNegativeIntegerSchema,
      }),
    )
    .refine(
      (categories) =>
        categories.every(
          (item, index) =>
            index === 0 || categories[index - 1]!.category < item.category,
        ),
      "Category counts must be unique and sorted.",
    ),
});

function findingCountsMatch(
  findings: Finding[],
  counts: z.infer<typeof FindingCountsSchema>,
): boolean {
  const severity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const confidence = { high: 0, medium: 0, low: 0 };
  const disposition = { active: 0, dismissed: 0 };
  const categories: Record<string, number> = {};
  let actionable = 0;

  for (const finding of findings) {
    severity[finding.severity] += 1;
    confidence[finding.confidence] += 1;
    disposition[finding.disposition] += 1;
    categories[finding.category] = (categories[finding.category] ?? 0) + 1;
    if (deriveResult([finding]) === "yellow") actionable += 1;
  }

  return (
    counts.total === findings.length &&
    counts.actionable === actionable &&
    Object.entries(severity).every(
      ([key, value]) =>
        counts.severity[key as keyof typeof counts.severity] === value,
    ) &&
    Object.entries(confidence).every(
      ([key, value]) =>
        counts.confidence[key as keyof typeof counts.confidence] === value,
    ) &&
    Object.entries(disposition).every(
      ([key, value]) =>
        counts.disposition[key as keyof typeof counts.disposition] === value,
    ) &&
    counts.categories.length === Object.keys(categories).length &&
    counts.categories.every((item) => categories[item.category] === item.count)
  );
}

const ReportIdentitySchema = z.strictObject({
  report_id: ReportIdSchema,
  report_version: z.number().int().positive(),
  supersedes_report_id: ReportIdSchema.nullable(),
  scanner_version: VersionSchema,
  scanner_policy_version: VersionSchema,
  prompt_policy_version: VersionSchema,
  source_id: z.string().regex(/^github-[1-9][0-9]*$/u),
  provider: z.literal("github"),
  repository_id: z.number().int().positive(),
  repository: RepositorySchema,
  canonical_url: z.url().startsWith("https://github.com/"),
  target_sha: FullShaSchema,
  completed_at: z.iso.datetime(),
  mode: ScanModeSchema,
});

export const ScanReportSchema = ReportIdentitySchema.extend({
  schema_version: z.literal(1),
  history: z.strictObject({
    base_sha: FullShaSchema.nullable(),
    commits: z.number().int().min(1).max(20),
  }),
  coverage: z.strictObject({
    inventory: InventoryCoverageSchema,
    tools: z.array(ToolCoverageSchema).min(1),
    model: ModelCoverageSchema,
  }),
  result: PublicResultSchema,
  finding_counts: FindingCountsSchema,
  findings: z.array(FindingSchema),
}).superRefine((report, context) => {
  if (report.source_id !== `github-${report.repository_id}`) {
    context.addIssue({
      code: "custom",
      path: ["source_id"],
      message: "Source ID must match repository ID.",
    });
  }
  if (report.canonical_url !== `https://github.com/${report.repository}`) {
    context.addIssue({
      code: "custom",
      path: ["canonical_url"],
      message: "Canonical URL must match repository.",
    });
  }
  if (report.supersedes_report_id === report.report_id) {
    context.addIssue({
      code: "custom",
      path: ["supersedes_report_id"],
      message: "A report cannot supersede itself.",
    });
  }
  if (report.result !== deriveResult(report.findings)) {
    context.addIssue({
      code: "custom",
      path: ["result"],
      message: "Result must be derived from active review-level findings.",
    });
  }
  if (!findingCountsMatch(report.findings, report.finding_counts)) {
    context.addIssue({
      code: "custom",
      path: ["finding_counts"],
      message: "Finding totals must match sanitized findings.",
    });
  }
  if (
    new Set(report.coverage.tools.map((tool) => tool.name)).size !==
    report.coverage.tools.length
  ) {
    context.addIssue({
      code: "custom",
      path: ["coverage", "tools"],
      message: "Tool coverage names must be unique.",
    });
  }
});

export const ReportIndexEntrySchema = ReportIdentitySchema.omit({
  canonical_url: true,
})
  .extend({
    result: PublicResultSchema,
    finding_counts: FindingCountsSchema,
    coverage: z.strictObject({
      history_commits: z.number().int().min(1).max(20),
      inventory_files: NonNegativeIntegerSchema,
      inventory_bytes: NonNegativeIntegerSchema,
      tools_completed: NonNegativeIntegerSchema,
      tools_not_applicable: NonNegativeIntegerSchema,
      model_chunks: NonNegativeIntegerSchema,
    }),
    report_url: z
      .url()
      .startsWith("https://mentallyquill.github.io/TavernKeeper/reports/"),
  })
  .superRefine((report, context) => {
    if (report.source_id !== `github-${report.repository_id}`) {
      context.addIssue({
        code: "custom",
        path: ["source_id"],
        message: "Source ID must match repository ID.",
      });
    }
    const expectedUrl =
      `https://mentallyquill.github.io/TavernKeeper/reports/github/` +
      `${report.repository_id}/${report.target_sha}/${report.scanner_policy_version}/` +
      `${report.mode}/${report.report_version}/`;
    if (report.report_url !== expectedUrl) {
      context.addIssue({
        code: "custom",
        path: ["report_url"],
        message: "Report URL must match immutable report identity.",
      });
    }
    if (report.supersedes_report_id === report.report_id) {
      context.addIssue({
        code: "custom",
        path: ["supersedes_report_id"],
        message: "A report cannot supersede itself.",
      });
    }
  });

export const ReportIndexSchema = z
  .strictObject({
    schema_version: z.literal(1),
    generated_at: z.iso.datetime(),
    reports: z.array(ReportIndexEntrySchema),
  })
  .superRefine((index, context) => {
    const preferredIdentities = index.reports.map(
      (report) =>
        `${report.repository_id}:${report.target_sha}:${report.scanner_policy_version}`,
    );
    if (new Set(preferredIdentities).size !== preferredIdentities.length) {
      context.addIssue({
        code: "custom",
        path: ["reports"],
        message: "Preferred report identities must be unique.",
      });
    }
    const reportIds = index.reports.map((report) => report.report_id);
    if (new Set(reportIds).size !== reportIds.length) {
      context.addIssue({
        code: "custom",
        path: ["reports"],
        message: "Report IDs must be unique.",
      });
    }
  });

export type ToolCoverage = z.infer<typeof ToolCoverageSchema>;
export type ScanReport = z.infer<typeof ScanReportSchema>;
export type ReportIndex = z.infer<typeof ReportIndexSchema>;
export type ReportIndexEntry = z.infer<typeof ReportIndexEntrySchema>;
