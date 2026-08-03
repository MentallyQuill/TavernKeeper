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
export const PublicResultSchema = z.enum(["teal", "red"]);

const FindingFields = {
  origin: z.string().regex(/^[a-z0-9][a-z0-9:_-]{0,79}$/u),
  rule_id: z.string().min(1).max(120),
  category: CategorySchema,
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
  fingerprint: ReportIdSchema,
};

function lineRangeIsValid(finding: {
  line_start: number | null;
  line_end: number | null;
}) {
  return finding.line_start === null
    ? finding.line_end === null
    : finding.line_end === null || finding.line_end >= finding.line_start;
}

export const FindingSchema = z
  .strictObject(FindingFields)
  .refine(lineRangeIsValid, {
    path: ["line_end"],
    message: "Line end must be null or at least line start.",
  });

export const FindingPolicyStatusSchema = z.enum([
  "reportable",
  "informational",
]);

export const FindingV4Schema = z
  .strictObject({
    ...FindingFields,
    rule_id: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,119}$/u),
    policy_status: FindingPolicyStatusSchema,
  })
  .refine(lineRangeIsValid, {
    path: ["line_end"],
    message: "Line end must be null or at least line start.",
  })
  .refine(
    (finding) =>
      finding.policy_status ===
      (["critical", "high", "medium"].includes(finding.severity) &&
      ["high", "medium"].includes(finding.confidence)
        ? "reportable"
        : "informational"),
    {
      path: ["policy_status"],
      message: "Finding policy status must match severity and confidence.",
    },
  );

export const ToolCoverageSchema = z.strictObject({
  name: z.string().regex(/^[a-z0-9][a-z0-9-]{0,79}$/u),
  version: VersionSchema,
  status: z.enum(["completed", "not-applicable"]),
});

const FileByteTotalsSchema = z.strictObject({
  files: NonNegativeIntegerSchema,
  bytes: NonNegativeIntegerSchema,
});

const ExcludedCountsSchema = z.strictObject({
  dependency_lockfiles: FileByteTotalsSchema,
  vendored_dependencies: FileByteTotalsSchema,
  generated_bundles: FileByteTotalsSchema,
  minified_files: FileByteTotalsSchema,
  binaries: FileByteTotalsSchema,
  archives: FileByteTotalsSchema,
  oversized_files: FileByteTotalsSchema,
  unsafe_entries: FileByteTotalsSchema,
});

export const FindingCountsV4Schema = z.strictObject({
  total: NonNegativeIntegerSchema,
  reportable: NonNegativeIntegerSchema,
  informational: NonNegativeIntegerSchema,
  reportable_severity: z.strictObject({
    critical: NonNegativeIntegerSchema,
    high: NonNegativeIntegerSchema,
    medium: NonNegativeIntegerSchema,
  }),
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
  policy_status: z.strictObject({
    reportable: NonNegativeIntegerSchema,
    informational: NonNegativeIntegerSchema,
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

const SafeSummaryTextSchema = (maximum: number) =>
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
      "Summary text contains unsafe characters.",
    );

export const DeterministicSummarySchema = z.strictObject({
  headline: SafeSummaryTextSchema(120),
  detail: SafeSummaryTextSchema(400),
});

export function deriveV4Result(
  findings: Array<Pick<z.infer<typeof FindingV4Schema>, "policy_status">>,
) {
  return PublicResultSchema.parse(
    findings.some((finding) => finding.policy_status === "reportable")
      ? "red"
      : "teal",
  );
}

export function buildFindingCountsV4(
  findings: Array<z.infer<typeof FindingV4Schema>>,
) {
  const severity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const reportableSeverity = { critical: 0, high: 0, medium: 0 };
  const confidence = { high: 0, medium: 0, low: 0 };
  const policyStatus = { reportable: 0, informational: 0 };
  const categories: Record<string, number> = {};

  for (const finding of findings) {
    severity[finding.severity] += 1;
    confidence[finding.confidence] += 1;
    policyStatus[finding.policy_status] += 1;
    categories[finding.category] = (categories[finding.category] ?? 0) + 1;
    if (finding.policy_status === "reportable")
      reportableSeverity[finding.severity as keyof typeof reportableSeverity] +=
        1;
  }

  return FindingCountsV4Schema.parse({
    total: findings.length,
    reportable: policyStatus.reportable,
    informational: policyStatus.informational,
    reportable_severity: reportableSeverity,
    severity,
    confidence,
    policy_status: policyStatus,
    categories: Object.entries(categories)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([category, count]) => ({ category, count })),
  });
}

function findingCountsV4Match(
  findings: Array<z.infer<typeof FindingV4Schema>>,
  counts: z.infer<typeof FindingCountsV4Schema>,
) {
  return (
    JSON.stringify(buildFindingCountsV4(findings)) === JSON.stringify(counts)
  );
}

function findingCountsV4AreInternallyConsistent(
  counts: z.infer<typeof FindingCountsV4Schema>,
) {
  const total = (values: Record<string, number>) =>
    Object.values(values).reduce((sum, value) => sum + value, 0);
  return (
    counts.total === counts.reportable + counts.informational &&
    counts.total === total(counts.severity) &&
    counts.total === total(counts.confidence) &&
    counts.total === total(counts.policy_status) &&
    counts.total ===
      counts.categories.reduce((sum, item) => sum + item.count, 0) &&
    counts.reportable === counts.policy_status.reportable &&
    counts.informational === counts.policy_status.informational &&
    counts.reportable === total(counts.reportable_severity) &&
    counts.reportable_severity.critical <= counts.severity.critical &&
    counts.reportable_severity.high <= counts.severity.high &&
    counts.reportable_severity.medium <= counts.severity.medium
  );
}

const InventoryCoverageV4Schema = z.strictObject({
  files: NonNegativeIntegerSchema,
  bytes: NonNegativeIntegerSchema,
  first_party_text_files: NonNegativeIntegerSchema,
  first_party_text_bytes: NonNegativeIntegerSchema,
  excluded: ExcludedCountsSchema,
});

const ReportIdentityV4Schema = z.strictObject({
  report_id: ReportIdSchema,
  report_version: z.number().int().positive(),
  supersedes_report_id: ReportIdSchema.nullable(),
  scanner_version: VersionSchema,
  scanner_policy_version: VersionSchema,
  rule_catalog_version: VersionSchema,
  package_schema_version: z.number().int().positive(),
  source_id: z.string().regex(/^github-[1-9][0-9]*$/u),
  provider: z.literal("github"),
  repository_id: z.number().int().positive(),
  repository: RepositorySchema,
  canonical_url: z.url().startsWith("https://github.com/"),
  target_sha: FullShaSchema,
  completed_at: z.iso.datetime(),
  assessment_method: z.literal("deterministic-static-analysis"),
});

const findingToolByOrigin: Record<string, string | undefined> = {
  tavernkeeper: "tavernkeeper-static",
  gitleaks: "gitleaks",
  opengrep: "opengrep",
  "osv-scanner": "osv-scanner",
  zizmor: "zizmor",
  malcontent: "malcontent",
};

export const ScanReportV4Schema = ReportIdentityV4Schema.extend({
  schema_version: z.literal(4),
  history: z.strictObject({
    base_sha: FullShaSchema.nullable(),
    commits: z.number().int().min(1).max(20),
  }),
  coverage: z.strictObject({
    inventory: InventoryCoverageV4Schema,
    tools: z.array(ToolCoverageSchema).min(1),
    evidence_validation: z.strictObject({
      status: z.literal("completed"),
      validated_findings: NonNegativeIntegerSchema,
    }),
  }),
  result: PublicResultSchema,
  summary: DeterministicSummarySchema,
  finding_counts: FindingCountsV4Schema,
  findings: z.array(FindingV4Schema),
}).superRefine((report, context) => {
  if (report.source_id !== `github-${report.repository_id}`)
    context.addIssue({
      code: "custom",
      path: ["source_id"],
      message: "Source ID must match repository ID.",
    });
  if (report.canonical_url !== `https://github.com/${report.repository}`)
    context.addIssue({
      code: "custom",
      path: ["canonical_url"],
      message: "Canonical URL must match repository.",
    });
  if (report.supersedes_report_id === report.report_id)
    context.addIssue({
      code: "custom",
      path: ["supersedes_report_id"],
      message: "A report cannot supersede itself.",
    });
  if (report.result !== deriveV4Result(report.findings))
    context.addIssue({
      code: "custom",
      path: ["result"],
      message: "Result must be derived from reportable deterministic findings.",
    });
  if (!findingCountsV4Match(report.findings, report.finding_counts))
    context.addIssue({
      code: "custom",
      path: ["finding_counts"],
      message: "Finding totals must match deterministic findings.",
    });
  if (
    report.coverage.evidence_validation.validated_findings !==
    report.findings.length
  )
    context.addIssue({
      code: "custom",
      path: ["coverage", "evidence_validation", "validated_findings"],
      message: "Every published finding must pass evidence validation.",
    });
  const toolCoverage = new Map(
    report.coverage.tools.map((tool) => [tool.name, tool.status]),
  );
  if (toolCoverage.size !== report.coverage.tools.length)
    context.addIssue({
      code: "custom",
      path: ["coverage", "tools"],
      message: "Tool coverage names must be unique.",
    });
  if (
    report.findings.some((finding) => {
      const tool = findingToolByOrigin[finding.origin];
      return tool === undefined || toolCoverage.get(tool) !== "completed";
    })
  )
    context.addIssue({
      code: "custom",
      path: ["findings"],
      message: "Every finding must originate from a completed tool.",
    });
  if (
    new Set(report.findings.map((finding) => finding.fingerprint)).size !==
    report.findings.length
  )
    context.addIssue({
      code: "custom",
      path: ["findings"],
      message: "Finding fingerprints must be unique.",
    });
});

export const ReportIndexEntryV4Schema = ReportIdentityV4Schema.omit({
  canonical_url: true,
})
  .extend({
    result: PublicResultSchema,
    summary: DeterministicSummarySchema,
    finding_counts: FindingCountsV4Schema,
    coverage: z.strictObject({
      history_commits: z.number().int().min(1).max(20),
      inventory_files: NonNegativeIntegerSchema,
      inventory_bytes: NonNegativeIntegerSchema,
      tools_completed: NonNegativeIntegerSchema,
      tools_not_applicable: NonNegativeIntegerSchema,
      evidence_validated: NonNegativeIntegerSchema,
    }),
    report_url: z
      .url()
      .startsWith("https://mentallyquill.github.io/TavernKeeper/reports/"),
    history_url: z
      .url()
      .startsWith("https://mentallyquill.github.io/TavernKeeper/reports/"),
  })
  .superRefine((report, context) => {
    if (report.source_id !== `github-${report.repository_id}`)
      context.addIssue({
        code: "custom",
        path: ["source_id"],
        message: "Source ID must match repository ID.",
      });
    const reportUrl =
      `https://mentallyquill.github.io/TavernKeeper/reports/github/` +
      `${report.repository_id}/${report.target_sha}/${report.scanner_policy_version}/` +
      `${report.report_version}/`;
    if (report.report_url !== reportUrl)
      context.addIssue({
        code: "custom",
        path: ["report_url"],
        message: "Report URL must match immutable report identity.",
      });
    const historyUrl =
      "https://mentallyquill.github.io/TavernKeeper/reports/github/" +
      `${report.repository_id}/history/`;
    if (report.history_url !== historyUrl)
      context.addIssue({
        code: "custom",
        path: ["history_url"],
        message: "History URL must match immutable repository identity.",
      });
    if (report.supersedes_report_id === report.report_id)
      context.addIssue({
        code: "custom",
        path: ["supersedes_report_id"],
        message: "A report cannot supersede itself.",
      });
    if (
      !findingCountsV4AreInternallyConsistent(report.finding_counts) ||
      report.coverage.evidence_validated !== report.finding_counts.total ||
      report.result !== (report.finding_counts.reportable > 0 ? "red" : "teal")
    )
      context.addIssue({
        code: "custom",
        path: ["finding_counts"],
        message: "Indexed finding totals must be internally consistent.",
      });
  });

export const ReportIndexV4Schema = z
  .strictObject({
    schema_version: z.literal(4),
    generated_at: z.iso.datetime(),
    reports: z.array(ReportIndexEntryV4Schema),
  })
  .superRefine((index, context) => {
    const preferredIdentities = index.reports.map(
      (report) =>
        `${report.repository_id}:${report.target_sha}:${report.scanner_policy_version}`,
    );
    if (new Set(preferredIdentities).size !== preferredIdentities.length)
      context.addIssue({
        code: "custom",
        path: ["reports"],
        message: "Preferred report identities must be unique.",
      });
    const reportIds = index.reports.map((report) => report.report_id);
    if (new Set(reportIds).size !== reportIds.length)
      context.addIssue({
        code: "custom",
        path: ["reports"],
        message: "Report IDs must be unique.",
      });
  });

export function parseReportIndex(input: unknown) {
  return ReportIndexV4Schema.parse(input);
}

export type Severity = z.infer<typeof SeveritySchema>;
export type Confidence = z.infer<typeof ConfidenceSchema>;
export type PublicResult = z.infer<typeof PublicResultSchema>;
export type Finding = z.infer<typeof FindingSchema>;
export type FindingV4 = z.infer<typeof FindingV4Schema>;
export type FindingCountsV4 = z.infer<typeof FindingCountsV4Schema>;
export type DeterministicSummary = z.infer<typeof DeterministicSummarySchema>;
export type ToolCoverage = z.infer<typeof ToolCoverageSchema>;
export type ScanReportV4 = z.infer<typeof ScanReportV4Schema>;
export type ReportIndexV4 = z.infer<typeof ReportIndexV4Schema>;
export type ReportIndexEntryV4 = z.infer<typeof ReportIndexEntryV4Schema>;
