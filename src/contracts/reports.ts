import { z } from "zod";

import { FullShaSchema } from "./targets.js";

const NonNegativeIntegerSchema = z.number().int().nonnegative();
const VersionSchema = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/u);
const ModelIdentifierSchema = z
  .string()
  .regex(/^[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}$/u);
const HttpsOriginSchema = z.url().refine((value) => {
  const url = new URL(value);
  return url.protocol === "https:" && url.origin === value;
}, "Model endpoint origin must be a canonical HTTPS origin.");
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
const StaffActorSchema = z
  .string()
  .regex(/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/u);

export const ScanModeSchema = z.enum(["standard", "deep"]);
export const ConfidenceSchema = z.enum(["high", "medium", "low"]);
export const DispositionSchema = z.enum(["active", "dismissed"]);
const AdjudicationSchema = z.strictObject({
  decision: DispositionSchema,
  rationale: z.string().min(1).max(1_000),
  actor: StaffActorSchema,
  completed_at: z.iso.datetime(),
  reusable: z.boolean(),
});
export const PublicResultSchema = z.enum(["green", "yellow"]);
export const PublicResultV2Schema = z.enum(["teal", "red"]);
export const AutomatedDispositionSchema = z.enum([
  "confirmed",
  "not-supported",
  "inconclusive",
]);
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
    reference_url: RuleReferenceUrlSchema.optional(),
    fingerprint: ReportIdSchema,
    disposition: DispositionSchema,
    adjudication: AdjudicationSchema.optional(),
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
  )
  .superRefine((finding, context) => {
    if (
      finding.adjudication !== undefined &&
      finding.adjudication.decision !== finding.disposition
    )
      context.addIssue({
        code: "custom",
        path: ["adjudication", "decision"],
        message: "Adjudication decision must match finding disposition.",
      });
    if (
      finding.disposition === "dismissed" &&
      finding.adjudication === undefined
    )
      context.addIssue({
        code: "custom",
        path: ["adjudication"],
        message: "Dismissed findings require staff adjudication metadata.",
      });
    if (
      finding.adjudication?.reusable === true &&
      finding.disposition !== "dismissed"
    )
      context.addIssue({
        code: "custom",
        path: ["adjudication", "reusable"],
        message: "Only a dismissed finding can create a reusable rule.",
      });
  });

const AutomatedReviewSchema = z.strictObject({
  analyzer_policy: VersionSchema,
  challenger_policy: VersionSchema,
  arbiter_policy: VersionSchema,
});

export const FindingV2Schema = z
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
    reference_url: RuleReferenceUrlSchema.optional(),
    fingerprint: ReportIdSchema,
    disposition: AutomatedDispositionSchema,
    automated_review: AutomatedReviewSchema,
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
export type PublicResultV2 = z.infer<typeof PublicResultV2Schema>;
export type AutomatedDisposition = z.infer<typeof AutomatedDispositionSchema>;
export type Finding = z.infer<typeof FindingSchema>;
export type FindingV2 = z.infer<typeof FindingV2Schema>;

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

export function deriveV2Result(
  findings: Array<{
    severity: Severity;
    confidence: Confidence;
    disposition: AutomatedDisposition;
  }>,
): PublicResultV2 {
  return findings.some(
    (finding) =>
      finding.disposition === "confirmed" &&
      ["critical", "high", "medium"].includes(finding.severity) &&
      ["high", "medium"].includes(finding.confidence),
  )
    ? "red"
    : "teal";
}

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
    endpoint_origin: HttpsOriginSchema,
    provider: VersionSchema,
    model: ModelIdentifierSchema,
    input_chunks: NonNegativeIntegerSchema,
    completed_chunks: NonNegativeIntegerSchema,
    input_tokens: NonNegativeIntegerSchema,
    output_tokens: NonNegativeIntegerSchema,
    cache_read_tokens: NonNegativeIntegerSchema,
    reasoning_tokens: NonNegativeIntegerSchema,
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

const RoleCompletionSchema = z
  .strictObject({
    required: NonNegativeIntegerSchema,
    completed: NonNegativeIntegerSchema,
  })
  .refine((value) => value.completed === value.required, {
    path: ["completed"],
    message: "Every required model role call must complete.",
  });

const ModelCoverageV2Schema = ModelCoverageSchema.safeExtend({
  roles: z.strictObject({
    analyzer: RoleCompletionSchema,
    challenger: RoleCompletionSchema,
    arbiter: RoleCompletionSchema,
  }),
});

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

const FindingCountsV2Schema = FindingCountsSchema.omit({
  disposition: true,
}).extend({
  disposition: z.strictObject({
    confirmed: NonNegativeIntegerSchema,
    not_supported: NonNegativeIntegerSchema,
    inconclusive: NonNegativeIntegerSchema,
  }),
});

export function buildFindingCounts(findings: Finding[]) {
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

  return FindingCountsSchema.parse({
    total: findings.length,
    actionable,
    severity,
    confidence,
    disposition,
    categories: Object.entries(categories)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([category, count]) => ({ category, count })),
  });
}

function findingCountsMatch(
  findings: Finding[],
  counts: z.infer<typeof FindingCountsSchema>,
): boolean {
  return (
    JSON.stringify(buildFindingCounts(findings)) === JSON.stringify(counts)
  );
}

export function buildFindingCountsV2(findings: FindingV2[]) {
  const severity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const confidence = { high: 0, medium: 0, low: 0 };
  const disposition = { confirmed: 0, not_supported: 0, inconclusive: 0 };
  const categories: Record<string, number> = {};
  let actionable = 0;

  for (const finding of findings) {
    severity[finding.severity] += 1;
    confidence[finding.confidence] += 1;
    disposition[
      finding.disposition === "not-supported"
        ? "not_supported"
        : finding.disposition
    ] += 1;
    categories[finding.category] = (categories[finding.category] ?? 0) + 1;
    if (deriveV2Result([finding]) === "red") actionable += 1;
  }

  return FindingCountsV2Schema.parse({
    total: findings.length,
    actionable,
    severity,
    confidence,
    disposition,
    categories: Object.entries(categories)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([category, count]) => ({ category, count })),
  });
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

export const ScanReportV2Schema = ReportIdentitySchema.extend({
  schema_version: z.literal(2),
  history: z.strictObject({
    base_sha: FullShaSchema.nullable(),
    commits: z.number().int().min(1).max(20),
  }),
  coverage: z.strictObject({
    inventory: InventoryCoverageSchema,
    tools: z.array(ToolCoverageSchema).min(1),
    model: ModelCoverageV2Schema,
    evidence_validation: z.strictObject({
      status: z.literal("completed"),
      validated_findings: NonNegativeIntegerSchema,
    }),
  }),
  result: PublicResultV2Schema,
  finding_counts: FindingCountsV2Schema,
  findings: z.array(FindingV2Schema),
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
  if (report.result !== deriveV2Result(report.findings)) {
    context.addIssue({
      code: "custom",
      path: ["result"],
      message: "Result must be derived from confirmed review-level findings.",
    });
  }
  if (
    JSON.stringify(buildFindingCountsV2(report.findings)) !==
    JSON.stringify(report.finding_counts)
  ) {
    context.addIssue({
      code: "custom",
      path: ["finding_counts"],
      message: "Finding totals must match sanitized findings.",
    });
  }
  if (
    report.coverage.evidence_validation.validated_findings !==
    report.findings.length
  ) {
    context.addIssue({
      code: "custom",
      path: ["coverage", "evidence_validation", "validated_findings"],
      message: "Every published finding must pass evidence validation.",
    });
  }
  if (
    report.findings.some(
      (finding) =>
        finding.disposition === "inconclusive" &&
        ["critical", "high", "medium"].includes(finding.severity) &&
        ["high", "medium"].includes(finding.confidence),
    )
  ) {
    context.addIssue({
      code: "custom",
      path: ["findings"],
      message:
        "A complete report cannot contain an inconclusive review-level finding.",
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

export const ReportIndexEntryV2Schema = ReportIdentitySchema.omit({
  canonical_url: true,
})
  .extend({
    result: PublicResultV2Schema,
    finding_counts: FindingCountsV2Schema,
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
    history_url: z
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
    const expectedReportUrl =
      `https://mentallyquill.github.io/TavernKeeper/reports/github/` +
      `${report.repository_id}/${report.target_sha}/${report.scanner_policy_version}/` +
      `${report.mode}/${report.report_version}/`;
    if (report.report_url !== expectedReportUrl) {
      context.addIssue({
        code: "custom",
        path: ["report_url"],
        message: "Report URL must match immutable report identity.",
      });
    }
    const expectedHistoryUrl =
      "https://mentallyquill.github.io/TavernKeeper/reports/github/" +
      `${report.repository_id}/history/`;
    if (report.history_url !== expectedHistoryUrl) {
      context.addIssue({
        code: "custom",
        path: ["history_url"],
        message: "History URL must match immutable repository identity.",
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

export const ReportIndexV2Schema = z
  .strictObject({
    schema_version: z.literal(2),
    generated_at: z.iso.datetime(),
    reports: z.array(ReportIndexEntryV2Schema),
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

const ReportIndexInputSchema = z.union([
  ReportIndexSchema,
  ReportIndexV2Schema,
]);

export function parseReportIndex(input: unknown) {
  return ReportIndexInputSchema.parse(input);
}

export type ToolCoverage = z.infer<typeof ToolCoverageSchema>;
export type ScanReport = z.infer<typeof ScanReportSchema>;
export type ScanReportV2 = z.infer<typeof ScanReportV2Schema>;
export type ReportIndex = z.infer<typeof ReportIndexSchema>;
export type ReportIndexEntry = z.infer<typeof ReportIndexEntrySchema>;
export type ReportIndexV2 = z.infer<typeof ReportIndexV2Schema>;
export type ReportIndexEntryV2 = z.infer<typeof ReportIndexEntryV2Schema>;
