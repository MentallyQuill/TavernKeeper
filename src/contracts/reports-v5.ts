import { z } from "zod";

import {
  ContextualAssessmentSchema,
  ContextualAssessmentV2Schema,
  ContextualObservationSchema,
  ContextualObservationV2Schema,
  PolicyV5AssessmentSchema,
  PublishedContextualAssessmentSchema,
  PublishedContextualObservationSchema,
  TriageReasonCodeSchema,
} from "../model/contextual-review-contract.js";
import {
  ConfidenceSchema,
  SeveritySchema,
  ToolCoverageSchema,
} from "./reports.js";
import { FullShaSchema } from "./targets.js";
import {
  JavascriptAnalysisCoverageSchema,
  JavascriptUnresolvedSchema,
  type JavascriptAnalysisCoverage,
} from "../scanners/javascript-analysis-types.js";
import { ExecutionScopeSchema } from "../triage/execution-scope.js";

const CountSchema = z.number().int().nonnegative();
const DigestSchema = z.string().regex(/^[0-9a-f]{64}$/u);
const VersionSchema = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/u);
const RepositorySchema = z.string().regex(/^[^/\s]+\/[^/\s]+$/u);
const PathSchema = z
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
    "Candidate path must be repository-relative.",
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
      "Public report text contains unsafe characters.",
    );

const FileByteTotalsSchema = z.strictObject({
  files: CountSchema,
  bytes: CountSchema,
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
const InventoryCoverageV5Schema = z.strictObject({
  files: CountSchema,
  bytes: CountSchema,
  first_party_text_files: CountSchema,
  first_party_text_bytes: CountSchema,
  excluded: ExcludedCountsSchema,
});

export const PUBLIC_JAVASCRIPT_UNRESOLVED_MAX = 100;
export const INCOMPLETE_JAVASCRIPT_LIMITATION =
  "JavaScript analysis was incomplete, so this first-filter scan supports no clean conclusion about unobserved behavior.";
export const METADATA_ONLY_EVIDENCE_LIMITATION =
  "One or more scanner candidates refer to non-text artifacts. Their size, digest, and scanner metadata were verified, but raw contents were not provided to the contextual model.";

function unresolvedIdentity(value: z.infer<typeof JavascriptUnresolvedSchema>) {
  return `${value.path}\u0000${value.stage}\u0000${value.reason}\u0000${value.recovered}`;
}

export const PublicJavascriptAnalysisCoverageSchema =
  JavascriptAnalysisCoverageSchema.safeExtend({
    unresolved: z
      .array(JavascriptUnresolvedSchema)
      .max(PUBLIC_JAVASCRIPT_UNRESOLVED_MAX),
  }).superRefine((coverage, context) => {
    const identities = coverage.unresolved.map(unresolvedIdentity);
    if (
      identities.some(
        (identity, index) => index > 0 && identities[index - 1]! >= identity,
      )
    )
      context.addIssue({
        code: "custom",
        path: ["unresolved"],
        message:
          "Public unresolved JavaScript coverage must be unique and sorted.",
      });
  });

export function publicJavascriptAnalysisCoverage(
  input: JavascriptAnalysisCoverage,
) {
  const unresolved = [
    ...new Map(
      input.unresolved.map((value) => [unresolvedIdentity(value), value]),
    ).entries(),
  ]
    .sort(([left], [right]) => (left < right ? -1 : left > right ? 1 : 0))
    .slice(0, PUBLIC_JAVASCRIPT_UNRESOLVED_MAX)
    .map(([, value]) => value);
  return PublicJavascriptAnalysisCoverageSchema.parse({
    ...input,
    unresolved,
  });
}

export const FileRoleSchema = z.enum([
  "production",
  "test",
  "fixture",
  "documentation",
  "tooling",
  "generated",
  "vendored",
  "unknown",
]);

export const CandidateV5Schema = z
  .strictObject({
    candidate_id: DigestSchema,
    evidence_id: DigestSchema,
    origin: z.string().regex(/^[a-z0-9][a-z0-9:_-]{0,79}$/u),
    scanner_version: VersionSchema,
    rule_id: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,119}$/u),
    category: z.string().regex(/^[a-z0-9][a-z0-9-]{0,79}$/u),
    scanner_severity: SeveritySchema,
    scanner_confidence: ConfidenceSchema,
    path: PathSchema,
    line_start: z.number().int().positive().nullable(),
    line_end: z.number().int().positive().nullable(),
    evidence_sha: FullShaSchema,
    file_role: FileRoleSchema,
    execution_scope: ExecutionScopeSchema.optional(),
    title: SafeTextSchema(200),
    explanation: SafeTextSchema(1_000),
    remediation: SafeTextSchema(1_000).optional(),
    reference_url: z
      .url()
      .startsWith("https://mentallyquill.github.io/TavernKeeper/rules/")
      .optional(),
  })
  .refine(
    (candidate) =>
      candidate.line_start === null
        ? candidate.line_end === null
        : candidate.line_end === null ||
          candidate.line_end >= candidate.line_start,
    { path: ["line_end"], message: "Candidate line range is invalid." },
  );

const ReviewCountsFields = {
  disposition: z.strictObject({
    expected_behavior: CountSchema,
    minor_weakness: CountSchema,
    material_vulnerability: CountSchema,
    credible_malicious_behavior: CountSchema,
  }),
  impact: z.strictObject({
    none: CountSchema,
    low: CountSchema,
    medium: CountSchema,
    high: CountSchema,
    critical: CountSchema,
  }),
  exploitability: z.strictObject({
    unlikely: CountSchema,
    plausible: CountSchema,
    readily_exploitable: CountSchema,
  }),
  confidence: z.strictObject({
    low: CountSchema,
    medium: CountSchema,
    high: CountSchema,
  }),
  recommended_risk: z.strictObject({
    low: CountSchema,
    material: CountSchema,
    high: CountSchema,
  }),
};

export const ContextualCountsV5Schema = z.strictObject({
  candidates: CountSchema,
  assessments: CountSchema,
  observations: CountSchema,
  items: CountSchema,
  ...ReviewCountsFields,
});

type ReviewItem =
  | z.infer<typeof PublishedContextualAssessmentSchema>
  | z.infer<typeof PolicyV5AssessmentSchema>
  | z.infer<typeof PublishedContextualObservationSchema>;

export function buildContextualCountsV5(
  candidates: number,
  assessments: readonly (
    | z.infer<typeof PublishedContextualAssessmentSchema>
    | z.infer<typeof PolicyV5AssessmentSchema>
  )[],
  observations: readonly z.infer<typeof PublishedContextualObservationSchema>[],
) {
  const counts = {
    candidates,
    assessments: assessments.length,
    observations: observations.length,
    items: assessments.length + observations.length,
    disposition: {
      expected_behavior: 0,
      minor_weakness: 0,
      material_vulnerability: 0,
      credible_malicious_behavior: 0,
    },
    impact: { none: 0, low: 0, medium: 0, high: 0, critical: 0 },
    exploitability: {
      unlikely: 0,
      plausible: 0,
      readily_exploitable: 0,
    },
    confidence: { low: 0, medium: 0, high: 0 },
    recommended_risk: { low: 0, material: 0, high: 0 },
  };
  for (const item of [...assessments, ...observations] as ReviewItem[]) {
    counts.disposition[item.disposition] += 1;
    counts.impact[item.impact] += 1;
    counts.exploitability[item.exploitability] += 1;
    counts.confidence[item.confidence] += 1;
    counts.recommended_risk[item.recommended_risk] += 1;
  }
  return ContextualCountsV5Schema.parse(counts);
}

const EvidenceValidationCoverageV5Schema = z
  .discriminatedUnion("status", [
    z.strictObject({
      status: z.literal("completed"),
      validated_candidates: CountSchema,
    }),
    z.strictObject({
      status: z.literal("completed-with-limitations"),
      validated_candidates: CountSchema,
      metadata_only_candidates: z.number().int().positive(),
    }),
  ])
  .superRefine((coverage, context) => {
    if (
      coverage.status === "completed-with-limitations" &&
      coverage.metadata_only_candidates > coverage.validated_candidates
    )
      context.addIssue({
        code: "custom",
        path: ["metadata_only_candidates"],
        message: "Metadata-only candidates cannot exceed validated candidates.",
      });
  });

const ReportIdentityV5Fields = {
  report_id: DigestSchema,
  report_digest: DigestSchema,
  report_version: z.number().int().positive(),
  supersedes_report_id: DigestSchema.nullable(),
  scanner_version: VersionSchema,
  scanner_policy_version: VersionSchema,
  rule_catalog_version: VersionSchema,
  package_schema_version: z.number().int().positive(),
  contextual_review_policy_version: VersionSchema,
  ecosystem_context_version: VersionSchema,
  prompt_version: VersionSchema,
  assessment_schema_version: VersionSchema,
  source_id: z.string().regex(/^github-[1-9][0-9]*$/u),
  provider: z.literal("github"),
  repository_id: z.number().int().positive(),
  repository: RepositorySchema,
  canonical_url: z.url().startsWith("https://github.com/"),
  target_sha: FullShaSchema,
  completed_at: z.iso.datetime(),
  assessment_method: z.literal("deterministic-evidence-contextual-review"),
};

export const ReviewReuseV5Schema = z.strictObject({
  groups: z.strictObject({
    fresh: CountSchema,
    reused: CountSchema,
  }),
  candidates: z.strictObject({
    fresh: CountSchema,
    reused: CountSchema,
  }),
  source_report_ids: z.array(DigestSchema).max(10_000),
});

export const ReviewBatchUsageV5Schema = z.strictObject({
  kind: z.enum(["contextual_review", "json_repair"]),
  attempt: z.number().int().min(1).max(5),
  group_count: z.number().int().min(1).max(5),
  candidate_count: z.number().int().min(1).max(320),
  estimated_input_tokens: CountSchema.nullable(),
  over_budget: z.boolean(),
  input_tokens: CountSchema,
  output_tokens: CountSchema,
  cache_read_tokens: CountSchema,
  reasoning_tokens: CountSchema,
});

export const ReviewTriageV5Schema = z.strictObject({
  policy_version: z.literal("1"),
  candidates: z.strictObject({
    total: CountSchema,
    deterministic: CountSchema,
    contextual: CountSchema,
    reused_contextual: CountSchema,
  }),
  cases: z.strictObject({
    total: CountSchema,
    contextual: CountSchema,
    reused_contextual: CountSchema,
  }),
  reasons: z
    .array(
      z.strictObject({
        reason_code: TriageReasonCodeSchema,
        count: z.number().int().positive(),
      }),
    )
    .max(10_000),
  model_budget: z.strictObject({
    configured: z.strictObject({
      max_fresh_behavior_cases: z.literal(12),
      max_provider_calls: z.literal(6),
      max_estimated_input_tokens: z.literal(200_000),
      max_actual_input_tokens: z.literal(250_000),
      max_actual_output_tokens: z.literal(40_000),
    }),
    actual: z.strictObject({
      fresh_behavior_cases: CountSchema,
      provider_calls: CountSchema,
      estimated_input_tokens: CountSchema,
      input_tokens: CountSchema,
      output_tokens: CountSchema,
    }),
  }),
});

export const ScanReportV5Schema = z
  .strictObject({
    schema_version: z.literal(5),
    ...ReportIdentityV5Fields,
    contextual_reviewer: z
      .strictObject({
        provider: z.string().regex(/^[A-Za-z0-9.-]{1,253}$/u),
        model: z.string().trim().min(1).max(200),
      })
      .optional(),
    review_usage: z.strictObject({
      input_tokens: CountSchema,
      output_tokens: CountSchema,
      cache_read_tokens: CountSchema,
      reasoning_tokens: CountSchema,
    }),
    review_batches: z.array(ReviewBatchUsageV5Schema).max(10_000).optional(),
    review_triage: ReviewTriageV5Schema.optional(),
    history: z.strictObject({
      base_sha: FullShaSchema.nullable(),
      commits: z.number().int().min(1).max(20),
    }),
    coverage: z.strictObject({
      inventory: InventoryCoverageV5Schema,
      tools: z.array(ToolCoverageSchema).min(1),
      javascript_analysis: PublicJavascriptAnalysisCoverageSchema.optional(),
      evidence_validation: EvidenceValidationCoverageV5Schema,
    }),
    review_coverage: z.strictObject({
      required: CountSchema,
      completed: CountSchema,
    }),
    review_reuse: ReviewReuseV5Schema.optional(),
    candidates: z.array(CandidateV5Schema),
    assessments: z.array(
      z.union([PublishedContextualAssessmentSchema, PolicyV5AssessmentSchema]),
    ),
    observations: z.array(PublishedContextualObservationSchema),
    counts: ContextualCountsV5Schema,
    limitations: z.array(SafeTextSchema(600)).min(1).max(20),
  })
  .superRefine((report, context) => {
    const policy5 =
      report.scanner_policy_version === "5" &&
      report.contextual_review_policy_version === "5";
    if (
      (report.scanner_policy_version === "5") !==
      (report.contextual_review_policy_version === "5")
    )
      context.addIssue({
        code: "custom",
        path: ["contextual_review_policy_version"],
        message: "Scanner policy 5 requires contextual review policy 5.",
      });
    if (!policy5 && report.contextual_reviewer === undefined)
      context.addIssue({
        code: "custom",
        path: ["contextual_reviewer"],
        message: "Historical reports require a contextual reviewer.",
      });
    if (!policy5 && report.review_triage !== undefined)
      context.addIssue({
        code: "custom",
        path: ["review_triage"],
        message: "Review triage provenance requires policy 5.",
      });
    if (
      report.review_batches !== undefined &&
      (
        [
          ["input_tokens", report.review_usage.input_tokens],
          ["output_tokens", report.review_usage.output_tokens],
          ["cache_read_tokens", report.review_usage.cache_read_tokens],
          ["reasoning_tokens", report.review_usage.reasoning_tokens],
        ] as const
      ).some(
        ([field, total]) =>
          report.review_batches!.reduce(
            (sum, batch) => sum + batch[field],
            0,
          ) !== total,
      )
    )
      context.addIssue({
        code: "custom",
        path: ["review_batches"],
        message: "Published review batch usage must reconcile with totals.",
      });
    if (report.review_reuse !== undefined) {
      const sourceIds = report.review_reuse.source_report_ids;
      const expectedCandidates = policy5
        ? report.review_triage?.candidates.contextual
        : report.candidates.length;
      if (
        report.review_reuse.candidates.fresh +
          report.review_reuse.candidates.reused !==
          expectedCandidates ||
        (report.review_reuse.groups.reused === 0) !==
          (sourceIds.length === 0) ||
        new Set(sourceIds).size !== sourceIds.length ||
        sourceIds.some(
          (sourceId, index) => index > 0 && sourceIds[index - 1]! >= sourceId,
        )
      )
        context.addIssue({
          code: "custom",
          path: ["review_reuse"],
          message: "Review reuse provenance is inconsistent.",
        });
    }
    if (
      ["4", "5"].includes(report.scanner_policy_version) &&
      report.coverage.javascript_analysis === undefined
    )
      context.addIssue({
        code: "custom",
        path: ["coverage", "javascript_analysis"],
        message: "JavaScript coverage is required for scanner policy 4.",
      });
    const incompleteJavascript =
      report.coverage.javascript_analysis?.status === "incomplete";
    if (
      incompleteJavascript !==
      report.limitations.includes(INCOMPLETE_JAVASCRIPT_LIMITATION)
    )
      context.addIssue({
        code: "custom",
        path: ["limitations"],
        message:
          "Incomplete JavaScript coverage requires its fixed public limitation.",
      });
    const metadataOnlyEvidence =
      report.coverage.evidence_validation.status ===
      "completed-with-limitations";
    if (
      metadataOnlyEvidence !==
      report.limitations.includes(METADATA_ONLY_EVIDENCE_LIMITATION)
    )
      context.addIssue({
        code: "custom",
        path: ["limitations"],
        message: "Metadata-only evidence requires its fixed public limitation.",
      });
    if (policy5) {
      const triage = report.review_triage;
      if (
        report.rule_catalog_version !== "2" ||
        report.prompt_version !== "contextual-review-v7" ||
        report.assessment_schema_version !== "contextual-assessment-v2"
      )
        context.addIssue({
          code: "custom",
          path: ["contextual_review_policy_version"],
          message:
            "Policy 5 requires current rule, prompt, and schema versions.",
        });
      if (triage === undefined)
        context.addIssue({
          code: "custom",
          path: ["review_triage"],
          message: "Policy 5 requires deterministic triage provenance.",
        });
      for (const [index, candidate] of report.candidates.entries())
        if (candidate.execution_scope === undefined)
          context.addIssue({
            code: "custom",
            path: ["candidates", index, "execution_scope"],
            message: "Policy 5 candidates require execution scope.",
          });
      for (const [index, assessment] of report.assessments.entries())
        if (!PolicyV5AssessmentSchema.safeParse(assessment).success)
          context.addIssue({
            code: "custom",
            path: ["assessments", index],
            message: "Policy 5 assessments require triage provenance.",
          });
      if (triage !== undefined) {
        const reasonCounts = new Map<string, number>();
        let deterministic = 0;
        let contextual = 0;
        for (const assessment of report.assessments)
          if ("assessment_source" in assessment) {
            if (assessment.assessment_source === "deterministic-policy")
              deterministic += 1;
            else contextual += 1;
            reasonCounts.set(
              assessment.triage_reason_code,
              (reasonCounts.get(assessment.triage_reason_code) ?? 0) + 1,
            );
          }
        const publishedReasons = triage.reasons.map(
          ({ reason_code, count }) => [reason_code, count] as const,
        );
        const expectedReasons = [...reasonCounts].sort(([left], [right]) =>
          left.localeCompare(right),
        );
        const reuseCandidates = report.review_reuse?.candidates.reused ?? 0;
        const reuseCases = report.review_reuse?.groups.reused ?? 0;
        const batches = report.review_batches ?? [];
        const actual = triage.model_budget.actual;
        const configured = triage.model_budget.configured;
        const estimatedInputTokens = batches.reduce(
          (total, batch) => total + (batch.estimated_input_tokens ?? 0),
          0,
        );
        if (
          triage.candidates.total !== report.candidates.length ||
          triage.candidates.deterministic + triage.candidates.contextual !==
            triage.candidates.total ||
          triage.candidates.deterministic !== deterministic ||
          triage.candidates.contextual !== contextual ||
          triage.candidates.reused_contextual > triage.candidates.contextual ||
          triage.candidates.reused_contextual !== reuseCandidates
        )
          context.addIssue({
            code: "custom",
            path: ["review_triage", "candidates"],
            message: "Policy 5 triage candidate counts are inconsistent.",
          });
        if (
          triage.cases.contextual > triage.cases.total ||
          triage.cases.reused_contextual > triage.cases.contextual ||
          triage.cases.reused_contextual !== reuseCases ||
          (triage.candidates.total > 0 && triage.cases.total === 0)
        )
          context.addIssue({
            code: "custom",
            path: ["review_triage", "cases"],
            message: "Policy 5 triage case counts are inconsistent.",
          });
        if (
          JSON.stringify(publishedReasons) !==
            JSON.stringify(expectedReasons) ||
          publishedReasons.reduce((total, [, count]) => total + count, 0) !==
            triage.candidates.total
        )
          context.addIssue({
            code: "custom",
            path: ["review_triage", "reasons"],
            message: "Policy 5 triage reason counts are inconsistent.",
          });
        if (
          actual.fresh_behavior_cases !==
            triage.cases.contextual - triage.cases.reused_contextual ||
          actual.provider_calls !== batches.length ||
          actual.estimated_input_tokens !== estimatedInputTokens ||
          actual.input_tokens !== report.review_usage.input_tokens ||
          actual.output_tokens !== report.review_usage.output_tokens ||
          actual.fresh_behavior_cases > configured.max_fresh_behavior_cases ||
          actual.provider_calls > configured.max_provider_calls ||
          actual.estimated_input_tokens >
            configured.max_estimated_input_tokens ||
          actual.input_tokens > configured.max_actual_input_tokens ||
          actual.output_tokens > configured.max_actual_output_tokens
        )
          context.addIssue({
            code: "custom",
            path: ["review_triage", "model_budget"],
            message: "Policy 5 model budget usage is inconsistent.",
          });
        if (
          (contextual > 0 || actual.provider_calls > 0) &&
          report.contextual_reviewer === undefined
        )
          context.addIssue({
            code: "custom",
            path: ["contextual_reviewer"],
            message: "Contextual candidates require a reviewer identity.",
          });
        if (contextual === 0 && report.observations.length > 0)
          context.addIssue({
            code: "custom",
            path: ["observations"],
            message:
              "All-deterministic reports cannot contain model observations.",
          });
      }
    } else if (
      report.assessments.some((assessment) => "assessment_source" in assessment)
    )
      context.addIssue({
        code: "custom",
        path: ["assessments"],
        message: "Assessment triage provenance requires policy 5.",
      });
    if (report.contextual_review_policy_version === "2") {
      for (const [index, assessment] of report.assessments.entries())
        if (!ContextualAssessmentV2Schema.safeParse(assessment).success)
          context.addIssue({
            code: "custom",
            path: ["assessments", index],
            message: "Policy 2 assessment violates immediate-danger rules.",
          });
      for (const [index, observation] of report.observations.entries())
        if (!ContextualObservationV2Schema.safeParse(observation).success)
          context.addIssue({
            code: "custom",
            path: ["observations", index],
            message: "Policy 2 observation violates immediate-danger rules.",
          });
    }
    if (
      report.contextual_review_policy_version === "3" ||
      report.contextual_review_policy_version === "4"
    ) {
      const expectedPrompt = ["4", "5"].includes(
        report.contextual_review_policy_version,
      )
        ? "contextual-review-v7"
        : "contextual-review-v6";
      if (report.prompt_version !== expectedPrompt)
        context.addIssue({
          code: "custom",
          path: ["prompt_version"],
          message:
            "Policy " +
            report.contextual_review_policy_version +
            " requires " +
            expectedPrompt +
            ".",
        });
      if (report.assessment_schema_version !== "contextual-assessment-v2")
        context.addIssue({
          code: "custom",
          path: ["assessment_schema_version"],
          message:
            "Policy " +
            report.contextual_review_policy_version +
            " requires contextual assessment schema 2.",
        });
      for (const [index, assessment] of report.assessments.entries())
        if (!ContextualAssessmentSchema.safeParse(assessment).success)
          context.addIssue({
            code: "custom",
            path: ["assessments", index],
            message:
              "Policy " +
              report.contextual_review_policy_version +
              " assessment violates demonstrated-risk rules.",
          });
      for (const [index, observation] of report.observations.entries())
        if (!ContextualObservationSchema.safeParse(observation).success)
          context.addIssue({
            code: "custom",
            path: ["observations", index],
            message:
              "Policy " +
              report.contextual_review_policy_version +
              " observation violates demonstrated-risk rules.",
          });
    }
    if (report.report_id !== report.report_digest)
      context.addIssue({
        code: "custom",
        path: ["report_digest"],
        message: "Report ID and digest must identify the same public body.",
      });
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
    const candidateIds = report.candidates.map((item) => item.candidate_id);
    const candidateById = new Map(
      report.candidates.map((item) => [item.candidate_id, item]),
    );
    const candidateByEvidenceId = new Map(
      report.candidates.map((item) => [item.evidence_id, item]),
    );
    const evidenceIds = new Set(candidateByEvidenceId.keys());
    const assessmentIds = report.assessments.map((item) => item.candidate_id);
    if (
      new Set(candidateIds).size !== candidateIds.length ||
      new Set(report.candidates.map((item) => item.evidence_id)).size !==
        report.candidates.length
    )
      context.addIssue({
        code: "custom",
        path: ["candidates"],
        message: "Candidate and evidence identities must be unique.",
      });
    if (
      assessmentIds.length !== candidateIds.length ||
      new Set(assessmentIds).size !== assessmentIds.length ||
      candidateIds.some((candidateId) => !assessmentIds.includes(candidateId))
    )
      context.addIssue({
        code: "custom",
        path: ["assessments"],
        message: "Every candidate must have exactly one assessment.",
      });
    for (const [index, item] of report.assessments.entries()) {
      const candidate = candidateById.get(item.candidate_id);
      const citedPaths = new Set(
        item.evidence_ids
          .map((evidenceId) => candidateByEvidenceId.get(evidenceId)?.path)
          .filter((path): path is string => path !== undefined),
      );
      if (
        candidate === undefined ||
        !item.evidence_ids.includes(candidate.evidence_id) ||
        item.evidence_ids.some((evidenceId) => !evidenceIds.has(evidenceId)) ||
        item.locations.some((location) => !citedPaths.has(location.path))
      )
        context.addIssue({
          code: "custom",
          path: ["assessments", index],
          message:
            "An assessment must cite its candidate evidence and only paths bound to cited evidence.",
        });
    }
    for (const [index, item] of report.observations.entries()) {
      const citedPaths = new Set(
        item.evidence_ids
          .map((evidenceId) => candidateByEvidenceId.get(evidenceId)?.path)
          .filter((path): path is string => path !== undefined),
      );
      if (
        item.related_candidate_ids.some(
          (candidateId) => !candidateById.has(candidateId),
        ) ||
        item.evidence_ids.some((evidenceId) => !evidenceIds.has(evidenceId)) ||
        item.locations.some((location) => !citedPaths.has(location.path))
      )
        context.addIssue({
          code: "custom",
          path: ["observations", index],
          message:
            "An observation must cite known candidates and only paths bound to cited evidence.",
        });
    }
    const expectedCounts = buildContextualCountsV5(
      report.candidates.length,
      report.assessments,
      report.observations,
    );
    if (JSON.stringify(report.counts) !== JSON.stringify(expectedCounts))
      context.addIssue({
        code: "custom",
        path: ["counts"],
        message: "Contextual counts must match report items.",
      });
    if (
      report.review_coverage.required !== report.candidates.length ||
      report.review_coverage.completed !== report.assessments.length ||
      report.review_coverage.required !== report.review_coverage.completed ||
      report.coverage.evidence_validation.validated_candidates !==
        report.candidates.length
    )
      context.addIssue({
        code: "custom",
        path: ["review_coverage"],
        message: "Review coverage must include every candidate.",
      });
    const completedTools = new Map(
      report.coverage.tools.map((tool) => [tool.name, tool.status]),
    );
    if (
      ["4", "5"].includes(report.scanner_policy_version) &&
      completedTools.get("javascript-analysis") !== "completed"
    )
      context.addIssue({
        code: "custom",
        path: ["coverage", "tools"],
        message: "Policy-4 reports require completed JavaScript analysis.",
      });
    const toolByOrigin: Record<string, string | undefined> = {
      tavernkeeper: "tavernkeeper-static",
      gitleaks: "gitleaks",
      opengrep: "opengrep",
      "javascript-analysis": "javascript-analysis",
      "osv-scanner": "osv-scanner",
      zizmor: "zizmor",
      malcontent: "malcontent",
    };
    if (
      completedTools.size !== report.coverage.tools.length ||
      report.candidates.some(
        (candidate) =>
          completedTools.get(toolByOrigin[candidate.origin] ?? "") !==
          "completed",
      )
    )
      context.addIssue({
        code: "custom",
        path: ["coverage", "tools"],
        message: "Candidate origins require unique completed tool coverage.",
      });
  });

export const ReportIndexEntryV5Schema = z
  .strictObject({
    ...ReportIdentityV5Fields,
    canonical_url: z.never().optional(),
    counts: ContextualCountsV5Schema,
    coverage: z.strictObject({
      history_commits: z.number().int().min(1).max(20),
      inventory_files: CountSchema,
      inventory_bytes: CountSchema,
      tools_completed: CountSchema,
      tools_not_applicable: CountSchema,
      evidence_validated: CountSchema,
      metadata_only_candidates: CountSchema.default(0),
      review_required: CountSchema,
      review_completed: CountSchema,
      javascript_analysis_status: z
        .enum(["complete", "incomplete", "legacy"])
        .default("legacy"),
    }),
    report_url: z
      .url()
      .startsWith("https://mentallyquill.github.io/TavernKeeper/reports/"),
    history_url: z
      .url()
      .startsWith("https://mentallyquill.github.io/TavernKeeper/reports/"),
  })
  .superRefine((entry, context) => {
    if (entry.source_id !== `github-${entry.repository_id}`)
      context.addIssue({
        code: "custom",
        path: ["source_id"],
        message: "Source ID must match repository ID.",
      });
    const expectedReport =
      `https://mentallyquill.github.io/TavernKeeper/reports/github/` +
      `${entry.repository_id}/${entry.target_sha}/${entry.scanner_policy_version}/${entry.report_id}/`;
    if (entry.report_url !== expectedReport)
      context.addIssue({
        code: "custom",
        path: ["report_url"],
        message: "Report URL must match V5 identity.",
      });
    const expectedHistory =
      `https://mentallyquill.github.io/TavernKeeper/reports/github/` +
      `${entry.repository_id}/history/`;
    if (entry.history_url !== expectedHistory)
      context.addIssue({
        code: "custom",
        path: ["history_url"],
        message: "History URL must match repository identity.",
      });
    if (
      entry.report_id !== entry.report_digest ||
      entry.coverage.review_required !== entry.counts.candidates ||
      entry.coverage.review_completed !== entry.counts.assessments ||
      entry.coverage.review_required !== entry.coverage.review_completed
    )
      context.addIssue({
        code: "custom",
        path: ["coverage"],
        message: "Index review coverage must be complete.",
      });
    if (
      ["4", "5"].includes(entry.scanner_policy_version) &&
      entry.coverage.javascript_analysis_status === "legacy"
    )
      context.addIssue({
        code: "custom",
        path: ["coverage", "javascript_analysis_status"],
        message: "Policy-4 index entries require JavaScript coverage status.",
      });
  });

export const ReportIndexV5Schema = z
  .strictObject({
    schema_version: z.literal(5),
    generated_at: z.iso.datetime(),
    reports: z.array(ReportIndexEntryV5Schema),
  })
  .superRefine((index, context) => {
    const repositoryIds = index.reports.map((entry) => entry.repository_id);
    const reportIds = index.reports.map((entry) => entry.report_id);
    if (
      new Set(repositoryIds).size !== repositoryIds.length ||
      new Set(reportIds).size !== reportIds.length
    )
      context.addIssue({
        code: "custom",
        path: ["reports"],
        message: "Preferred V5 report identities must be unique.",
      });
  });

export function parseReportIndexV5(input: unknown) {
  return ReportIndexV5Schema.parse(input);
}

export type CandidateV5 = z.infer<typeof CandidateV5Schema>;
export type ContextualCountsV5 = z.infer<typeof ContextualCountsV5Schema>;
export type ScanReportV5 = z.infer<typeof ScanReportV5Schema>;
export type ReportIndexEntryV5 = z.infer<typeof ReportIndexEntryV5Schema>;
export type ReportIndexV5 = z.infer<typeof ReportIndexV5Schema>;
