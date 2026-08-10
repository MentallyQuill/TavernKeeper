import type {
  EvidenceContextGroup,
  FileRole,
} from "../context/evidence-context.js";
import { z } from "zod";
import { CURRENT_SCANNER_POLICY_VERSION } from "../config/policy.js";
import {
  buildContextualCountsV5,
  INCOMPLETE_JAVASCRIPT_LIMITATION,
  METADATA_ONLY_EVIDENCE_LIMITATION,
  publicJavascriptAnalysisCoverage,
  ReviewTriageV5Schema,
  ScanReportV5Schema,
  type CandidateV5,
  type ScanReportV5,
} from "../contracts/reports-v5.js";
import {
  validateScanPackageEvidence,
  type ScanPackageV1,
} from "../contracts/scan-package.js";
import type { CompletedContextualReview } from "../model/contextual-review.js";
import {
  ReviewBatchUsageSchema,
  ReviewUnitSchema,
} from "../model/contextual-review.js";
import {
  ContextualObservationSchema,
  PolicyV5AssessmentSchema,
} from "../model/contextual-review-contract.js";
import {
  describeFinding,
  RULE_CATALOG_VERSION,
} from "../policy/rule-descriptions.js";
import { reportIdentity } from "../publish/report-path.js";
import type { ContextualReviewPolicy } from "../model/contextual-review.js";
import type { ReviewTriagePlan } from "../triage/review-triage.js";

const CountSchema = z.number().int().nonnegative();
const UsageSchema = z.strictObject({
  inputTokens: CountSchema,
  outputTokens: CountSchema,
  cacheReadTokens: CountSchema,
  reasoningTokens: CountSchema,
});

export const CompletedReviewV5Schema = z.strictObject({
  policy_version: z.literal("5"),
  prompt_version: z.literal("contextual-review-v7"),
  schema_version: z.literal("contextual-assessment-v2"),
  reviewer: z
    .strictObject({
      provider: z.string().regex(/^[A-Za-z0-9.-]{1,253}$/u),
      endpoint_origin: z.url(),
      model: z.string().trim().min(1).max(200),
    })
    .optional(),
  coverage: z.strictObject({ required: CountSchema, completed: CountSchema }),
  assessments: z.array(PolicyV5AssessmentSchema),
  observations: z.array(ContextualObservationSchema),
  usage: UsageSchema,
  completion_ids: z.array(z.string().min(1).max(200)),
  review_units: z.array(ReviewUnitSchema),
  review_batches: z.array(ReviewBatchUsageSchema).optional(),
  review_triage: ReviewTriageV5Schema,
});

export type CompletedReviewV5 = z.infer<typeof CompletedReviewV5Schema>;

function zeroUsage() {
  return {
    inputTokens: 0,
    outputTokens: 0,
    cacheReadTokens: 0,
    reasoningTokens: 0,
  };
}

export function mergePolicyV5Review(input: {
  triage: ReviewTriagePlan;
  contextualReview?: CompletedContextualReview | undefined;
  policy: ContextualReviewPolicy;
}): CompletedReviewV5 {
  const contextualCandidates = input.triage.decisions.filter(
    ({ destination }) => destination === "contextual",
  );
  if (
    contextualCandidates.length > 0 !==
    (input.contextualReview !== undefined)
  )
    throw new Error("Contextual review does not match the triage partition.");
  const contextual = input.contextualReview;
  if (
    contextual !== undefined &&
    (contextual.coverage.required !== contextualCandidates.length ||
      contextual.coverage.completed !== contextualCandidates.length ||
      contextual.review_units === undefined)
  )
    throw new Error("Contextual review coverage is incomplete.");
  const decisionByCandidate = new Map(
    input.triage.decisions.map((decision) => [decision.candidate_id, decision]),
  );
  const assessments = [
    ...input.triage.deterministicAssessments.map((assessment) => ({
      ...assessment,
      assessment_source: "deterministic-policy" as const,
      triage_reason_code: decisionByCandidate.get(assessment.candidate_id)!
        .reason_code,
    })),
    ...(contextual?.assessments ?? []).map((assessment) => ({
      ...assessment,
      assessment_source: "contextual-model" as const,
      triage_reason_code: decisionByCandidate.get(assessment.candidate_id)!
        .reason_code,
    })),
  ]
    .map((assessment) => PolicyV5AssessmentSchema.parse(assessment))
    .sort((left, right) => left.candidate_id.localeCompare(right.candidate_id));
  if (assessments.length !== input.triage.decisions.length)
    throw new Error("Merged review coverage is incomplete.");
  const reviewUnits = contextual?.review_units ?? [];
  const reviewBatches = contextual?.review_batches;
  const reusedUnits = reviewUnits.filter(({ reused }) => reused);
  const freshUnits = reviewUnits.filter(({ reused }) => !reused);
  const usage = contextual?.usage ?? zeroUsage();
  const completionIds = contextual?.completion_ids ?? [];
  return CompletedReviewV5Schema.parse({
    policy_version: "5",
    prompt_version: input.policy.promptVersion,
    schema_version: input.policy.schemaVersion,
    ...(contextual === undefined
      ? {}
      : {
          reviewer: {
            provider: contextual.provider,
            endpoint_origin: contextual.endpoint_origin,
            model: contextual.model,
          },
        }),
    coverage: {
      required: input.triage.decisions.length,
      completed: assessments.length,
    },
    assessments,
    observations: contextual?.observations ?? [],
    usage,
    completion_ids: completionIds,
    review_units: reviewUnits,
    ...(reviewBatches === undefined || reviewBatches.length === 0
      ? {}
      : { review_batches: reviewBatches }),
    review_triage: {
      policy_version: "1",
      candidates: {
        total: input.triage.counts.candidates.total,
        deterministic: input.triage.counts.candidates.deterministic,
        contextual: input.triage.counts.candidates.contextual,
        reused_contextual: reusedUnits.reduce(
          (total, unit) => total + unit.candidate_ids.length,
          0,
        ),
      },
      cases: {
        total: input.triage.counts.cases.total,
        contextual: input.triage.counts.cases.contextual,
        reused_contextual: reusedUnits.length,
      },
      reasons: input.triage.counts.reasons,
      model_budget: {
        configured: {
          max_fresh_behavior_cases: input.policy.maxFreshBehaviorCases,
          max_provider_calls: input.policy.maxProviderCalls,
          max_estimated_input_tokens: input.policy.maxEstimatedInputTokens,
          max_actual_input_tokens: input.policy.maxActualInputTokens,
          max_actual_output_tokens: input.policy.maxActualOutputTokens,
        },
        actual: {
          fresh_behavior_cases: freshUnits.length,
          provider_calls: completionIds.length,
          estimated_input_tokens: (reviewBatches ?? []).reduce(
            (total, batch) => total + (batch.estimated_input_tokens ?? 0),
            0,
          ),
          input_tokens: usage.inputTokens,
          output_tokens: usage.outputTokens,
        },
      },
    },
  });
}

export interface ContextualReportInput {
  scanPackage: unknown;
  review: CompletedReviewV5;
  evidenceGroups: readonly EvidenceContextGroup[];
}

export interface ContextualReportOptions {
  targetSha: string;
  completedAt: string;
  reportVersion: number;
  supersedesReportId: string | null;
  limitations: readonly string[];
}

const originTool: Record<string, string | undefined> = {
  tavernkeeper: "tavernkeeper-static",
  gitleaks: "gitleaks",
  opengrep: "opengrep",
  "javascript-analysis": "javascript-analysis",
  "osv-scanner": "osv-scanner",
  zizmor: "zizmor",
  malcontent: "malcontent",
};

const coverageLimitationText = {
  parser_syntax:
    "OpenGrep could not parse some source files; findings from successfully analyzed files are included.",
  rule_timeout:
    "OpenGrep timed out on some rule and file combinations; findings from completed analyses are included.",
} as const;

function reportLimitations(
  scanPackage: ScanPackageV1,
  configured: readonly string[],
  evidenceGroups: readonly EvidenceContextGroup[],
) {
  const scannerLimitations = scanPackage.tools.flatMap((tool) =>
    (tool.limitations ?? []).map(
      (limitation) => coverageLimitationText[limitation],
    ),
  );
  const javascriptLimitations =
    scanPackage.javascript_analysis?.status === "incomplete"
      ? [INCOMPLETE_JAVASCRIPT_LIMITATION]
      : [];
  const contextualLimitations = evidenceGroups.some(
    (group) => group.source_kind === "metadata-only",
  )
    ? [METADATA_ONLY_EVIDENCE_LIMITATION]
    : [];
  return [
    ...new Set([
      ...configured,
      ...scannerLimitations,
      ...javascriptLimitations,
      ...contextualLimitations,
    ]),
  ];
}

function candidateRoles(
  groups: readonly EvidenceContextGroup[],
  scanPackage: ScanPackageV1,
) {
  const roles = new Map<string, { role: FileRole; evidenceId: string }>();
  for (const group of groups) {
    if (
      group.repository !== scanPackage.target.repository ||
      group.target_sha !== scanPackage.target.target_sha ||
      group.ecosystem_context_version !== "sillytavern-community-v1"
    )
      throw new Error(
        "Evidence group identity does not match the Scan Package.",
      );
    for (const candidate of group.candidates) {
      if (roles.has(candidate.candidate_id))
        throw new Error("Evidence candidate identities must be unique.");
      roles.set(candidate.candidate_id, {
        role: group.file_role,
        evidenceId: candidate.evidence_id,
      });
    }
  }
  if (
    roles.size !== scanPackage.findings.length ||
    scanPackage.findings.some((finding) => !roles.has(finding.fingerprint))
  )
    throw new Error("Evidence groups must cover every Scan Package finding.");
  return roles;
}

function publicCandidates(
  scanPackage: ScanPackageV1,
  groups: readonly EvidenceContextGroup[],
): CandidateV5[] {
  const roles = candidateRoles(groups, scanPackage);
  const versions = new Map<string, string>(
    scanPackage.tools.map((tool) => [tool.name, tool.version]),
  );
  return scanPackage.findings.map((finding) => {
    const description = describeFinding(finding);
    const role = roles.get(finding.fingerprint)!;
    const tool = originTool[finding.origin];
    const scannerVersion = tool === undefined ? undefined : versions.get(tool);
    if (scannerVersion === undefined)
      throw new Error("Candidate scanner version is unavailable.");
    return {
      candidate_id: finding.fingerprint,
      evidence_id: role.evidenceId,
      origin: finding.origin,
      scanner_version: scannerVersion,
      rule_id: finding.rule_id,
      category: finding.category,
      scanner_severity: finding.severity,
      scanner_confidence: finding.confidence,
      path: finding.path,
      line_start: finding.line_start,
      line_end: finding.line_end,
      evidence_sha: finding.evidence_sha ?? scanPackage.target.target_sha,
      file_role: role.role,
      title: description.title,
      explanation: description.explanation,
      remediation: description.remediation,
    };
  });
}

export function buildContextualReport(
  input: ContextualReportInput,
  options: ContextualReportOptions,
): ScanReportV5 {
  const scanPackage = validateScanPackageEvidence(input.scanPackage);
  if (scanPackage.target.target_sha !== options.targetSha)
    throw new Error(
      "Report target SHA must match the Scan Package target SHA.",
    );
  if (
    scanPackage.scanner_policy_version !== CURRENT_SCANNER_POLICY_VERSION ||
    scanPackage.rule_catalog_version !== RULE_CATALOG_VERSION
  )
    throw new Error("Contextual report policy versions are unsupported.");
  const candidates = publicCandidates(scanPackage, input.evidenceGroups);
  if (
    input.review.coverage.required !== candidates.length ||
    input.review.coverage.completed !== candidates.length ||
    input.review.assessments.length !== candidates.length
  )
    throw new Error("Contextual review coverage is incomplete.");
  const counts = buildContextualCountsV5(
    candidates.length,
    input.review.assessments,
    input.review.observations,
  );
  const metadataOnlyCandidates = input.evidenceGroups.reduce(
    (total, group) =>
      total +
      (group.source_kind === "metadata-only" ? group.candidates.length : 0),
    0,
  );
  const reviewReuse =
    input.review.review_units === undefined
      ? undefined
      : {
          groups: {
            fresh: input.review.review_units.filter(({ reused }) => !reused)
              .length,
            reused: input.review.review_units.filter(({ reused }) => reused)
              .length,
          },
          candidates: {
            fresh: input.review.review_units
              .filter(({ reused }) => !reused)
              .reduce(
                (total, { candidate_ids }) => total + candidate_ids.length,
                0,
              ),
            reused: input.review.review_units
              .filter(({ reused }) => reused)
              .reduce(
                (total, { candidate_ids }) => total + candidate_ids.length,
                0,
              ),
          },
          source_report_ids: [
            ...new Set(
              input.review.review_units.flatMap(({ origin_report_id }) =>
                origin_report_id === null ? [] : [origin_report_id],
              ),
            ),
          ].sort(),
        };
  const withoutIdentity = {
    schema_version: 5 as const,
    report_version: options.reportVersion,
    supersedes_report_id: options.supersedesReportId,
    scanner_version: scanPackage.scanner_version,
    scanner_policy_version: scanPackage.scanner_policy_version,
    rule_catalog_version: scanPackage.rule_catalog_version,
    package_schema_version: scanPackage.schema_version,
    contextual_review_policy_version: input.review.policy_version,
    ecosystem_context_version: "sillytavern-community-v1",
    prompt_version: input.review.prompt_version,
    assessment_schema_version: input.review.schema_version,
    source_id: scanPackage.target.source_id,
    provider: scanPackage.target.provider,
    repository_id: scanPackage.target.repository_id,
    repository: scanPackage.target.repository,
    canonical_url: scanPackage.target.canonical_url,
    target_sha: scanPackage.target.target_sha,
    completed_at: options.completedAt,
    assessment_method: "deterministic-evidence-contextual-review" as const,
    ...(input.review.reviewer === undefined
      ? {}
      : {
          contextual_reviewer: {
            provider: input.review.reviewer.provider,
            model: input.review.reviewer.model,
          },
        }),
    review_usage: {
      input_tokens: input.review.usage.inputTokens,
      output_tokens: input.review.usage.outputTokens,
      cache_read_tokens: input.review.usage.cacheReadTokens,
      reasoning_tokens: input.review.usage.reasoningTokens,
    },
    ...(input.review.review_batches === undefined
      ? {}
      : { review_batches: input.review.review_batches }),
    review_triage: input.review.review_triage,
    history: scanPackage.history,
    coverage: {
      inventory: {
        files: scanPackage.inventory.totals.files,
        bytes: scanPackage.inventory.totals.bytes,
        first_party_text_files: scanPackage.inventory.first_party_text.files,
        first_party_text_bytes: scanPackage.inventory.first_party_text.bytes,
        excluded: scanPackage.inventory.excluded,
      },
      tools: scanPackage.tools.map(({ name, version, status }) => ({
        name,
        version,
        status: status === "completed-with-limitations" ? "completed" : status,
      })),
      javascript_analysis: publicJavascriptAnalysisCoverage(
        scanPackage.javascript_analysis!,
      ),
      evidence_validation: {
        status:
          metadataOnlyCandidates > 0
            ? ("completed-with-limitations" as const)
            : ("completed" as const),
        validated_candidates: candidates.length,
        ...(metadataOnlyCandidates > 0
          ? { metadata_only_candidates: metadataOnlyCandidates }
          : {}),
      },
    },
    review_coverage: input.review.coverage,
    ...(reviewReuse === undefined ? {} : { review_reuse: reviewReuse }),
    candidates,
    assessments: input.review.assessments,
    observations: input.review.observations,
    counts,
    limitations: reportLimitations(
      scanPackage,
      options.limitations,
      input.evidenceGroups,
    ),
  };
  const identity = reportIdentity({
    ...withoutIdentity,
    report_id: "0".repeat(64),
    report_digest: "0".repeat(64),
  });
  return ScanReportV5Schema.parse({
    ...withoutIdentity,
    report_id: identity,
    report_digest: identity,
  });
}
