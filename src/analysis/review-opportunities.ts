import { z } from "zod";

import {
  ReportIndexV5Schema,
  ScanReportV5Schema,
  type ReportIndexEntryV5,
  type ScanReportV5,
} from "../contracts/reports-v5.js";

const CountSchema = z.number().int().nonnegative();
const UsageSchema = z.strictObject({
  input_tokens: CountSchema,
  output_tokens: CountSchema,
  cache_read_tokens: CountSchema,
  reasoning_tokens: CountSchema,
});

const OpportunityKeySchema = z.strictObject({
  origin: z.string().min(1),
  rule_id: z.string().min(1),
  scanner_version: z.string().min(1),
  execution_scope: z.string().min(1),
  file_role: z.string().min(1),
  scanner_confidence: z.enum(["low", "medium", "high"]),
  triage_reason_code: z.string().min(1),
});

const OutcomeCountsSchema = z.strictObject({
  disposition: z.strictObject({
    expected_behavior: CountSchema,
    minor_weakness: CountSchema,
    material_vulnerability: CountSchema,
    credible_malicious_behavior: CountSchema,
  }),
  risk_exposure: z.strictObject({
    not_demonstrated: CountSchema,
    demonstrated: CountSchema,
  }),
  recommended_risk: z.strictObject({
    low: CountSchema,
    material: CountSchema,
    high: CountSchema,
  }),
});

const OpportunityReferenceSchema = z.strictObject({
  repository: z.string().min(1),
  repository_id: z.number().int().positive(),
  target_sha: z.string().regex(/^[0-9a-f]{40}$/u),
  report_id: z.string().regex(/^[0-9a-f]{64}$/u),
  report_url: z.url(),
  candidate_id: z.string().regex(/^[0-9a-f]{64}$/u),
  path: z.string().min(1),
});

const ReviewerStratumSchema = z.strictObject({
  provider: z.string().min(1),
  model: z.string().min(1),
  candidate_count: CountSchema,
  report_count: CountSchema,
});

const ReviewOpportunitySchema = z.strictObject({
  key: OpportunityKeySchema,
  candidate_count: CountSchema,
  repository_count: CountSchema,
  outcomes: OutcomeCountsSchema,
  associated_reports: z.strictObject({
    attribution: z.literal("overlapping-non-additive"),
    report_count: CountSchema,
    provider_calls: CountSchema,
    usage: UsageSchema,
  }),
  reviewer_strata: z.array(ReviewerStratumSchema),
  references: z.array(OpportunityReferenceSchema),
});

export const ReviewOpportunityAnalysisSchema = z.strictObject({
  schema_version: z.literal(1),
  contextual_policy_version: z.literal("5"),
  attribution: z.strictObject({
    candidate_counts: z.literal("exact"),
    corpus_usage: z.literal("exact"),
    associated_usage: z.literal("overlapping-non-additive"),
    per_rule_savings: z.literal("not-attributable"),
  }),
  corpus: z.strictObject({
    indexed_reports: CountSchema,
    loaded_reports: CountSchema,
    skipped_policy_reports: CountSchema,
    contextual_candidates: CountSchema,
    provider_calls: CountSchema,
    usage: UsageSchema,
    reports_with_unmapped_contextual_reuse: CountSchema,
  }),
  opportunities: z.array(ReviewOpportunitySchema),
  limitations: z.array(z.string().min(1)),
});

export type ReviewOpportunityAnalysis = z.infer<
  typeof ReviewOpportunityAnalysisSchema
>;
export type ReviewOpportunity = z.infer<typeof ReviewOpportunitySchema>;

type Usage = z.infer<typeof UsageSchema>;
type OpportunityKey = z.infer<typeof OpportunityKeySchema>;
type Outcomes = z.infer<typeof OutcomeCountsSchema>;
type OpportunityReference = z.infer<typeof OpportunityReferenceSchema>;

type AssociatedReport = {
  providerCalls: number;
  usage: Usage;
};

type ReviewerStratumAccumulator = {
  provider: string;
  model: string;
  candidateCount: number;
  reportIds: Set<string>;
};

type OpportunityAccumulator = {
  key: OpportunityKey;
  candidateCount: number;
  repositoryIds: Set<number>;
  outcomes: Outcomes;
  associatedReports: Map<string, AssociatedReport>;
  reviewerStrata: Map<string, ReviewerStratumAccumulator>;
  references: OpportunityReference[];
};

const identityFields = [
  "report_id",
  "report_digest",
  "report_version",
  "supersedes_report_id",
  "scanner_version",
  "scanner_policy_version",
  "rule_catalog_version",
  "package_schema_version",
  "contextual_review_policy_version",
  "ecosystem_context_version",
  "prompt_version",
  "assessment_schema_version",
  "source_id",
  "provider",
  "repository_id",
  "repository",
  "target_sha",
  "completed_at",
  "assessment_method",
] as const satisfies readonly (keyof ReportIndexEntryV5 & keyof ScanReportV5)[];

function emptyUsage(): Usage {
  return {
    input_tokens: 0,
    output_tokens: 0,
    cache_read_tokens: 0,
    reasoning_tokens: 0,
  };
}

function addUsage(target: Usage, source: Usage) {
  target.input_tokens += source.input_tokens;
  target.output_tokens += source.output_tokens;
  target.cache_read_tokens += source.cache_read_tokens;
  target.reasoning_tokens += source.reasoning_tokens;
}

function emptyOutcomes(): Outcomes {
  return {
    disposition: {
      expected_behavior: 0,
      minor_weakness: 0,
      material_vulnerability: 0,
      credible_malicious_behavior: 0,
    },
    risk_exposure: { not_demonstrated: 0, demonstrated: 0 },
    recommended_risk: { low: 0, material: 0, high: 0 },
  };
}

function compareStrings(left: string, right: string) {
  return left < right ? -1 : left > right ? 1 : 0;
}

function opportunityIdentity(key: OpportunityKey) {
  return JSON.stringify([
    key.origin,
    key.rule_id,
    key.scanner_version,
    key.execution_scope,
    key.file_role,
    key.scanner_confidence,
    key.triage_reason_code,
  ]);
}

function compareReferences(
  left: OpportunityReference,
  right: OpportunityReference,
) {
  return (
    compareStrings(left.repository, right.repository) ||
    left.repository_id - right.repository_id ||
    compareStrings(left.target_sha, right.target_sha) ||
    compareStrings(left.report_id, right.report_id) ||
    compareStrings(left.candidate_id, right.candidate_id) ||
    compareStrings(left.path, right.path)
  );
}

function addBoundedReference(
  references: OpportunityReference[],
  reference: OpportunityReference,
  maximumReferences: number,
) {
  references.push(reference);
  references.sort(compareReferences);
  if (references.length > maximumReferences) references.pop();
}

function verifyPreferredIdentity(
  entry: ReportIndexEntryV5,
  report: ScanReportV5,
) {
  const mismatch = identityFields.find(
    (field) => entry[field] !== report[field],
  );
  if (mismatch !== undefined)
    throw new Error(
      `Report identity does not match its preferred index entry: ${mismatch}`,
    );
}

function reportProviderCalls(report: ScanReportV5) {
  return report.review_triage?.model_budget.actual.provider_calls ?? 0;
}

export async function analyzeReviewOpportunities(input: {
  index: unknown;
  loadReport: (entry: ReportIndexEntryV5) => Promise<unknown>;
  contextualPolicyVersion?: "5";
  maxReferencesPerOpportunity?: number;
}): Promise<ReviewOpportunityAnalysis> {
  const index = ReportIndexV5Schema.parse(input.index);
  const contextualPolicyVersion = input.contextualPolicyVersion ?? "5";
  const maximumReferences = z
    .number()
    .int()
    .min(1)
    .max(100)
    .parse(input.maxReferencesPerOpportunity ?? 5);
  const corpusUsage = emptyUsage();
  const opportunities = new Map<string, OpportunityAccumulator>();
  let loadedReports = 0;
  let skippedPolicyReports = 0;
  let contextualCandidates = 0;
  let providerCalls = 0;
  let reportsWithUnmappedContextualReuse = 0;

  for (const entry of index.reports) {
    if (
      entry.scanner_policy_version !== contextualPolicyVersion ||
      entry.contextual_review_policy_version !== contextualPolicyVersion
    ) {
      skippedPolicyReports += 1;
      continue;
    }

    const report = ScanReportV5Schema.parse(await input.loadReport(entry));
    verifyPreferredIdentity(entry, report);
    loadedReports += 1;
    providerCalls += reportProviderCalls(report);
    addUsage(corpusUsage, report.review_usage);
    if ((report.review_triage?.candidates.reused_contextual ?? 0) > 0)
      reportsWithUnmappedContextualReuse += 1;

    const candidatesById = new Map(
      report.candidates.map((candidate) => [candidate.candidate_id, candidate]),
    );
    for (const assessment of report.assessments) {
      if (
        !("assessment_source" in assessment) ||
        assessment.assessment_source !== "contextual-model"
      )
        continue;
      const candidate = candidatesById.get(assessment.candidate_id);
      if (candidate === undefined)
        throw new Error(
          `Contextual assessment has no candidate: ${assessment.candidate_id}`,
        );
      const reviewer = report.contextual_reviewer;
      if (reviewer === undefined)
        throw new Error(
          `Contextual assessment has no reviewer identity: ${assessment.candidate_id}`,
        );

      contextualCandidates += 1;
      const key: OpportunityKey = {
        origin: candidate.origin,
        rule_id: candidate.rule_id,
        scanner_version: candidate.scanner_version,
        execution_scope: candidate.execution_scope ?? "unknown",
        file_role: candidate.file_role,
        scanner_confidence: candidate.scanner_confidence,
        triage_reason_code: assessment.triage_reason_code,
      };
      const identity = opportunityIdentity(key);
      let opportunity = opportunities.get(identity);
      if (opportunity === undefined) {
        opportunity = {
          key,
          candidateCount: 0,
          repositoryIds: new Set<number>(),
          outcomes: emptyOutcomes(),
          associatedReports: new Map<string, AssociatedReport>(),
          reviewerStrata: new Map<string, ReviewerStratumAccumulator>(),
          references: [],
        };
        opportunities.set(identity, opportunity);
      }

      opportunity.candidateCount += 1;
      opportunity.repositoryIds.add(report.repository_id);
      opportunity.outcomes.disposition[assessment.disposition] += 1;
      opportunity.outcomes.risk_exposure[assessment.risk_exposure] += 1;
      opportunity.outcomes.recommended_risk[assessment.recommended_risk] += 1;
      if (!opportunity.associatedReports.has(report.report_id))
        opportunity.associatedReports.set(report.report_id, {
          providerCalls: reportProviderCalls(report),
          usage: { ...report.review_usage },
        });
      const reviewerIdentity = JSON.stringify([
        reviewer.provider,
        reviewer.model,
      ]);
      let reviewerStratum = opportunity.reviewerStrata.get(reviewerIdentity);
      if (reviewerStratum === undefined) {
        reviewerStratum = {
          provider: reviewer.provider,
          model: reviewer.model,
          candidateCount: 0,
          reportIds: new Set<string>(),
        };
        opportunity.reviewerStrata.set(reviewerIdentity, reviewerStratum);
      }
      reviewerStratum.candidateCount += 1;
      reviewerStratum.reportIds.add(report.report_id);
      addBoundedReference(
        opportunity.references,
        {
          repository: report.repository,
          repository_id: report.repository_id,
          target_sha: report.target_sha,
          report_id: report.report_id,
          report_url: entry.report_url,
          candidate_id: candidate.candidate_id,
          path: candidate.path,
        },
        maximumReferences,
      );
    }
  }

  const renderedOpportunities = [...opportunities.values()]
    .map((opportunity): ReviewOpportunity => {
      const associatedUsage = emptyUsage();
      let associatedProviderCalls = 0;
      for (const report of opportunity.associatedReports.values()) {
        associatedProviderCalls += report.providerCalls;
        addUsage(associatedUsage, report.usage);
      }
      return {
        key: opportunity.key,
        candidate_count: opportunity.candidateCount,
        repository_count: opportunity.repositoryIds.size,
        outcomes: opportunity.outcomes,
        associated_reports: {
          attribution: "overlapping-non-additive",
          report_count: opportunity.associatedReports.size,
          provider_calls: associatedProviderCalls,
          usage: associatedUsage,
        },
        reviewer_strata: [...opportunity.reviewerStrata.values()]
          .sort(
            (left, right) =>
              compareStrings(left.provider, right.provider) ||
              compareStrings(left.model, right.model),
          )
          .map((stratum) => ({
            provider: stratum.provider,
            model: stratum.model,
            candidate_count: stratum.candidateCount,
            report_count: stratum.reportIds.size,
          })),
        references: opportunity.references,
      };
    })
    .sort(
      (left, right) =>
        right.candidate_count - left.candidate_count ||
        right.repository_count - left.repository_count ||
        compareStrings(
          opportunityIdentity(left.key),
          opportunityIdentity(right.key),
        ),
    );

  const limitations = [
    "Public review batches do not bind provider calls or tokens to individual candidates.",
    "Opportunity-associated calls and token usage are overlapping report-level envelopes and are not additive.",
  ];
  if (reportsWithUnmappedContextualReuse > 0)
    limitations.push(
      "Public reports do not map reused contextual assessments to individual candidates.",
    );

  return ReviewOpportunityAnalysisSchema.parse({
    schema_version: 1,
    contextual_policy_version: "5",
    attribution: {
      candidate_counts: "exact",
      corpus_usage: "exact",
      associated_usage: "overlapping-non-additive",
      per_rule_savings: "not-attributable",
    },
    corpus: {
      indexed_reports: index.reports.length,
      loaded_reports: loadedReports,
      skipped_policy_reports: skippedPolicyReports,
      contextual_candidates: contextualCandidates,
      provider_calls: providerCalls,
      usage: corpusUsage,
      reports_with_unmapped_contextual_reuse:
        reportsWithUnmappedContextualReuse,
    },
    opportunities: renderedOpportunities,
    limitations,
  });
}
