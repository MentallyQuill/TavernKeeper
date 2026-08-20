import {
  ReviewOpportunityAnalysisSchema,
  type ReviewOpportunityAnalysis,
} from "./review-opportunities.js";

function inlineCode(value: string) {
  const normalized = value.replace(/[\r\n]+/gu, " ");
  const longestBacktickRun = Math.max(
    0,
    ...[...normalized.matchAll(/`+/gu)].map(([run]) => run.length),
  );
  const delimiter = "`".repeat(longestBacktickRun + 1);
  const needsPadding =
    normalized.startsWith("`") ||
    normalized.endsWith("`") ||
    /^\s|\s$/u.test(normalized);
  const padding = needsPadding ? " " : "";
  return `${delimiter}${padding}${normalized}${padding}${delimiter}`;
}

function usageSummary(usage: {
  input_tokens: number;
  output_tokens: number;
  cache_read_tokens: number;
  reasoning_tokens: number;
}) {
  return (
    `${usage.input_tokens} input, ${usage.output_tokens} output, ` +
    `${usage.cache_read_tokens} cache-read, ${usage.reasoning_tokens} reasoning tokens`
  );
}

export function renderReviewOpportunitiesJson(
  analysis: ReviewOpportunityAnalysis,
) {
  const parsed = ReviewOpportunityAnalysisSchema.parse(analysis);
  return `${JSON.stringify(parsed, null, 2)}\n`;
}

export function renderReviewOpportunitiesMarkdown(
  analysis: ReviewOpportunityAnalysis,
) {
  const parsed = ReviewOpportunityAnalysisSchema.parse(analysis);
  const lines = [
    "# Contextual Review Opportunities",
    "",
    `Contextual review policy: ${inlineCode(parsed.contextual_policy_version)}`,
    "",
    "## Attribution",
    "",
    "Candidate and repository frequencies are exact. Corpus-wide provider calls and token usage are exact.",
    "",
    "Associated usage is an overlapping, non-additive report-level envelope; do not sum it or interpret it as avoided spend.",
    "",
    "Public review batches do not identify exact avoided calls or tokens for any rule.",
    "",
    "## Corpus",
    "",
    `- Indexed reports: ${parsed.corpus.indexed_reports}`,
    `- Loaded Policy 5 reports: ${parsed.corpus.loaded_reports}`,
    `- Skipped other-policy reports: ${parsed.corpus.skipped_policy_reports}`,
    `- Contextual candidates: ${parsed.corpus.contextual_candidates}`,
    `- Provider calls: ${parsed.corpus.provider_calls}`,
    `- Usage: ${usageSummary(parsed.corpus.usage)}`,
    `- Reports with unmapped contextual reuse: ${parsed.corpus.reports_with_unmapped_contextual_reuse}`,
    "",
    "## Ranked opportunities",
    "",
  ];

  if (parsed.opportunities.length === 0) {
    lines.push("No contextual-model assessments were present.", "");
  } else {
    for (const [index, opportunity] of parsed.opportunities.entries()) {
      lines.push(
        `### ${index + 1}. ${inlineCode(`${opportunity.key.origin}:${opportunity.key.rule_id}`)}`,
        "",
        `- Scanner: ${inlineCode(opportunity.key.scanner_version)}`,
        `- Execution scope: ${inlineCode(opportunity.key.execution_scope)}`,
        `- File role: ${inlineCode(opportunity.key.file_role)}`,
        `- Scanner confidence: ${inlineCode(opportunity.key.scanner_confidence)}`,
        `- Triage reason: ${inlineCode(opportunity.key.triage_reason_code)}`,
        `- Candidates: ${opportunity.candidate_count}`,
        `- Distinct repositories: ${opportunity.repository_count}`,
        `- Dispositions: expected behavior ${opportunity.outcomes.disposition.expected_behavior}; minor weakness ${opportunity.outcomes.disposition.minor_weakness}; material vulnerability ${opportunity.outcomes.disposition.material_vulnerability}; credible malicious behavior ${opportunity.outcomes.disposition.credible_malicious_behavior}`,
        `- Credible malicious behavior: ${opportunity.outcomes.disposition.credible_malicious_behavior}`,
        `- Demonstrated exposure: ${opportunity.outcomes.risk_exposure.demonstrated}`,
        `- High recommended risk: ${opportunity.outcomes.recommended_risk.high}`,
        `- Risk exposure: not demonstrated ${opportunity.outcomes.risk_exposure.not_demonstrated}; demonstrated ${opportunity.outcomes.risk_exposure.demonstrated}`,
        `- Recommended risk: low ${opportunity.outcomes.recommended_risk.low}; material ${opportunity.outcomes.recommended_risk.material}; high ${opportunity.outcomes.recommended_risk.high}`,
        `- Associated reports: ${opportunity.associated_reports.report_count}`,
        `- Associated provider calls: ${opportunity.associated_reports.provider_calls}`,
        `- Associated usage (${opportunity.associated_reports.attribution}): ${usageSummary(opportunity.associated_reports.usage)}`,
        "- Associated usage is an overlapping, non-additive report-level envelope; do not sum it or interpret it as avoided spend.",
      );
      for (const stratum of opportunity.reviewer_strata)
        lines.push(
          `- Reviewer stratum: ${inlineCode(stratum.provider)} / ${inlineCode(stratum.model)}; candidates ${stratum.candidate_count}; reports ${stratum.report_count}`,
        );
      lines.push("", "Representative references:", "");
      for (const reference of opportunity.references)
        lines.push(
          `- ${inlineCode(reference.repository)} at ${inlineCode(reference.target_sha)}: ` +
            `${inlineCode(reference.path)} ([report](${reference.report_url}))`,
        );
      lines.push("");
    }
  }

  lines.push("## Limitations", "");
  for (const limitation of parsed.limitations) lines.push(`- ${limitation}`);
  lines.push("");
  return `${lines.join("\n")}\n`;
}
