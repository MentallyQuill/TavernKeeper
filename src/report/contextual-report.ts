import type {
  EvidenceContextGroup,
  FileRole,
} from "../context/evidence-context.js";
import {
  buildContextualCountsV5,
  INCOMPLETE_JAVASCRIPT_LIMITATION,
  publicJavascriptAnalysisCoverage,
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
  describeFinding,
  RULE_CATALOG_VERSION,
} from "../policy/rule-descriptions.js";
import { reportIdentity } from "../publish/report-path.js";

export interface ContextualReportInput {
  scanPackage: unknown;
  review: CompletedContextualReview;
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
  return [
    ...new Set([
      ...configured,
      ...scannerLimitations,
      ...javascriptLimitations,
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
    scanPackage.scanner_policy_version !== "4" ||
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
    contextual_reviewer: {
      provider: input.review.provider,
      model: input.review.model,
    },
    review_usage: {
      input_tokens: input.review.usage.inputTokens,
      output_tokens: input.review.usage.outputTokens,
      cache_read_tokens: input.review.usage.cacheReadTokens,
      reasoning_tokens: input.review.usage.reasoningTokens,
    },
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
        status: "completed" as const,
        validated_candidates: candidates.length,
      },
    },
    review_coverage: input.review.coverage,
    candidates,
    assessments: input.review.assessments,
    observations: input.review.observations,
    counts,
    limitations: reportLimitations(scanPackage, options.limitations),
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
