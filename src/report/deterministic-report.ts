import { createHash } from "node:crypto";

import {
  buildFindingCountsV4,
  DeterministicSummarySchema,
  ScanReportV4Schema,
  type FindingV4,
  type ScanReportV4,
} from "../contracts/reports.js";
import {
  validateScanPackageEvidence,
  type ScanPackageV1,
} from "../contracts/scan-package.js";
import {
  classifyFinding,
  describeFinding,
  RULE_CATALOG_VERSION,
} from "../policy/rule-descriptions.js";

export interface DeterministicReportOptions {
  targetSha: string;
  completedAt: string;
  reportVersion: number;
  supersedesReportId: string | null;
}

function canonicalValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (value !== null && typeof value === "object")
    return Object.fromEntries(
      Object.entries(value)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, nested]) => [key, canonicalValue(nested)]),
    );
  return value;
}

function reportDigest(report: Omit<ScanReportV4, "report_id">) {
  return createHash("sha256")
    .update(JSON.stringify(canonicalValue(report)))
    .digest("hex");
}

function assertSafeGeneratedText(value: string) {
  if (
    value !== value.trim() ||
    /[\u0000-\u001f\u007f-\u009f\u202a-\u202e\u2066-\u2069<>]/u.test(value)
  )
    throw new Error("deterministic report text is unsafe");
}

function publicFinding(finding: ScanPackageV1["findings"][number]): FindingV4 {
  const description = describeFinding(finding);
  for (const value of Object.values(description))
    assertSafeGeneratedText(value);
  return {
    origin: finding.origin,
    rule_id: finding.rule_id,
    category: finding.category,
    severity: finding.severity,
    confidence: finding.confidence,
    policy_status: classifyFinding(finding),
    path: finding.path,
    line_start: finding.line_start,
    line_end: finding.line_end,
    evidence_sha: finding.evidence_sha,
    title: description.title,
    explanation: description.explanation,
    remediation: description.remediation,
    fingerprint: finding.fingerprint,
  };
}

function deterministicSummary(reportable: number) {
  const summary =
    reportable === 0
      ? {
          headline: "No reportable concerns detected",
          detail:
            "All required scanners completed at this commit, and no finding met TavernKeeper's reportable threshold.",
        }
      : {
          headline: "Reportable concerns detected",
          detail: `${reportable} reportable ${reportable === 1 ? "concern" : "concerns"} met TavernKeeper's severity and confidence threshold. Review the finding details before installing this project.`,
        };
  for (const value of Object.values(summary)) assertSafeGeneratedText(value);
  return DeterministicSummarySchema.parse(summary);
}

export function buildDeterministicReport(
  input: unknown,
  options: DeterministicReportOptions,
): ScanReportV4 {
  const scanPackage = validateScanPackageEvidence(input);
  if (scanPackage.target.target_sha !== options.targetSha)
    throw new Error(
      "Report target SHA must match the Scan Package target SHA.",
    );
  if (scanPackage.scanner_policy_version !== "2")
    throw new Error("Deterministic reports require scanner policy version 2.");
  if (scanPackage.rule_catalog_version !== RULE_CATALOG_VERSION)
    throw new Error("Scan Package rule catalog version is not supported.");

  const findings = scanPackage.findings.map(publicFinding);
  const findingCounts = buildFindingCountsV4(findings);
  const withoutReportId: Omit<ScanReportV4, "report_id"> = {
    schema_version: 4,
    report_version: options.reportVersion,
    supersedes_report_id: options.supersedesReportId,
    scanner_version: scanPackage.scanner_version,
    scanner_policy_version: scanPackage.scanner_policy_version,
    rule_catalog_version: scanPackage.rule_catalog_version,
    package_schema_version: scanPackage.schema_version,
    source_id: scanPackage.target.source_id,
    provider: scanPackage.target.provider,
    repository_id: scanPackage.target.repository_id,
    repository: scanPackage.target.repository,
    canonical_url: scanPackage.target.canonical_url,
    target_sha: scanPackage.target.target_sha,
    completed_at: options.completedAt,
    assessment_method: "deterministic-static-analysis",
    history: scanPackage.history,
    coverage: {
      inventory: {
        files: scanPackage.inventory.totals.files,
        bytes: scanPackage.inventory.totals.bytes,
        first_party_text_files: scanPackage.inventory.first_party_text.files,
        first_party_text_bytes: scanPackage.inventory.first_party_text.bytes,
        excluded: scanPackage.inventory.excluded,
      },
      tools: scanPackage.tools,
      evidence_validation: {
        status: "completed",
        validated_findings: scanPackage.evidence_validation.findings,
      },
    },
    result: findingCounts.reportable > 0 ? "red" : "teal",
    summary: deterministicSummary(findingCounts.reportable),
    finding_counts: findingCounts,
    findings,
  };
  return ScanReportV4Schema.parse({
    ...withoutReportId,
    report_id: reportDigest(withoutReportId),
  });
}
