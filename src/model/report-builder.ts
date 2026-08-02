import {
  buildFindingCountsV2,
  deriveV2Result,
  FindingV2Schema,
  type FindingV2,
} from "../contracts/reports.js";
import { ModelRequestError } from "./openai-compatible-client.js";

export function buildAutomatedReportFindings(input: readonly FindingV2[]) {
  const findings = input
    .map((finding) => FindingV2Schema.parse(finding))
    .sort((left, right) => left.fingerprint.localeCompare(right.fingerprint));
  if (
    new Set(findings.map(({ fingerprint }) => fingerprint)).size !==
    findings.length
  ) {
    throw new ModelRequestError(
      "MODEL_EVIDENCE_INVALID",
      "repository",
      "Validated model findings contain duplicate evidence identities.",
    );
  }
  if (
    findings.some(
      (finding) =>
        finding.disposition === "inconclusive" &&
        ["critical", "high", "medium"].includes(finding.severity) &&
        ["high", "medium"].includes(finding.confidence),
    )
  ) {
    throw new ModelRequestError(
      "MODEL_INVALID_RESPONSE",
      "repository",
      "Review-level findings cannot remain inconclusive.",
    );
  }
  return {
    findings,
    findingCounts: buildFindingCountsV2(findings),
    result: deriveV2Result(findings),
    evidenceValidation: {
      status: "completed" as const,
      validated_findings: findings.length,
    },
  };
}
