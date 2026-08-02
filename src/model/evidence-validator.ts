import type { Finding, FindingV2 } from "../contracts/reports.js";
import { FindingV2Schema } from "../contracts/reports.js";
import { ModelRequestError } from "./openai-compatible-client.js";
import type {
  ArbiterDecision,
  EvidenceReference,
  RolePolicies,
} from "./role-contracts.js";

export interface EvidenceRecord {
  finding: Finding;
  evidence: EvidenceReference;
  automatedReview: {
    analyzer_policy: string;
    challenger_policy: string;
    arbiter_policy: string;
  };
}

export type EvidenceMap = Map<string, EvidenceRecord>;

function evidenceFailure(): never {
  throw new ModelRequestError(
    "MODEL_EVIDENCE_INVALID",
    "repository",
    "The arbiter changed or invented immutable evidence.",
  );
}

function sameEvidence(left: EvidenceReference, right: EvidenceReference) {
  return (
    left.path === right.path &&
    left.line_start === right.line_start &&
    left.line_end === right.line_end &&
    left.segment_id === right.segment_id &&
    left.content_digest === right.content_digest &&
    left.target_sha === right.target_sha
  );
}

export function automatedReviewMetadata(policies: RolePolicies) {
  return {
    analyzer_policy: policies.analyzer,
    challenger_policy: policies.challenger,
    arbiter_policy: policies.arbiter,
  };
}

export function validateArbiterDecision(
  decision: ArbiterDecision,
  evidenceMap: EvidenceMap,
  targetSha: string,
): FindingV2 {
  const record = evidenceMap.get(decision.fingerprint);
  if (
    record === undefined ||
    decision.fingerprint !== record.finding.fingerprint ||
    decision.evidence.target_sha !== targetSha ||
    record.evidence.target_sha !== targetSha ||
    !sameEvidence(decision.evidence, record.evidence) ||
    record.finding.path !== record.evidence.path ||
    record.finding.line_start !== record.evidence.line_start ||
    record.finding.line_end !== record.evidence.line_end
  ) {
    evidenceFailure();
  }

  const {
    adjudication: _adjudication,
    disposition: _disposition,
    ...finding
  } = record.finding;
  return FindingV2Schema.parse({
    ...finding,
    disposition: decision.disposition,
    automated_review: record.automatedReview,
  });
}
