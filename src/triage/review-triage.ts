import { createHash } from "node:crypto";

import { z } from "zod";

import type {
  EvidenceCandidate,
  EvidenceContextGroup,
} from "../context/evidence-context.js";
import {
  ContextualAssessmentSchema,
  type ContextualAssessment,
} from "../model/contextual-review-contract.js";
import { ownedRuleTriage } from "../policy/rule-descriptions.js";

export const AssessmentSourceSchema = z.enum([
  "deterministic-policy",
  "contextual-model",
]);

export const TriageReasonCodeSchema = z
  .string()
  .regex(/^[a-z0-9]+(?:-[a-z0-9]+)*$/u)
  .max(80);

export const TriageDecisionSchema = z.strictObject({
  candidate_id: z.string().regex(/^[0-9a-f]{64}$/u),
  case_id: z.string().regex(/^[0-9a-f]{64}$/u),
  destination: z.enum(["deterministic", "contextual"]),
  reason_code: TriageReasonCodeSchema,
});

export type TriageDecision = z.infer<typeof TriageDecisionSchema>;
export type DeterministicAssessment = ContextualAssessment;

export interface ReviewTriagePlan {
  deterministicAssessments: DeterministicAssessment[];
  contextualGroups: EvidenceContextGroup[];
  decisions: TriageDecision[];
  counts: {
    cases: { total: number; contextual: number };
    candidates: { total: number; deterministic: number; contextual: number };
    reasons: Array<{ reason_code: string; count: number }>;
  };
}

const hardEscalatorRules = new Set([
  "credential-exfiltration",
  "network-install-hook",
  "javascript.credential-to-network",
  "javascript.download-to-execution",
  "javascript.correlated.download-to-execution",
]);

function isHardEscalator(ruleId: string) {
  return (
    ownedRuleTriage(ruleId) === "correlation-only" ||
    hardEscalatorRules.has(ruleId) ||
    /(?:credential|environment).*(?:exfiltration|network)|(?:download|decode)-to-execution|install.*network|persistence/iu.test(
      ruleId,
    )
  );
}

function hasDangerousCorrelation(group: EvidenceContextGroup) {
  if (
    ["tooling-only", "test-documentation-data"].includes(group.execution_scope)
  )
    return false;
  const dynamicExecution = group.candidates.some(({ rule_id, category }) =>
    /(?:dynamic-execution|code-execution|unsafe-(?:stmt|command|vm))/iu.test(
      `${rule_id} ${category}`,
    ),
  );
  const boundarySignal = group.candidates.some(({ rule_id, category }) =>
    /(?:network|credential|serialize-environment|data-exfiltration|persistence)/iu.test(
      `${rule_id} ${category}`,
    ),
  );
  return dynamicExecution && boundarySignal;
}

function behaviorCaseId(
  group: EvidenceContextGroup,
  candidateIds: readonly string[],
) {
  return createHash("sha256")
    .update(
      [
        "review-case-v1",
        group.repository,
        group.path,
        group.execution_scope,
        ...[...candidateIds].sort(),
      ].join("\0"),
    )
    .digest("hex");
}

function reasonCounts(decisions: readonly TriageDecision[]) {
  const counts = new Map<string, number>();
  for (const decision of decisions)
    counts.set(
      decision.reason_code,
      (counts.get(decision.reason_code) ?? 0) + 1,
    );
  return [...counts]
    .sort(([left], [right]) => left.localeCompare(right))
    .map(([reason_code, count]) => ({ reason_code, count }));
}

function candidateLocation(
  group: EvidenceContextGroup,
  candidate: EvidenceCandidate,
) {
  const fallback =
    [
      ...group.context.imports.matchAll(/^\s*([1-9][0-9]*)\s+\|/gmu),
      ...group.context.source.matchAll(/^\s*([1-9][0-9]*)\s+\|/gmu),
    ]
      .map((match) => Number.parseInt(match[1]!, 10))
      .sort((left, right) => left - right)[0] ?? 1;
  const lineStart = candidate.line_start ?? fallback;
  const lineEnd = candidate.line_end ?? lineStart;
  return [{ path: group.path, line_start: lineStart, line_end: lineEnd }];
}

function deterministicAssessment(
  group: EvidenceContextGroup,
  candidate: EvidenceCandidate,
  kind:
    | "expected"
    | "expected-decoded"
    | "minor-regex"
    | "minor-local"
    | "structured-weakness"
    | "advisory",
) {
  const common = {
    candidate_id: candidate.candidate_id,
    evidence_ids: [candidate.evidence_id],
    risk_exposure: "not_demonstrated" as const,
    recommended_risk: "low" as const,
    locations: candidateLocation(group, candidate),
  };
  if (kind === "expected")
    return ContextualAssessmentSchema.parse({
      ...common,
      disposition: "expected_behavior",
      impact: "none",
      exploitability: "unlikely",
      confidence: "high",
      technical_explanation:
        "The scanner evidence is confined to a proven non-runtime scope and does not demonstrate user harm.",
      layman_explanation:
        "This technical signal is not part of the shipped runtime behavior.",
      developer_action: "none",
    });
  if (kind === "expected-decoded")
    return ContextualAssessmentSchema.parse({
      ...common,
      disposition: "expected_behavior",
      impact: "none",
      exploitability: "unlikely",
      confidence: "high",
      technical_explanation:
        "Bounded analysis decoded the literal, and the derived representation contains no execution, network, persistence, credential, or unresolved signal.",
      layman_explanation:
        "The encoded value was inspected and did not reveal dangerous behavior.",
      developer_action: "none",
    });
  if (kind === "minor-regex")
    return ContextualAssessmentSchema.parse({
      ...common,
      disposition: "minor_weakness",
      impact: "low",
      exploitability: "plausible",
      confidence: "medium",
      technical_explanation:
        "The expression may permit a local CPU slowdown, but this evidence shows no credential, persistence, code-execution, or cross-user impact.",
      layman_explanation:
        "A crafted input might briefly slow or freeze the local client, without showing broader security harm.",
      developer_action:
        "Bound the input length or replace the expression when practical.",
    });
  if (kind === "minor-local")
    return ContextualAssessmentSchema.parse({
      ...common,
      disposition: "minor_weakness",
      impact: "low",
      exploitability: "unlikely",
      confidence: "medium",
      technical_explanation:
        "The finding may cause a local performance or robustness problem, without showing credential, persistence, code-execution, or cross-user impact.",
      layman_explanation:
        "This may make a local operation slower or less reliable, but it does not show broader security harm.",
      developer_action:
        "Move the operation out of hot paths or reduce unnecessary work when practical.",
    });
  const impact =
    candidate.scanner_severity === "critical"
      ? "critical"
      : candidate.scanner_severity === "high"
        ? "high"
        : candidate.scanner_severity === "medium"
          ? "medium"
          : "low";
  if (kind === "structured-weakness")
    return ContextualAssessmentSchema.parse({
      ...common,
      disposition: "material_vulnerability",
      impact,
      exploitability: "plausible",
      confidence: candidate.scanner_confidence,
      technical_explanation:
        "The scanner identified a bounded implementation weakness, but this evidence does not demonstrate attacker reachability or concrete user harm.",
      layman_explanation:
        "The code has a known weakness, though this scan does not show that anyone can exploit it here.",
      developer_action:
        "Replace or constrain the flagged primitive when practical.",
    });
  return ContextualAssessmentSchema.parse({
    ...common,
    disposition: "material_vulnerability",
    impact,
    exploitability: "unlikely",
    confidence: candidate.scanner_confidence,
    technical_explanation:
      "The installed dependency version matches a structured advisory, but the advisory match alone does not demonstrate reachable exploitation in this project.",
    layman_explanation:
      "A dependency has a published security issue, though this scan does not show that the project exposes it to an attacker.",
    developer_action:
      "Update or replace the affected dependency when a fixed version is available.",
  });
}

type CandidateTriage =
  | {
      destination: "deterministic";
      reasonCode: string;
      assessment: DeterministicAssessment;
    }
  | { destination: "contextual"; reasonCode: string };

const xrayRuntimeLowRules = new Set([
  "javascript.xray.synchronous-io",
  "javascript.xray.log-usage",
]);
const xrayStructuredWeaknessRules = new Set([
  "javascript.xray.crypto.weak-algorithm",
  "javascript.xray.crypto.weak-scrypt",
  "javascript.xray.crypto.unsafe-prehash",
  "javascript.xray.crypto.weak-bcrypt",
  "javascript.xray.crypto.password-shucking",
  "javascript.xray.sql-injection",
  "javascript.xray.monkey-patch",
  "javascript.xray.prototype-pollution",
]);
const xrayAmbiguousRules = new Set([
  "javascript.xray.unsafe-stmt",
  "javascript.xray.short-identifiers",
  "javascript.xray.suspicious-literal",
  "javascript.xray.suspicious-file",
  "javascript.xray.obfuscated-code",
  "javascript.xray.shady-link",
  "javascript.xray.unsafe-command",
  "javascript.xray.unsafe-import",
  "javascript.xray.serialize-environment",
  "javascript.xray.data-exfiltration",
  "javascript.xray.unsafe-vm-context",
]);
const knownZizmorRules = new Set([
  "template-injection",
  "excessive-permissions",
  "unpinned-uses",
  "dangerous-triggers",
  "cache-poisoning",
  "github-env",
]);

function encodedLiteralHasDangerousCompanion(group: EvidenceContextGroup) {
  return group.candidates.some(
    ({ rule_id, category }) =>
      rule_id !== "javascript.xray.encoded-literal" &&
      (/(?:execution|network|persistence|credential|exfiltration|unsafe-stmt|unsafe-command|unsafe-vm)/iu.test(
        `${rule_id} ${category}`,
      ) ||
        !rule_id.startsWith("javascript.xray.")),
  );
}

function triageCandidate(
  group: EvidenceContextGroup,
  candidate: EvidenceCandidate,
): CandidateTriage {
  const inert = ["tooling-only", "test-documentation-data"].includes(
    group.execution_scope,
  );
  if (candidate.origin === "gitleaks") {
    const placeholder =
      inert &&
      /\b(?:example|placeholder|dummy|fake|not-a-real|fixture)\b/iu.test(
        `${group.context.imports}\n${group.context.source}`,
      );
    return placeholder
      ? {
          destination: "deterministic",
          reasonCode: "gitleaks-inert-placeholder",
          assessment: deterministicAssessment(group, candidate, "expected"),
        }
      : {
          destination: "contextual",
          reasonCode: "gitleaks-credential-ambiguity",
        };
  }
  if (candidate.origin === "osv-scanner")
    return {
      destination: "deterministic",
      reasonCode: "osv-structured-advisory",
      assessment: deterministicAssessment(group, candidate, "advisory"),
    };
  if (candidate.origin === "zizmor")
    return knownZizmorRules.has(candidate.rule_id)
      ? {
          destination: "deterministic",
          reasonCode: "zizmor-known-workflow-rule",
          assessment: deterministicAssessment(
            group,
            candidate,
            "structured-weakness",
          ),
        }
      : { destination: "contextual", reasonCode: "unknown-rule" };
  if (candidate.origin === "malcontent")
    return inert
      ? {
          destination: "deterministic",
          reasonCode: "malcontent-inert-asset",
          assessment: deterministicAssessment(group, candidate, "expected"),
        }
      : {
          destination: "contextual",
          reasonCode: "malcontent-runtime-capability",
        };
  const ownedBehavior = ownedRuleTriage(candidate.rule_id);
  if (ownedBehavior === "deterministic")
    return {
      destination: "deterministic",
      reasonCode: "owned-structured-weakness",
      assessment: deterministicAssessment(
        group,
        candidate,
        "structured-weakness",
      ),
    };
  if (ownedBehavior === "contextual")
    return inert
      ? {
          destination: "deterministic",
          reasonCode: "owned-inert-tooling",
          assessment: deterministicAssessment(group, candidate, "expected"),
        }
      : {
          destination: "contextual",
          reasonCode: "owned-context-dependent-rule",
        };
  if (candidate.rule_id === "javascript.xray.unsafe-regex")
    return {
      destination: "deterministic",
      reasonCode: inert
        ? "javascript-unsafe-regex-inert"
        : "javascript-unsafe-regex-runtime-low",
      assessment: deterministicAssessment(
        group,
        candidate,
        inert ? "expected" : "minor-regex",
      ),
    };
  if (candidate.rule_id === "javascript.xray.encoded-literal") {
    const decoded = group.context.representations.some(
      ({ stage }) => stage === "decoded",
    );
    return decoded && !encodedLiteralHasDangerousCompanion(group)
      ? {
          destination: "deterministic",
          reasonCode: "javascript-encoded-literal-decoded",
          assessment: deterministicAssessment(
            group,
            candidate,
            "expected-decoded",
          ),
        }
      : {
          destination: "contextual",
          reasonCode: decoded
            ? "javascript-encoded-literal-correlated"
            : "javascript-encoded-literal-unresolved",
        };
  }
  if (
    xrayRuntimeLowRules.has(candidate.rule_id) ||
    xrayStructuredWeaknessRules.has(candidate.rule_id) ||
    xrayAmbiguousRules.has(candidate.rule_id)
  ) {
    if (inert)
      return {
        destination: "deterministic",
        reasonCode:
          group.execution_scope === "tooling-only"
            ? "javascript-xray-inert-tooling"
            : "javascript-xray-inert-content",
        assessment: deterministicAssessment(group, candidate, "expected"),
      };
    if (xrayRuntimeLowRules.has(candidate.rule_id))
      return {
        destination: "deterministic",
        reasonCode: "javascript-xray-runtime-low",
        assessment: deterministicAssessment(group, candidate, "minor-local"),
      };
    if (xrayStructuredWeaknessRules.has(candidate.rule_id))
      return {
        destination: "deterministic",
        reasonCode: "javascript-xray-structured-weakness",
        assessment: deterministicAssessment(
          group,
          candidate,
          "structured-weakness",
        ),
      };
  }
  if (
    [
      "javascript.xray.serialize-environment",
      "javascript.xray.data-exfiltration",
    ].includes(candidate.rule_id)
  )
    return inert
      ? {
          destination: "deterministic",
          reasonCode:
            group.execution_scope === "tooling-only"
              ? "javascript-xray-inert-tooling"
              : "javascript-xray-inert-content",
          assessment: deterministicAssessment(group, candidate, "expected"),
        }
      : {
          destination: "contextual",
          reasonCode: "runtime-cross-boundary-signal",
        };
  if (candidate.rule_id === "javascript.xray.shady-link")
    return inert
      ? {
          destination: "deterministic",
          reasonCode:
            group.execution_scope === "tooling-only"
              ? "javascript-xray-inert-tooling"
              : "javascript-xray-inert-content",
          assessment: deterministicAssessment(group, candidate, "expected"),
        }
      : {
          destination: "contextual",
          reasonCode: "runtime-network-destination",
        };
  if (xrayAmbiguousRules.has(candidate.rule_id))
    return {
      destination: "contextual",
      reasonCode: "runtime-ambiguous-signal",
    };
  return { destination: "contextual", reasonCode: "unknown-rule" };
}

export function triageEvidenceGroups(
  groups: readonly EvidenceContextGroup[],
): ReviewTriagePlan {
  const deterministicAssessments: DeterministicAssessment[] = [];
  const contextualGroups: EvidenceContextGroup[] = [];
  const decisions: TriageDecision[] = [];

  for (const group of groups) {
    const caseId = behaviorCaseId(
      group,
      group.candidates.map(({ candidate_id }) => candidate_id),
    );
    const hardEscalator =
      group.candidates.some(({ rule_id }) => isHardEscalator(rule_id)) ||
      hasDangerousCorrelation(group);
    if (hardEscalator || group.execution_scope === "unknown") {
      const reasonCode = hardEscalator
        ? "hard-dangerous-correlation"
        : "unknown-execution-scope";
      contextualGroups.push({ ...group, group_id: caseId });
      for (const candidate of group.candidates)
        decisions.push(
          TriageDecisionSchema.parse({
            candidate_id: candidate.candidate_id,
            case_id: caseId,
            destination: "contextual",
            reason_code: reasonCode,
          }),
        );
      continue;
    }

    const contextualCandidates = [];
    for (const candidate of group.candidates) {
      const triage = triageCandidate(group, candidate);
      decisions.push(
        TriageDecisionSchema.parse({
          candidate_id: candidate.candidate_id,
          case_id: caseId,
          destination: triage.destination,
          reason_code: triage.reasonCode,
        }),
      );
      if (triage.destination === "deterministic")
        deterministicAssessments.push(triage.assessment);
      else contextualCandidates.push(candidate);
    }
    if (contextualCandidates.length > 0)
      contextualGroups.push({
        ...group,
        group_id: caseId,
        candidates: contextualCandidates,
      });
  }

  const contextualCandidates = decisions.filter(
    ({ destination }) => destination === "contextual",
  ).length;

  return {
    deterministicAssessments,
    contextualGroups,
    decisions,
    counts: {
      cases: { total: groups.length, contextual: contextualGroups.length },
      candidates: {
        total: decisions.length,
        deterministic: deterministicAssessments.length,
        contextual: contextualCandidates,
      },
      reasons: reasonCounts(decisions),
    },
  };
}
