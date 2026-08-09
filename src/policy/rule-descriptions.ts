import type { Confidence, Severity } from "../contracts/reports.js";

export const RULE_CATALOG_VERSION = "1";

export type FindingPolicyStatus = "reportable" | "informational";

interface FindingClassificationInput {
  severity: Severity;
  confidence: Confidence;
}

interface FindingDescriptionInput extends FindingClassificationInput {
  origin: string;
  rule_id: string;
  category: string;
  path: string;
}

interface FindingDescription {
  title: string;
  explanation: string;
  remediation: string;
}

const reviewSeverities = new Set<Severity>(["critical", "high", "medium"]);
const reviewConfidences = new Set<Confidence>(["high", "medium"]);

const unsafeIdentifierPatterns = [
  /(?:^|[-_])sk-[a-z0-9]{20,}/iu,
  /ghp_[a-z0-9]{20,}/iu,
  /github_pat_[a-z0-9_]{20,}/iu,
  /(?:api|access|secret)[-_]?key[-_:]?[a-z0-9]{16,}/iu,
];

const staticDescriptions: Record<string, FindingDescription> = {
  "credential-exfiltration": {
    title: "Credential access and network transmission in one file",
    explanation:
      "A credential source and an outbound network operation were detected in the same file.",
    remediation:
      "Review the data flow, remove unintended credential transmission, and restrict any required destination.",
  },
  "network-install-hook": {
    title: "Network activity detected in an install hook",
    explanation:
      "A package installation hook contains an outbound network operation.",
    remediation:
      "Review the hook, remove unnecessary network activity, and pin any required downloaded resource.",
  },
  "unicode-bidi-control": {
    title: "Bidirectional text control detected in source",
    explanation:
      "A bidirectional Unicode control character was detected in a source file.",
    remediation:
      "Review the affected line and remove the control character unless its presence is explicitly required.",
  },
};

const externalOrigins = {
  gitleaks: {
    label: "Gitleaks",
    noun: "secret-detection rule",
    remediation:
      "Verify whether the matched value is active, revoke it if necessary, and remove it from repository history.",
  },
  opengrep: {
    label: "OpenGrep",
    noun: "static-analysis rule",
    remediation:
      "Review the matched code path and remove or constrain the flagged behavior when it is not required.",
  },
  "javascript-analysis": {
    label: "JavaScript analysis",
    noun: "static JavaScript security signal",
    remediation:
      "Review the correlated source behavior and remove unsafe execution, credential access, persistence, or network activity that is not required.",
  },
  "osv-scanner": {
    label: "OSV-Scanner",
    noun: "dependency advisory",
    remediation:
      "Review the advisory and update or replace the affected dependency when a fixed version is available.",
  },
  zizmor: {
    label: "zizmor",
    noun: "workflow-security rule",
    remediation:
      "Review the affected workflow and apply the least-privilege or pinning change recommended for the rule.",
  },
  malcontent: {
    label: "malcontent",
    noun: "behavioral-analysis rule",
    remediation:
      "Review the flagged artifact and remove it or isolate the behavior when it is not an intended project capability.",
  },
} as const;

function assertSafeRuleIdentifier(ruleId: string) {
  if (
    !/^[A-Za-z0-9][A-Za-z0-9._:-]{0,119}$/u.test(ruleId) ||
    unsafeIdentifierPatterns.some((pattern) => pattern.test(ruleId))
  )
    throw new Error("unsafe rule identifier");
}

export function classifyFinding({
  severity,
  confidence,
}: FindingClassificationInput): FindingPolicyStatus {
  return reviewSeverities.has(severity) && reviewConfidences.has(confidence)
    ? "reportable"
    : "informational";
}

export function describeFinding({
  origin,
  rule_id: ruleId,
}: FindingDescriptionInput): FindingDescription {
  assertSafeRuleIdentifier(ruleId);

  if (origin === "tavernkeeper") {
    const description = staticDescriptions[ruleId];
    if (description === undefined)
      throw new Error(`unsupported TavernKeeper rule: ${ruleId}`);
    return description;
  }

  const external = externalOrigins[origin as keyof typeof externalOrigins];
  if (external === undefined)
    throw new Error(`unsupported finding origin: ${origin}`);

  if (origin === "osv-scanner")
    return {
      title: `Dependency advisory ${ruleId} applies`,
      explanation: `OSV-Scanner matched advisory ${ruleId} to a dependency declared by this repository.`,
      remediation: external.remediation,
    };

  return {
    title: `${external.label} reported ${ruleId}`,
    explanation: `${external.label} matched ${external.noun} ${ruleId} in this repository.`,
    remediation: external.remediation,
  };
}
