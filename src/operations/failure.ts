import { createHash } from "node:crypto";

import { z } from "zod";

export const FailureDomains = ["target", "shared", "security"] as const;

export const FailureComponents = [
  "acquisition",
  "inventory",
  "history",
  "gitleaks",
  "opengrep",
  "osv-scanner",
  "zizmor",
  "malcontent",
  "evidence-context",
  "contextual-model",
  "finalization",
  "artifact-transport",
  "publication",
  "target-manifest",
  "github",
  "pages",
  "orchestrator",
] as const;

export const SafeFailureDiagnostics = [
  "assessment_candidate_id",
  "assessment_confidence",
  "assessment_developer_action",
  "assessment_disposition",
  "assessment_evidence_ids",
  "assessment_exploitability",
  "assessment_impact",
  "assessment_layman_explanation",
  "assessment_locations",
  "assessment_recommended_risk",
  "assessment_schema",
  "assessment_technical_explanation",
  "observation_schema",
  "output_limit",
  "response_content",
  "response_envelope",
  "response_json",
  "response_size",
  "response_usage",
  "review_schema",
  "evidence_non_text",
  "parser_syntax",
  "rule_timeout",
] as const;

export const FailureDescriptorSchema = z.strictObject({
  code: z.string().regex(/^[A-Z][A-Z0-9_]{0,79}$/u),
  domain: z.enum(FailureDomains),
  component: z.enum(FailureComponents),
  diagnostic: z.enum(SafeFailureDiagnostics).optional(),
});

export type FailureDescriptor = z.infer<typeof FailureDescriptorSchema>;

const TargetSystemCodes = new Set([
  "CLASSIFICATION_INVALID",
  "CONTEXTUAL_REVIEW_INVALID",
  "EVIDENCE_CONTEXT_UNSUPPORTED",
  "INVENTORY_INVALID",
  "MALFORMED_SCANNER_OUTPUT",
  "MODEL_CONTEXT_INCOMPLETE",
  "MODEL_EVIDENCE_INVALID",
  "MODEL_INVALID_RESPONSE",
  "REPORT_FINALIZATION_FAILED",
  "SCAN_PACKAGE_FINALIZATION_FAILED",
  "SCAN_PACKAGE_INVALID",
  "SCANNER_FAILED",
  "SCANNER_OUTPUT_LIMIT",
  "SCANNER_TIMEOUT",
]);

const SharedSystemCodes = new Set([
  "MODEL_PROVIDER",
  "MODEL_QUOTA",
  "SCAN_BOOTSTRAP_FAILED",
  "SCANNER_UNAVAILABLE",
]);

const SecuritySystemCodes = new Set([
  "MODEL_AUTHENTICATION",
  "MODEL_AUTH_HEADER_MISMATCH",
  "MODEL_CONFIGURATION",
  "MODEL_IDENTITY_MISMATCH",
  "MODEL_RESPONSE_ORIGIN",
  "SCAN_POLICY_MISMATCH",
]);

function objectRecord(value: unknown): Record<string, unknown> {
  return value !== null && typeof value === "object"
    ? (value as Record<string, unknown>)
    : {};
}

function safeCode(value: unknown) {
  return typeof value === "string" && /^[A-Z][A-Z0-9_]{0,79}$/u.test(value)
    ? value
    : "CLI_FAILED";
}

function inferredComponent(code: string): (typeof FailureComponents)[number] {
  if (code.startsWith("MODEL_") || code === "CONTEXTUAL_REVIEW_INVALID")
    return "contextual-model";
  if (
    code.startsWith("INVENTORY_") ||
    code === "CLASSIFICATION_INVALID" ||
    [
      "AMBIGUOUS_PATH",
      "BYTE_BUDGET_EXCEEDED",
      "FILE_BUDGET_EXCEEDED",
      "INVALID_ROOT",
      "READ_FAILED",
      "UNSAFE_LINK",
      "UNSAFE_PATH",
    ].includes(code)
  )
    return "inventory";
  if (code === "HISTORY_FAILED") return "history";
  if (["CHECKOUT_FAILED", "HEAD_MISMATCH", "INVALID_TARGET"].includes(code))
    return "acquisition";
  if (code.startsWith("REPORT_") || code.startsWith("SCAN_PACKAGE_"))
    return "finalization";
  return "orchestrator";
}

export function classifyFailure(value: unknown): FailureDescriptor {
  const parsedDescriptor = FailureDescriptorSchema.safeParse(value);
  if (parsedDescriptor.success) return parsedDescriptor.data;

  const candidate = objectRecord(value);
  const code = safeCode(candidate.code);
  const scope =
    candidate.scope === "repository" || candidate.scope === "system"
      ? candidate.scope
      : "system";
  const component =
    FailureComponents.find((entry) => entry === candidate.component) ??
    inferredComponent(code);
  const diagnostic = SafeFailureDiagnostics.find(
    (entry) => entry === candidate.diagnostic,
  );

  const domain =
    scope === "repository" || TargetSystemCodes.has(code)
      ? "target"
      : SharedSystemCodes.has(code)
        ? "shared"
        : SecuritySystemCodes.has(code)
          ? "security"
          : "shared";

  return {
    code,
    domain,
    component,
    ...(diagnostic === undefined ? {} : { diagnostic }),
  };
}

export function failureFingerprint(failure: FailureDescriptor) {
  const parsed = FailureDescriptorSchema.parse(failure);
  return createHash("sha256")
    .update(
      JSON.stringify([
        parsed.domain,
        parsed.component,
        parsed.code,
        parsed.diagnostic ?? null,
      ]),
    )
    .digest("hex");
}
