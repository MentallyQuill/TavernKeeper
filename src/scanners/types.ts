import { createHash } from "node:crypto";

import {
  FindingSchema,
  type Confidence,
  type Finding,
  type Severity,
} from "../contracts/reports.js";

export interface ScannerRun {
  name: string;
  version: string;
  status: "completed" | "not-applicable";
  findings: Finding[];
}

export type ScannerErrorCode =
  | "SCANNER_UNAVAILABLE"
  | "SCANNER_TIMEOUT"
  | "SCANNER_OUTPUT_LIMIT"
  | "SCANNER_FAILED"
  | "MALFORMED_SCANNER_OUTPUT";

export const ScannerComponents = [
  "gitleaks",
  "opengrep",
  "osv-scanner",
  "zizmor",
  "malcontent",
] as const;
export type ScannerComponent = (typeof ScannerComponents)[number];

export class ScannerError extends Error {
  constructor(
    readonly code: ScannerErrorCode,
    readonly scope: "repository" | "system",
    message: string,
    readonly component?: ScannerComponent,
  ) {
    super(message);
    this.name = "ScannerError";
  }
}

export interface NormalizedFindingInput {
  origin: string;
  ruleId: string;
  category: string;
  severity: Severity;
  confidence: Confidence;
  path: string;
  lineStart: number | null;
  lineEnd: number | null;
  evidenceSha: string | null;
  title: string;
  explanation: string;
  remediation?: string;
}

export function normalizeFinding(input: NormalizedFindingInput): Finding {
  const fingerprint = createHash("sha256")
    .update(
      JSON.stringify([
        input.origin,
        input.ruleId,
        input.path,
        input.lineStart,
        input.lineEnd,
        input.evidenceSha,
      ]),
    )
    .digest("hex");
  return FindingSchema.parse({
    origin: input.origin,
    rule_id: input.ruleId,
    category: input.category,
    severity: input.severity,
    confidence: input.confidence,
    path: input.path,
    line_start: input.lineStart,
    line_end: input.lineEnd,
    evidence_sha: input.evidenceSha,
    title: input.title,
    explanation: input.explanation,
    ...(input.remediation === undefined
      ? {}
      : { remediation: input.remediation }),
    fingerprint,
    disposition: "active",
  });
}

export function scannerExecutionError(
  scanner: ScannerComponent,
  code: "SPAWN_FAILED" | "TIMED_OUT" | "OUTPUT_LIMIT_EXCEEDED",
): ScannerError {
  const displayName: Record<ScannerComponent, string> = {
    gitleaks: "Gitleaks",
    opengrep: "OpenGrep",
    "osv-scanner": "OSV-Scanner",
    zizmor: "zizmor",
    malcontent: "malcontent",
  };
  if (code === "SPAWN_FAILED")
    return new ScannerError(
      "SCANNER_UNAVAILABLE",
      "system",
      `${displayName[scanner]} could not be started.`,
      scanner,
    );
  if (code === "TIMED_OUT")
    return new ScannerError(
      "SCANNER_TIMEOUT",
      "system",
      `${displayName[scanner]} exceeded its runtime ceiling.`,
      scanner,
    );
  return new ScannerError(
    "SCANNER_OUTPUT_LIMIT",
    "system",
    `${displayName[scanner]} exceeded its output ceiling.`,
    scanner,
  );
}
