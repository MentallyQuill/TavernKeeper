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

export class ScannerError extends Error {
  constructor(
    readonly code: ScannerErrorCode,
    readonly scope: "repository" | "system",
    message: string,
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
  scanner: string,
  code: "SPAWN_FAILED" | "TIMED_OUT" | "OUTPUT_LIMIT_EXCEEDED",
): ScannerError {
  if (code === "SPAWN_FAILED")
    return new ScannerError(
      "SCANNER_UNAVAILABLE",
      "system",
      `${scanner} could not be started.`,
    );
  if (code === "TIMED_OUT")
    return new ScannerError(
      "SCANNER_TIMEOUT",
      "system",
      `${scanner} exceeded its runtime ceiling.`,
    );
  return new ScannerError(
    "SCANNER_OUTPUT_LIMIT",
    "system",
    `${scanner} exceeded its output ceiling.`,
  );
}
