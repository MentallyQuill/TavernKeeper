import { createHash } from "node:crypto";

import {
  FindingSchema,
  type Confidence,
  type Finding,
  type Severity,
} from "../contracts/reports.js";
import type {
  JavaScriptEvidenceHint,
  JavascriptAnalysisCoverage,
  JavascriptDerivativeAncestry,
} from "./javascript-analysis-types.js";

export interface ScannerRun {
  name: string;
  version: string;
  status: "completed" | "completed-with-limitations" | "not-applicable";
  limitations?: ScannerDiagnostic[] | undefined;
  findings: Finding[];
  pathCoverage?: ScannerPathCoverage | undefined;
  javascriptAnalysis?: JavascriptAnalysisCoverage | undefined;
  evidenceHints?: JavaScriptEvidenceHint[] | undefined;
  derivativeAncestry?: JavascriptDerivativeAncestry[] | undefined;
}

export type ScannerPathSkipReason =
  "parse" | "timeout" | "target-limit" | "unsupported";

export interface ScannerPathCoverage {
  scanned: string[];
  skipped: Array<{ path: string; reason: ScannerPathSkipReason }>;
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
  "javascript-analysis",
  "osv-scanner",
  "zizmor",
  "malcontent",
] as const;
export type ScannerComponent = (typeof ScannerComponents)[number];
export type ScannerDiagnostic = "parser_syntax" | "rule_timeout";

export class ScannerError extends Error {
  constructor(
    readonly code: ScannerErrorCode,
    readonly scope: "repository" | "system",
    message: string,
    readonly component?: ScannerComponent,
    readonly diagnostic?: ScannerDiagnostic,
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

export function findingFingerprint(
  input: Pick<
    NormalizedFindingInput,
    "origin" | "ruleId" | "path" | "lineStart" | "lineEnd" | "evidenceSha"
  >,
) {
  return createHash("sha256")
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
}

export function normalizeFinding(input: NormalizedFindingInput): Finding {
  const ruleId = input.ruleId
    .trim()
    .replace(/[^A-Za-z0-9._:-]+/gu, "-")
    .replace(/^[^A-Za-z0-9]+/u, "")
    .slice(0, 120);
  if (ruleId.length === 0)
    throw new ScannerError(
      "MALFORMED_SCANNER_OUTPUT",
      "system",
      "Scanner finding rule ID is invalid.",
    );
  const fingerprint = findingFingerprint({ ...input, ruleId });
  return FindingSchema.parse({
    origin: input.origin,
    rule_id: ruleId,
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
  });
}

export function scannerExecutionError(
  scanner: ScannerComponent,
  code: "SPAWN_FAILED" | "TIMED_OUT" | "OUTPUT_LIMIT_EXCEEDED",
): ScannerError {
  const displayName: Record<ScannerComponent, string> = {
    gitleaks: "Gitleaks",
    opengrep: "OpenGrep",
    "javascript-analysis": "JavaScript analysis",
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
