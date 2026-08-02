import {
  ScanReportSchema,
  ScanReportV2Schema,
  ScanReportV3Schema,
  type ScanReport,
  type ScanReportV2,
  type ScanReportV3,
} from "../contracts/reports.js";
import { reportIdentity } from "./report-path.js";

const CONTROL_CHARACTER = /[\u0000-\u001f\u007f-\u009f]/u;
const URL_LIKE = /\b(?:https?|ftp):\/\/|\bwww\./iu;
const LOCAL_PATH =
  /(?:\b[A-Za-z]:[\\/]|(?:^|[\s"'(])\/(?:Users|home|tmp|var\/tmp|private\/tmp)\/)/u;
const SECRET_SHAPED = [
  /\bgithub_pat_[A-Za-z0-9_]{20,}\b/u,
  /\bgh[pousr]_[A-Za-z0-9]{20,}\b/u,
  /\bsk-[A-Za-z0-9_-]{16,}\b/u,
  /\bAKIA[0-9A-Z]{16}\b/u,
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/u,
  /\bBearer\s+[A-Za-z0-9._~+/-]{16,}=*/iu,
  /\b(?:api[_ -]?key|token|secret|password)\s*[:=]\s*["']?[A-Za-z0-9_./+=-]{8,}/iu,
];
const SOURCE_SHAPED = [
  /```/u,
  /<\/?(?:script|style|iframe|object|embed)\b/iu,
  /\b(?:const|let|var)\s+[A-Za-z_$][\w$]*\s*=/u,
  /\b(?:async\s+)?function\s+[A-Za-z_$][\w$]*\s*\(/u,
  /\bclass\s+[A-Za-z_$][\w$]*\s*(?:extends\s+[A-Za-z_$][\w$]*\s*)?\{/u,
  /\b(?:import|export)\s+(?:\{|\*|default\b|[A-Za-z_$])/u,
  /=>/u,
];
const SAFETY_CLAIM = [
  /\b(?:repository|project|code|package|extension|plugin)\b.{0,48}\b(?:safe|trusted|certified|verified)\b/iu,
  /\b(?:safe|trusted|certified|verified)\b.{0,48}\b(?:repository|project|code|package|extension|plugin)\b/iu,
];

const APPROVED_URL_PATHS = new Set([
  "canonical_url",
  "coverage.model.endpoint_origin",
]);

function isApprovedUrlPath(path: string[]) {
  const normalized = path.map((segment) =>
    /^\d+$/u.test(segment) ? "*" : segment,
  );
  return (
    APPROVED_URL_PATHS.has(normalized.join(".")) ||
    normalized.join(".") === "findings.*.reference_url"
  );
}

function isFindingNarrativePath(path: string[]) {
  const normalized = path.map((segment) =>
    /^\d+$/u.test(segment) ? "*" : segment,
  );
  return [
    "findings.*.title",
    "findings.*.explanation",
    "findings.*.remediation",
    "findings.*.adjudication.rationale",
    "tool_results.*.signals.*.title",
    "model_review.recap",
    "model_review.concerns.*.title",
    "model_review.concerns.*.explanation",
  ].includes(normalized.join("."));
}

function reject(message: string): never {
  throw new Error(`Public report rejected: ${message}`);
}

function inspectString(value: string, path: string[]) {
  const field = path.join(".");
  const narrative = isFindingNarrativePath(path);
  if (CONTROL_CHARACTER.test(value))
    reject(`${field} contains control characters.`);
  if (!isApprovedUrlPath(path) && URL_LIKE.test(value))
    reject(`${field} contains an unapproved URL.`);
  if (narrative && LOCAL_PATH.test(value))
    reject(`${field} contains a local filesystem path.`);
  if (SECRET_SHAPED.some((pattern) => pattern.test(value)))
    reject(`${field} contains secret-shaped output.`);
  if (narrative && SOURCE_SHAPED.some((pattern) => pattern.test(value)))
    reject(`${field} contains a source excerpt.`);
  if (narrative && SAFETY_CLAIM.some((pattern) => pattern.test(value)))
    reject(`${field} contains a safety claim.`);
}

function inspectValue(value: unknown, path: string[] = []) {
  if (typeof value === "string") {
    inspectString(value, path);
    return;
  }
  if (Array.isArray(value)) {
    value.forEach((item, index) =>
      inspectValue(item, [...path, String(index)]),
    );
    return;
  }
  if (value !== null && typeof value === "object") {
    for (const [key, item] of Object.entries(value))
      inspectValue(item, [...path, key]);
  }
}

export function sanitizeReport(input: unknown): ScanReport {
  const parsed = ScanReportSchema.safeParse(input);
  if (!parsed.success) reject("schema or derived fields are invalid.");
  const report = parsed.data;
  if (report.report_id !== reportIdentity(report))
    reject("report identity does not match immutable fields.");
  inspectValue(report);
  return report;
}

export function sanitizeReportV2(input: unknown): ScanReportV2 {
  const parsed = ScanReportV2Schema.safeParse(input);
  if (!parsed.success) reject("schema or derived V2 fields are invalid.");
  const report = parsed.data;
  if (report.report_id !== reportIdentity(report)) {
    reject("report identity does not match immutable fields.");
  }
  inspectValue(report);
  return report;
}

export function sanitizeReportV3(input: unknown): ScanReportV3 {
  const parsed = ScanReportV3Schema.safeParse(input);
  if (!parsed.success) reject("schema or derived V3 fields are invalid.");
  const report = parsed.data;
  if (report.report_id !== reportIdentity(report))
    reject("report identity does not match immutable fields.");
  inspectValue(report);
  return report;
}
