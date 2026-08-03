import {
  ScanReportV5Schema,
  type ScanReportV5,
} from "../contracts/reports-v5.js";
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
const UNSAFE_HTML = [/<\/?[A-Za-z][^>]*>/u, /\bon[a-z][a-z0-9_-]*\s*=/iu];
const SAFETY_CLAIM = [
  /\b(?:repository|project|code|package|extension|plugin)\b.{0,48}\b(?:safe|trusted|certified|verified)\b/iu,
  /\b(?:safe|trusted|certified|verified)\b.{0,48}\b(?:repository|project|code|package|extension|plugin)\b/iu,
];

function normalizedPath(path: string[]) {
  return path
    .map((segment) => (/^\d+$/u.test(segment) ? "*" : segment))
    .join(".");
}

function isApprovedUrlPath(path: string[]) {
  return ["canonical_url", "candidates.*.reference_url"].includes(
    normalizedPath(path),
  );
}

function isNarrativePath(path: string[]) {
  return [
    "candidates.*.title",
    "candidates.*.explanation",
    "candidates.*.remediation",
    "assessments.*.technical_explanation",
    "assessments.*.layman_explanation",
    "assessments.*.developer_action",
    "observations.*.title",
    "observations.*.technical_explanation",
    "observations.*.layman_explanation",
    "observations.*.developer_action",
    "limitations.*",
  ].includes(normalizedPath(path));
}

function reject(message: string): never {
  throw new Error(`Public report rejected: ${message}`);
}

function inspectString(value: string, path: string[]) {
  const field = path.join(".");
  const narrative = isNarrativePath(path);
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
  if (narrative && UNSAFE_HTML.some((pattern) => pattern.test(value)))
    reject(`${field} contains unsafe HTML.`);
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
  if (value !== null && typeof value === "object")
    for (const [key, item] of Object.entries(value))
      inspectValue(item, [...path, key]);
}

export function sanitizeReportV5(input: unknown): ScanReportV5 {
  const parsed = ScanReportV5Schema.safeParse(input);
  if (!parsed.success) reject("schema or derived V5 fields are invalid.");
  const report = parsed.data;
  if (
    report.report_id !== reportIdentity(report) ||
    report.report_digest !== report.report_id
  )
    reject("report identity does not match the complete V5 public body.");
  inspectValue(report);
  return report;
}
