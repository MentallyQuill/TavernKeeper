import {
  ScanReportV5Schema,
  type ScanReportV5,
} from "../contracts/reports-v5.js";
import { publicNarrativeIsSafe } from "../contracts/public-narrative.js";
import { redactSource } from "../model/redaction.js";
import { reportIdentity } from "./report-path.js";

const CONTROL_CHARACTER = /[\u0000-\u001f\u007f-\u009f]/u;
const URL_LIKE = /\b(?:https?|ftp):\/\/|\bwww\./iu;

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
  if (redactSource(value) !== value)
    reject(`${field} contains secret-shaped output.`);
  if (narrative && !publicNarrativeIsSafe(value))
    reject(`${field} contains unsafe public narrative.`);
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
