import { createHash } from "node:crypto";

import { z } from "zod";

import { FullShaSchema } from "../contracts/targets.js";

const ReportPathIdentitySchema = z.strictObject({
  provider: z.literal("github"),
  repository_id: z.number().int().positive(),
  target_sha: FullShaSchema,
  scanner_policy_version: z
    .string()
    .regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/u),
  report_id: z.string().regex(/^[0-9a-f]{64}$/u),
});

type ReportIdentityInput = {
  provider: unknown;
  repository_id: unknown;
  target_sha?: unknown;
  scanner_policy_version?: unknown;
  schema_version?: unknown;
  report_id?: string;
  report_digest?: string;
  [key: string]: unknown;
};

function identityFields(report: ReportIdentityInput) {
  if (report.schema_version !== 5)
    throw new Error("Report path requires the V5 report contract.");
  return ReportPathIdentitySchema.parse({
    provider: report.provider,
    repository_id: report.repository_id,
    target_sha: report.target_sha,
    scanner_policy_version: report.scanner_policy_version,
    report_id: report.report_id,
  });
}

function canonicalValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (value !== null && typeof value === "object")
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, item]) => [key, canonicalValue(item)]),
    );
  return value;
}

export function reportIdentity(report: ReportIdentityInput) {
  if (report.schema_version !== 5)
    throw new Error("Report identity requires the V5 report contract.");
  const body = { ...(report as unknown as Record<string, unknown>) };
  delete body.report_id;
  delete body.report_digest;
  return createHash("sha256")
    .update(JSON.stringify(canonicalValue(body)))
    .digest("hex");
}

export function reportPath(report: ReportIdentityInput) {
  const identity = identityFields(report);
  return [
    "reports",
    identity.provider,
    String(identity.repository_id),
    identity.target_sha,
    identity.scanner_policy_version,
    identity.report_id,
  ].join("/");
}

export function reportUrl(report: ReportIdentityInput) {
  return `https://mentallyquill.github.io/TavernKeeper/${reportPath(report)}/`;
}

export function historyPath(
  report: Pick<ReportIdentityInput, "provider" | "repository_id">,
) {
  return `reports/${report.provider}/${report.repository_id}/history`;
}

export function historyUrl(
  report: Pick<ReportIdentityInput, "provider" | "repository_id">,
) {
  return `https://mentallyquill.github.io/TavernKeeper/${historyPath(report)}/`;
}
