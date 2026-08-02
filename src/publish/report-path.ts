import { createHash } from "node:crypto";

import { z } from "zod";

import { ScanModeSchema } from "../contracts/reports.js";
import { FullShaSchema } from "../contracts/targets.js";

const ReportIdentityInputSchema = z.strictObject({
  provider: z.literal("github"),
  repository_id: z.number().int().positive(),
  target_sha: FullShaSchema,
  scanner_policy_version: z
    .string()
    .regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/u),
  mode: ScanModeSchema,
  report_version: z.number().int().positive(),
});

type ReportIdentityInput = z.input<typeof ReportIdentityInputSchema>;

function identityFields(report: ReportIdentityInput) {
  return ReportIdentityInputSchema.parse({
    provider: report.provider,
    repository_id: report.repository_id,
    target_sha: report.target_sha,
    scanner_policy_version: report.scanner_policy_version,
    mode: report.mode,
    report_version: report.report_version,
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
  if (
    "schema_version" in report &&
    (report as ReportIdentityInput & { schema_version?: unknown })
      .schema_version === 3
  ) {
    const body = { ...(report as unknown as Record<string, unknown>) };
    delete body.report_id;
    return createHash("sha256")
      .update(JSON.stringify(canonicalValue(body)))
      .digest("hex");
  }
  return createHash("sha256")
    .update(JSON.stringify(identityFields(report)))
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
    identity.mode,
    String(identity.report_version),
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
