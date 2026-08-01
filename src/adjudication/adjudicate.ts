import { createHash } from "node:crypto";

import { z } from "zod";

import {
  buildFindingCounts,
  deriveResult,
  type ScanReport,
} from "../contracts/reports.js";
import { reportIdentity } from "../publish/report-path.js";
import { sanitizeReport } from "../publish/sanitize.js";

const FingerprintSchema = z.string().regex(/^[0-9a-f]{64}$/u);
const StaffActorSchema = z
  .string()
  .regex(/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/u);

const ReusableDismissalSchema = z.strictObject({
  id: FingerprintSchema,
  repository_id: z.number().int().positive(),
  origin: z.string().regex(/^[a-z0-9][a-z0-9:_-]{0,79}$/u),
  rule_id: z.string().min(1).max(120),
  path: z.string().min(1).max(500),
  rationale: z.string().min(1).max(1_000),
  actor: StaffActorSchema,
  created_at: z.iso.datetime(),
  source_report_id: FingerprintSchema,
  source_fingerprint: FingerprintSchema,
});

export const DismissalRegistrySchema = z
  .strictObject({
    schema_version: z.literal(1),
    dismissals: z.array(ReusableDismissalSchema),
  })
  .superRefine((registry, context) => {
    const ids = registry.dismissals.map(({ id }) => id);
    if (new Set(ids).size !== ids.length)
      context.addIssue({
        code: "custom",
        path: ["dismissals"],
        message: "Reusable dismissal IDs must be unique.",
      });
    if (
      registry.dismissals.some(
        (entry, index) =>
          index > 0 && registry.dismissals[index - 1]!.id >= entry.id,
      )
    )
      context.addIssue({
        code: "custom",
        path: ["dismissals"],
        message: "Reusable dismissals must be sorted by ID.",
      });
  });

export function adjudicateFinding({
  report: reportInput,
  fingerprint,
  decision,
  rationale,
  actor,
  completedAt,
  reusable = false,
}: {
  report: unknown;
  fingerprint: string;
  decision: "dismiss" | "restore";
  rationale: string;
  actor: string;
  completedAt: string;
  reusable?: boolean;
}): ScanReport {
  const report = sanitizeReport(reportInput);
  const targetFingerprint = FingerprintSchema.parse(fingerprint);
  const position = report.findings.findIndex(
    (finding) => finding.fingerprint === targetFingerprint,
  );
  if (position === -1)
    throw new Error("Finding fingerprint is not in the report.");
  const desiredDisposition = decision === "dismiss" ? "dismissed" : "active";
  const current = report.findings[position]!;
  if (current.disposition === desiredDisposition)
    throw new Error(`Finding is already ${desiredDisposition}.`);

  const findings = [...report.findings];
  findings[position] = {
    ...current,
    disposition: desiredDisposition,
    adjudication: {
      decision: desiredDisposition,
      rationale,
      actor,
      completed_at: completedAt,
      reusable: desiredDisposition === "dismissed" && reusable,
    },
  };
  const candidate = {
    ...report,
    report_version: report.report_version + 1,
    supersedes_report_id: report.report_id,
    completed_at: completedAt,
    findings,
    result: deriveResult(findings),
    finding_counts: buildFindingCounts(findings),
  };
  return sanitizeReport({
    ...candidate,
    report_id: reportIdentity(candidate),
  });
}

function dismissalId(report: ScanReport, position: number) {
  const finding = report.findings[position]!;
  return createHash("sha256")
    .update(
      JSON.stringify([
        report.repository_id,
        finding.origin,
        finding.rule_id,
        finding.path,
      ]),
    )
    .digest("hex");
}

export function addReusableDismissal({
  registry: registryInput,
  report: reportInput,
  fingerprint,
}: {
  registry: unknown;
  report: unknown;
  fingerprint: string;
}) {
  const registry = DismissalRegistrySchema.parse(registryInput);
  const report = sanitizeReport(reportInput);
  const position = report.findings.findIndex(
    (finding) => finding.fingerprint === fingerprint,
  );
  if (position === -1)
    throw new Error("Finding fingerprint is not in the report.");
  const finding = report.findings[position]!;
  if (
    finding.disposition !== "dismissed" ||
    finding.adjudication?.reusable !== true
  )
    throw new Error("Finding adjudication is not marked reusable.");
  const entry = ReusableDismissalSchema.parse({
    id: dismissalId(report, position),
    repository_id: report.repository_id,
    origin: finding.origin,
    rule_id: finding.rule_id,
    path: finding.path,
    rationale: finding.adjudication.rationale,
    actor: finding.adjudication.actor,
    created_at: finding.adjudication.completed_at,
    source_report_id: report.report_id,
    source_fingerprint: finding.fingerprint,
  });
  if (registry.dismissals.some(({ id }) => id === entry.id))
    throw new Error("Reusable dismissal already exists.");
  return DismissalRegistrySchema.parse({
    ...registry,
    dismissals: [...registry.dismissals, entry].sort((left, right) =>
      left.id.localeCompare(right.id),
    ),
  });
}
