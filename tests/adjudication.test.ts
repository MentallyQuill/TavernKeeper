import { readFile } from "node:fs/promises";

import { describe, expect, test } from "vitest";

import type { ScanReport } from "../src/contracts/reports.js";
import {
  addReusableDismissal,
  adjudicateFinding,
  DismissalRegistrySchema,
} from "../src/adjudication/adjudicate.js";
import { reportIdentity } from "../src/publish/report-path.js";
import { sanitizeReport } from "../src/publish/sanitize.js";

async function originalReport() {
  const raw = JSON.parse(
    await readFile(
      new URL("./fixtures/contracts/report.valid.json", import.meta.url),
      "utf8",
    ),
  ) as Record<string, unknown>;
  return {
    ...raw,
    report_id: reportIdentity(raw as never),
  } as unknown as ScanReport;
}

describe("immutable staff adjudication", () => {
  test("dismisses one finding in a new superseding report without mutating evidence", async () => {
    const original = await originalReport();
    const originalSnapshot = structuredClone(original);
    const appealed = original.findings[0]!;

    const next = adjudicateFinding({
      report: original,
      fingerprint: appealed.fingerprint,
      decision: "dismiss",
      rationale: "Confirmed test-only behavior with no credential destination.",
      actor: "MentallyQuill",
      completedAt: "2026-07-31T16:00:00.000Z",
      reusable: false,
    });

    expect(original).toEqual(originalSnapshot);
    expect(next.supersedes_report_id).toBe(original.report_id);
    expect(next.report_version).toBe(original.report_version + 1);
    expect(next.report_id).toBe(reportIdentity(next));
    expect(next.report_id).not.toBe(original.report_id);
    expect(next.result).toBe("green");
    expect(next.finding_counts).toMatchObject({
      total: 1,
      actionable: 0,
      disposition: { active: 0, dismissed: 1 },
    });
    expect(next.findings[0]).toEqual({
      ...appealed,
      disposition: "dismissed",
      adjudication: {
        decision: "dismissed",
        rationale:
          "Confirmed test-only behavior with no credential destination.",
        actor: "MentallyQuill",
        completed_at: "2026-07-31T16:00:00.000Z",
        reusable: false,
      },
    });
    expect(sanitizeReport(next)).toEqual(next);
  });

  test("requires a canonical report identity, exact fingerprint, and state-changing decision", async () => {
    const original = await originalReport();
    const base = {
      report: original,
      fingerprint: original.findings[0]!.fingerprint,
      decision: "dismiss" as const,
      rationale: "Reviewed by staff.",
      actor: "MentallyQuill",
      completedAt: "2026-07-31T16:00:00.000Z",
      reusable: false,
    };

    expect(() =>
      adjudicateFinding({
        ...base,
        report: { ...original, report_id: "f".repeat(64) },
      }),
    ).toThrow(/report identity/iu);
    expect(() =>
      adjudicateFinding({ ...base, fingerprint: "f".repeat(64) }),
    ).toThrow(/finding fingerprint/iu);

    const dismissed = adjudicateFinding(base);
    expect(() => adjudicateFinding({ ...base, report: dismissed })).toThrow(
      /already dismissed/iu,
    );
  });

  test("records a reusable repository-scoped dismissal only after explicit approval", async () => {
    const original = await originalReport();
    const fingerprint = original.findings[0]!.fingerprint;
    const ordinary = adjudicateFinding({
      report: original,
      fingerprint,
      decision: "dismiss",
      rationale: "One-off exception.",
      actor: "MentallyQuill",
      completedAt: "2026-07-31T16:00:00.000Z",
      reusable: false,
    });
    const reusable = adjudicateFinding({
      report: original,
      fingerprint,
      decision: "dismiss",
      rationale: "Reviewed repository-scoped generated file convention.",
      actor: "MentallyQuill",
      completedAt: "2026-07-31T16:00:00.000Z",
      reusable: true,
    });
    const registry = DismissalRegistrySchema.parse({
      schema_version: 1,
      dismissals: [],
    });

    expect(() =>
      addReusableDismissal({ registry, report: ordinary, fingerprint }),
    ).toThrow(/not marked reusable/iu);
    const updated = addReusableDismissal({
      registry,
      report: reusable,
      fingerprint,
    });
    expect(updated.dismissals).toHaveLength(1);
    expect(updated.dismissals[0]).toMatchObject({
      repository_id: original.repository_id,
      origin: original.findings[0]!.origin,
      rule_id: original.findings[0]!.rule_id,
      path: original.findings[0]!.path,
      source_report_id: reusable.report_id,
      source_fingerprint: fingerprint,
    });
  });

  test("ships an empty, strict reusable-dismissal registry", async () => {
    const registry = JSON.parse(
      await readFile(
        new URL("../rules/dismissals.json", import.meta.url),
        "utf8",
      ),
    );

    expect(DismissalRegistrySchema.parse(registry)).toEqual({
      schema_version: 1,
      dismissals: [],
    });
  });
});
