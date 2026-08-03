import { readFile } from "node:fs/promises";

import { describe, expect, test } from "vitest";

import type { ScanReportV4 } from "../src/contracts/reports.js";
import { renderHistoryHtml } from "../src/publish/render-history.js";
import { projectReportToIndexV4 } from "../src/publish/publisher.js";

async function entry() {
  const report = JSON.parse(
    await readFile(
      new URL("./fixtures/contracts/report.v4.valid.json", import.meta.url),
      "utf8",
    ),
  ) as ScanReportV4;
  const projected = projectReportToIndexV4(report);
  return {
    ...projected,
    result: "red" as const,
    summary: {
      headline: "Reportable concerns detected",
      detail:
        "1 reportable concern met TavernKeeper's deterministic threshold.",
    },
    finding_counts: {
      total: 1,
      reportable: 1,
      informational: 0,
      reportable_severity: { critical: 0, high: 1, medium: 0 },
      severity: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
      confidence: { high: 1, medium: 0, low: 0 },
      policy_status: { reportable: 1, informational: 0 },
      categories: [{ category: "credential-theft", count: 1 }],
    },
    coverage: { ...projected.coverage, evidence_validated: 1 },
  };
}

describe("repository scan history rendering", () => {
  test("links every preserved conclusion with exact SHA and result", async () => {
    const old = await entry();
    const current = {
      ...old,
      report_id: "f".repeat(64),
      target_sha: "e".repeat(40),
      completed_at: "2026-07-31T16:00:00.000Z",
      result: "teal" as const,
      summary: {
        headline: "No reportable concerns detected",
        detail:
          "All required deterministic checks completed without a reportable concern.",
      },
      finding_counts: {
        total: 0,
        reportable: 0,
        informational: 0,
        reportable_severity: { critical: 0, high: 0, medium: 0 },
        severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        confidence: { high: 0, medium: 0, low: 0 },
        policy_status: { reportable: 0, informational: 0 },
        categories: [],
      },
      coverage: { ...old.coverage, evidence_validated: 0 },
      report_url:
        "https://mentallyquill.github.io/TavernKeeper/reports/github/42/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee/2/1/",
    };

    const html = renderHistoryHtml([old, current]);

    expect(html).toContain(old.target_sha);
    expect(html).toContain(current.target_sha);
    expect(html).toContain(">RED<");
    expect(html).toContain(">TEAL<");
    expect(html).not.toMatch(/<script\b/iu);
  });
});
