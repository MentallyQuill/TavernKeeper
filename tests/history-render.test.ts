import { readFile } from "node:fs/promises";

import { describe, expect, test } from "vitest";

import type { ReportIndexEntryV2 } from "../src/contracts/reports.js";
import { renderHistoryHtml } from "../src/publish/render-history.js";

async function entry() {
  const index = JSON.parse(
    await readFile(
      new URL("./fixtures/contracts/index.v2.valid.json", import.meta.url),
      "utf8",
    ),
  ) as { reports: ReportIndexEntryV2[] };
  return index.reports[0]!;
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
      finding_counts: {
        total: 0,
        actionable: 0,
        severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        confidence: { high: 0, medium: 0, low: 0 },
        disposition: { confirmed: 0, not_supported: 0, inconclusive: 0 },
        categories: [],
      },
      report_url:
        "https://mentallyquill.github.io/TavernKeeper/reports/github/42/eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee/1/standard/1/",
    };

    const html = renderHistoryHtml([old, current]);

    expect(html).toContain(old.target_sha);
    expect(html).toContain(current.target_sha);
    expect(html).toContain(">RED<");
    expect(html).toContain(">TEAL<");
    expect(html).not.toMatch(/<script\b/iu);
  });
});
