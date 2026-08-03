import { describe, expect, test } from "vitest";

import { projectReportToIndexV5 } from "../src/publish/publisher.js";
import { renderHistoryHtml } from "../src/publish/render-history.js";
import { fixtureReportV5 } from "./helpers/v5-report.js";

describe("V5 technical history rendering", () => {
  test("shows assessment counts without inventing a project color", async () => {
    const first = await fixtureReportV5({
      target_sha: "a".repeat(40),
      completed_at: "2026-08-02T12:00:00.000Z",
    });
    const second = await fixtureReportV5({
      report_version: 2,
      supersedes_report_id: first.report_id,
      target_sha: "b".repeat(40),
      completed_at: "2026-08-03T12:00:00.000Z",
    });
    const html = renderHistoryHtml([
      projectReportToIndexV5(second),
      projectReportToIndexV5(first),
    ]);
    expect(html).toContain("TavernKeeper Scan History");
    expect(html).toContain("Advisory reports for Tavernary");
    expect(html).toContain("Scan history");
    expect(html).toContain("View report");
    expect(html).toContain("bbbbbbb");
    expect(html).toContain("0 high &middot; 0 material &middot; 0 low");
    expect(html.indexOf("Aug 3, 2026")).toBeLessThan(
      html.indexOf("Aug 2, 2026"),
    );
    expect(html).not.toMatch(/<script\b/iu);
    expect(html).not.toMatch(/\b(?:teal|orange|red)\b/iu);
  });
});
