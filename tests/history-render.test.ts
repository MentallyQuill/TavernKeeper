import { describe, expect, test } from "vitest";

import { projectReportToIndexV5 } from "../src/publish/publisher.js";
import { renderHistoryHtml } from "../src/publish/render-history.js";
import { fixtureReportV5 } from "./helpers/v5-report.js";

describe("V5 technical history rendering", () => {
  test("shows assessment counts without inventing a project color", async () => {
    const first = await fixtureReportV5();
    const second = await fixtureReportV5({
      report_version: 2,
      completed_at: "2026-08-03T12:00:00.000Z",
      supersedes_report_id: first.report_id,
    });
    const html = renderHistoryHtml([
      projectReportToIndexV5(second),
      projectReportToIndexV5(first),
    ]);
    expect(html).toContain("TavernKeeper Scan History");
    expect(html).toContain("Contextual review");
    expect(html.indexOf(first.report_id)).toBeLessThan(
      html.indexOf(second.report_id),
    );
    expect(html).not.toMatch(/\b(?:teal|orange|red)\b/iu);
  });
});
