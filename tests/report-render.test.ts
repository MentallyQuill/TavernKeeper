import { describe, expect, test } from "vitest";

import { renderReportV5Html } from "../src/publish/render-report.js";
import { fixtureReportV5 } from "./helpers/v5-report.js";

describe("V5 technical report HTML", () => {
  test("renders complete coverage without assigning Tavernary's final grade", async () => {
    const report = await fixtureReportV5();
    const html = renderReportV5Html(report);

    expect(html).toContain("TavernKeeper Scan Report");
    expect(html).toContain("Advisory reports for Tavernary");
    expect(html).toContain(
      "No material or high-risk concern was identified in this review.",
    );
    expect(html).toContain(
      'class="assessment-summary surface risk-mark risk-low"',
    );
    expect(html).toContain(
      `<time datetime="${report.completed_at}">Aug 2, 2026</time>`,
    );
    expect(html).toContain(">aaaaaaa<");
    expect(html.indexOf("What this review found")).toBeLessThan(
      html.indexOf("Technical scan identity"),
    );
    expect(html).toContain(report.target_sha);
    expect(html).toContain(report.report_id);
    expect(html).toContain(report.contextual_reviewer.model);
    expect(html).toContain("0 of 0 candidates assessed");
    expect(html).not.toMatch(/<script\b/iu);
    expect(html).not.toMatch(/https:\/\/(?:fonts|cdn)\./iu);
    expect(html).not.toMatch(/\b(?:teal|orange|red)\b/iu);
  });
});
