import { describe, expect, test } from "vitest";

import { renderReportV5Html } from "../src/publish/render-report.js";
import { fixtureReportV5 } from "./helpers/v5-report.js";

describe("V5 technical report HTML", () => {
  test("renders complete coverage without assigning Tavernary's final grade", async () => {
    const report = await fixtureReportV5();
    const html = renderReportV5Html(report);
    expect(html).toContain("TavernKeeper Scan Report");
    expect(html).toContain("Contextual assessments");
    expect(html).toContain("0 of 0 candidates assessed");
    expect(html).not.toMatch(/<script\b/iu);
    expect(html).not.toMatch(/\b(?:teal|orange|red)\b/iu);
  });
});
