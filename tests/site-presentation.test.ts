import { describe, expect, test } from "vitest";

import {
  assessmentSummary,
  escapeHtml,
  formatPublicDate,
  highestRisk,
  renderSiteHeader,
  shortSha,
  SITE_STYLES,
} from "../src/site/presentation.js";

describe("public site presentation", () => {
  test("uses the highest published recommendation without calling it a verdict", () => {
    expect(highestRisk({ high: 1, material: 4, low: 8 })).toBe("high");
    expect(highestRisk({ high: 0, material: 2, low: 8 })).toBe("material");
    expect(highestRisk({ high: 0, material: 0, low: 8 })).toBe("low");
    expect(assessmentSummary({ high: 0, material: 0, low: 4 })).toBe(
      "No material or high-risk concern was identified in this review.",
    );
  });

  test("formats public identity without losing exact machine values", () => {
    expect(shortSha("1bce1fa73fe6c0fe8e767c773a832b94bb336720")).toBe(
      "1bce1fa",
    );
    expect(formatPublicDate("2026-08-03T10:32:31.505Z")).toBe("Aug 3, 2026");
    expect(escapeHtml('<img src="x">')).toBe("&lt;img src=&quot;x&quot;&gt;");
  });

  test("renders the small shared family header", () => {
    const html = renderSiteHeader();
    expect(html).toContain("Advisory reports for Tavernary");
    expect(html).toContain(
      'href="https://mentallyquill.github.io/TavernKeeper/#reports"',
    );
    expect(html).toContain('href="https://tavernary.org/"');
  });

  test("allows long repository names to wrap at narrow viewports", () => {
    expect(SITE_STYLES).toMatch(
      /h1,\s*h2,\s*h3\s*\{[^}]*overflow-wrap: anywhere;/s,
    );
  });
});
