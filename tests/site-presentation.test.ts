import { describe, expect, test } from "vitest";

import {
  assessmentSummary,
  dangerBasisLabel,
  deriveProjectAdvisory,
  escapeHtml,
  formatPublicDate,
  highestRisk,
  renderSiteHeader,
  shortSha,
  SITE_STYLES,
} from "../src/site/presentation.js";

describe("public site presentation", () => {
  test("keeps legacy count helpers available for non-project item summaries", () => {
    expect(highestRisk({ high: 1, material: 4, low: 8 })).toBe("high");
    expect(highestRisk({ high: 0, material: 2, low: 8 })).toBe("material");
    expect(highestRisk({ high: 0, material: 0, low: 8 })).toBe("low");
    expect(assessmentSummary({ high: 0, material: 0, low: 4 })).toBe(
      "No material or immediate-danger concern was identified in this review.",
    );
  });

  test("reserves immediate danger for exact high-confidence evidence", () => {
    const materialDependency = {
      disposition: "material_vulnerability" as const,
      impact: "critical" as const,
      exploitability: "plausible" as const,
      confidence: "medium" as const,
      recommended_risk: "high" as const,
    };
    expect(deriveProjectAdvisory([materialDependency])).toMatchObject({
      risk: "material",
      dangerBasis: null,
    });
    expect(
      deriveProjectAdvisory([
        {
          ...materialDependency,
          exploitability: "readily_exploitable",
          confidence: "high",
        },
      ]),
    ).toMatchObject({
      risk: "high",
      dangerBasis: "critical_exploitable_vulnerability",
    });
    expect(
      deriveProjectAdvisory([
        {
          ...materialDependency,
          disposition: "credible_malicious_behavior",
          confidence: "high",
        },
      ]),
    ).toMatchObject({
      risk: "high",
      dangerBasis: "malicious_or_compromised",
    });
  });

  test("names a mixed immediate-danger basis without hiding either cause", () => {
    const advisory = deriveProjectAdvisory([
      {
        disposition: "credible_malicious_behavior",
        impact: "critical",
        exploitability: "readily_exploitable",
        confidence: "high",
        recommended_risk: "high",
      },
      {
        disposition: "material_vulnerability",
        impact: "critical",
        exploitability: "readily_exploitable",
        confidence: "high",
        recommended_risk: "high",
      },
    ]);
    expect(advisory).toMatchObject({ risk: "high", dangerBasis: "mixed" });
    expect(dangerBasisLabel(advisory.dangerBasis)).toMatch(
      /malicious.*critical/iu,
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
