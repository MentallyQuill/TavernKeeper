import { describe, expect, test } from "vitest";

import {
  assessmentSummary,
  dangerBasisLabel,
  deriveProjectAdvisory,
  deriveIndexedProjectAdvisory,
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
      risk_exposure: "not_demonstrated" as const,
      recommended_risk: "low" as const,
    };
    expect(deriveProjectAdvisory([materialDependency])).toMatchObject({
      risk: "low",
      dangerBasis: null,
    });
    expect(
      deriveProjectAdvisory([
        {
          ...materialDependency,
          exploitability: "readily_exploitable",
          confidence: "high",
          risk_exposure: "demonstrated",
          recommended_risk: "high",
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
          risk_exposure: "demonstrated",
          recommended_risk: "high",
        },
      ]),
    ).toMatchObject({
      risk: "high",
      dangerBasis: "malicious_or_compromised",
    });
  });

  test("keeps a policy-3 material-looking item teal without demonstrated exposure", () => {
    expect(
      deriveProjectAdvisory([
        {
          disposition: "material_vulnerability",
          impact: "high",
          exploitability: "plausible",
          confidence: "high",
          risk_exposure: "not_demonstrated",
          recommended_risk: "low",
        },
      ]),
    ).toEqual({
      risk: "low",
      dangerBasis: null,
      counts: { high: 0, material: 0, low: 1 },
    });
  });

  test("keeps a legacy imported-template execution vulnerability yellow", () => {
    expect(
      deriveProjectAdvisory([
        {
          disposition: "material_vulnerability",
          impact: "high",
          exploitability: "plausible",
          confidence: "high",
          recommended_risk: "material",
          file_role: "production",
          origin: "opengrep",
          rule_id: "tavernkeeper.dynamic-execution.javascript-eval",
          technical_explanation:
            "A user-imported preset supplies JavaScript that is passed directly to new Function and executes with the extension's privileges.",
          layman_explanation:
            "Importing a hostile preset can run its code in the extension.",
        },
      ]),
    ).toMatchObject({
      risk: "material",
      counts: { high: 0, material: 1, low: 0 },
    });
  });

  test("downgrades a legacy dependency guess without demonstrated reachability", () => {
    expect(
      deriveProjectAdvisory([
        {
          disposition: "material_vulnerability",
          impact: "high",
          exploitability: "plausible",
          confidence: "high",
          recommended_risk: "material",
          file_role: "production",
          origin: "osv-scanner",
          rule_id: "GHSA-abcd-1234-efgh",
          technical_explanation:
            "The advisory matches a lockfile entry, but the supplied evidence does not establish runtime reachability or attacker-controlled input.",
          layman_explanation:
            "A dependency advisory is present, but this scan did not show that the vulnerable code can run.",
        },
      ]),
    ).toMatchObject({
      risk: "low",
      counts: { high: 0, material: 0, low: 1 },
    });
  });

  test("downgrades a legacy same-file correlation without demonstrated data flow", () => {
    expect(
      deriveProjectAdvisory([
        {
          disposition: "material_vulnerability",
          impact: "high",
          exploitability: "plausible",
          confidence: "high",
          recommended_risk: "material",
          file_role: "production",
          origin: "javascript-analysis",
          rule_id: "javascript.correlated.download-to-execution",
          technical_explanation:
            "Download and execution APIs occur in the same file, but the supplied evidence does not establish a data flow between them or attacker control.",
          layman_explanation:
            "The two operations are nearby, but the scan did not show downloaded content being executed.",
        },
      ]),
    ).toMatchObject({
      risk: "low",
      counts: { high: 0, material: 0, low: 1 },
    });
  });

  test("downgrades a legacy unsafe-statement finding with unconfirmed reachability", () => {
    expect(
      deriveProjectAdvisory([
        {
          disposition: "material_vulnerability",
          impact: "high",
          exploitability: "plausible",
          confidence: "high",
          recommended_risk: "material",
          file_role: "production",
          origin: "javascript-analysis",
          rule_id: "javascript.xray.unsafe-stmt",
          technical_explanation:
            "Runtime reachability is not demonstrated by the available evidence.",
          layman_explanation:
            "The risky-looking statement may not run in the shipped path.",
        },
      ]),
    ).toMatchObject({
      risk: "low",
      counts: { high: 0, material: 0, low: 1 },
    });
  });

  test("downgrades non-OSV legacy dependency evidence with an unknown affected version", () => {
    expect(
      deriveProjectAdvisory([
        {
          disposition: "material_vulnerability",
          impact: "high",
          exploitability: "plausible",
          confidence: "high",
          recommended_risk: "material",
          file_role: "production",
          origin: "javascript-analysis",
          rule_id: "javascript.xray.unsafe-stmt",
          category: "dependency-vulnerability",
          explanation:
            "The affected package version remains unknown in the supplied evidence.",
        },
      ]),
    ).toMatchObject({
      risk: "low",
      counts: { high: 0, material: 0, low: 1 },
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

  test("preserves policy-3 red from its validated demonstrated-risk counts", () => {
    const advisory = deriveIndexedProjectAdvisory({
      contextual_review_policy_version: "3",
      counts: {
        recommended_risk: { high: 1, material: 0, low: 0 },
        disposition: { credible_malicious_behavior: 1 },
      },
      coverage: { javascript_analysis_status: "complete" },
    } as never);

    expect(advisory).toMatchObject({
      risk: "high",
      dangerBasis: "malicious_or_compromised",
      counts: { high: 1, material: 0, low: 0 },
    });
  });

  test("keeps an otherwise-low advisory teal when JavaScript coverage is incomplete", () => {
    const advisory = deriveIndexedProjectAdvisory({
      contextual_review_policy_version: "2",
      counts: {
        recommended_risk: { high: 0, material: 0, low: 2 },
        disposition: { credible_malicious_behavior: 0 },
      },
      coverage: { javascript_analysis_status: "incomplete" },
    } as never);

    expect(advisory.risk).toBe("low");
    expect(advisory.dangerBasis).toBeNull();
  });

  test("keeps an otherwise-low advisory teal when evidence is metadata-only", () => {
    const indexed = deriveIndexedProjectAdvisory({
      contextual_review_policy_version: "2",
      counts: {
        recommended_risk: { high: 0, material: 0, low: 1 },
        disposition: { credible_malicious_behavior: 0 },
      },
      coverage: {
        javascript_analysis_status: "complete",
        metadata_only_candidates: 1,
      },
    } as never);

    expect(indexed.risk).toBe("low");
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
