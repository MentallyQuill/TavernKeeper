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
      "No material or immediate-danger concern was identified in this review.",
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

  test("renders bounded unresolved paths and the first-filter warning", async () => {
    const legacy = await fixtureReportV5();
    const report = await fixtureReportV5({
      scanner_policy_version: "4",
      coverage: {
        ...legacy.coverage,
        tools: [
          ...legacy.coverage.tools,
          {
            name: "javascript-analysis",
            version: "test-version",
            status: "completed",
          },
        ],
        javascript_analysis: {
          status: "incomplete",
          candidates: 1,
          candidate_bytes: 123,
          representations: {
            raw: 1,
            decoded: 1,
            normalized: 1,
            bundle_modules: 0,
          },
          stages: {
            raw_signatures: 1,
            raw_ast: 1,
            raw_opengrep: 1,
            derived_signatures: 2,
            derived_ast: 2,
            derived_opengrep: 2,
          },
          unresolved: [
            {
              path: "dist/app.min.js",
              stage: "normalize",
              reason: "timeout",
              recovered: false,
            },
          ],
        },
      },
      limitations: [
        ...legacy.limitations,
        "JavaScript analysis was incomplete, so this first-filter scan supports no clean conclusion about unobserved behavior.",
      ],
    });
    const html = renderReportV5Html(report);

    expect(html).toMatch(/JavaScript coverage.*Incomplete/isu);
    expect(html).toMatch(/no clean conclusion/iu);
    expect(html).toContain("dist/app.min.js");
    expect(html).not.toContain("derived/000001-");
  });
});
