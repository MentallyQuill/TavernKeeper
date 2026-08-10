import { describe, expect, test } from "vitest";

import { renderReportV5Html } from "../src/publish/render-report.js";
import {
  fixturePolicy5ReportV5,
  fixtureReportV5,
} from "./helpers/v5-report.js";

describe("V5 technical report HTML", () => {
  test("separates deterministic technical evidence from model-reviewed findings", async () => {
    const report = await fixturePolicy5ReportV5();
    const html = renderReportV5Html(report);

    expect(html).toContain("Deterministic technical evidence (1)");
    expect(html).toContain("owned-structured-weakness");
    expect(html).toContain("runtime");
    expect(html).toContain("0 model calls");
    expect(html).not.toContain("Minor cautions</h3>");
    expect(html).not.toContain("Expected scanner matches");
    expect(html).toContain(
      "No material or immediate-danger item was identified",
    );
  });

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
    expect(html).toContain(report.contextual_reviewer?.model);
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
          warning_occurrences: 12,
          warning_families: 3,
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
    expect(html).toContain(
      "12 warning occurrences compacted to 3 evidence-preserving review families",
    );
    expect(html).toMatch(/no clean conclusion/iu);
    expect(html).toContain("dist/app.min.js");
    expect(html).not.toContain("derived/000001-");
  });

  test("renders fresh and reused review counts with source report IDs", async () => {
    const sourceReportId = "e".repeat(64);
    const report = await fixtureReportV5({
      review_reuse: {
        groups: { fresh: 0, reused: 1 },
        candidates: { fresh: 0, reused: 0 },
        source_report_ids: [sourceReportId],
      },
    });
    const html = renderReportV5Html(report);

    expect(html).toContain("0 fresh / 1 reused groups");
    expect(html).toContain("0 fresh / 0 reused candidates");
    expect(html).toContain(sourceReportId);
  });

  test("renders the model-call count and batch density", async () => {
    const base = await fixtureReportV5();
    const report = await fixtureReportV5({
      review_batches: [
        {
          kind: "contextual_review",
          attempt: 1,
          group_count: 5,
          candidate_count: 8,
          estimated_input_tokens: 900,
          over_budget: false,
          input_tokens: base.review_usage.input_tokens,
          output_tokens: base.review_usage.output_tokens,
          cache_read_tokens: base.review_usage.cache_read_tokens,
          reasoning_tokens: base.review_usage.reasoning_tokens,
        },
      ],
    });
    const html = renderReportV5Html(report);

    expect(html).toContain("1 model call");
    expect(html).toContain("up to 5 groups and 8 candidates per call");
    expect(html).toContain("0 retry calls");
  });
});
