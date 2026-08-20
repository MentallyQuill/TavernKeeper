import { execFile } from "node:child_process";
import { promisify } from "node:util";

import { describe, expect, test } from "vitest";

import {
  ReviewOpportunityAnalysisSchema,
  type ReviewOpportunityAnalysis,
} from "../src/analysis/review-opportunities.js";
import {
  renderReviewOpportunitiesJson,
  renderReviewOpportunitiesMarkdown,
} from "../src/analysis/render-review-opportunities.js";
import { reviewOpportunitiesMain } from "../src/cli/review-opportunities.js";

const execFileAsync = promisify(execFile);

const analysis: ReviewOpportunityAnalysis =
  ReviewOpportunityAnalysisSchema.parse({
    schema_version: 1,
    contextual_policy_version: "5",
    attribution: {
      candidate_counts: "exact",
      corpus_usage: "exact",
      associated_usage: "overlapping-non-additive",
      per_rule_savings: "not-attributable",
    },
    corpus: {
      indexed_reports: 3,
      loaded_reports: 2,
      skipped_policy_reports: 1,
      contextual_candidates: 3,
      provider_calls: 2,
      usage: {
        input_tokens: 300,
        output_tokens: 30,
        cache_read_tokens: 60,
        reasoning_tokens: 9,
      },
      reports_with_unmapped_contextual_reuse: 1,
    },
    opportunities: [
      {
        key: {
          origin: "zizmor",
          rule_id: "artipacked",
          scanner_version: "1.28.0",
          execution_scope: "automation",
          file_role: "production",
          scanner_confidence: "high",
          triage_reason_code: "unknown-rule",
        },
        candidate_count: 3,
        repository_count: 2,
        outcomes: {
          disposition: {
            expected_behavior: 1,
            minor_weakness: 0,
            material_vulnerability: 1,
            credible_malicious_behavior: 1,
          },
          risk_exposure: { not_demonstrated: 1, demonstrated: 2 },
          recommended_risk: { low: 1, material: 1, high: 1 },
        },
        reviewer_strata: [
          {
            provider: "openrouter.ai",
            model: "zai-org/glm-latest",
            candidate_count: 3,
            report_count: 2,
          },
        ],
        associated_reports: {
          attribution: "overlapping-non-additive",
          report_count: 2,
          provider_calls: 2,
          usage: {
            input_tokens: 300,
            output_tokens: 30,
            cache_read_tokens: 60,
            reasoning_tokens: 9,
          },
        },
        references: [
          {
            repository: "owner/repo",
            repository_id: 42,
            target_sha: "a".repeat(40),
            report_id: "b".repeat(64),
            report_url:
              "https://mentallyquill.github.io/TavernKeeper/reports/github/42/" +
              `${"a".repeat(40)}/5/${"b".repeat(64)}/`,
            candidate_id: "c".repeat(64),
            path: ".github/workflows/release.yml",
          },
        ],
      },
    ],
    limitations: [
      "Public review batches do not bind provider calls or tokens to individual candidates.",
      "Opportunity-associated calls and token usage are overlapping report-level envelopes and are not additive.",
      "Public reports do not map reused contextual assessments to individual candidates.",
    ],
  });

describe("review opportunity rendering", () => {
  test("renders canonical indented JSON with one trailing newline", () => {
    expect(renderReviewOpportunitiesJson(analysis)).toBe(
      `${JSON.stringify(analysis, null, 2)}\n`,
    );
  });

  test("renders exact counts and places the non-additive warning beside associated usage", () => {
    const markdown = renderReviewOpportunitiesMarkdown(analysis);

    expect(markdown).toContain("# Contextual Review Opportunities");
    expect(markdown).toContain("Contextual candidates: 3");
    expect(markdown).toContain("`zizmor:artipacked`");
    expect(markdown).toContain("Credible malicious behavior: 1");
    expect(markdown).toContain("Demonstrated exposure: 2");
    expect(markdown).toContain("High recommended risk: 1");
    expect(markdown).toContain("Recommended risk: low 1; material 1; high 1");
    expect(markdown).toContain(
      "Reviewer stratum: `openrouter.ai` / `zai-org/glm-latest`; candidates 3; reports 2",
    );
    expect(markdown).toContain(
      "Associated usage is an overlapping, non-additive report-level envelope; do not sum it or interpret it as avoided spend.",
    );
    expect(markdown).toContain(
      "https://mentallyquill.github.io/TavernKeeper/reports/github/42/",
    );
  });

  test("uses CommonMark-safe code-span delimiters for hostile valid text", () => {
    const hostile = ReviewOpportunityAnalysisSchema.parse({
      ...analysis,
      opportunities: [
        {
          ...analysis.opportunities[0],
          references: [
            {
              ...analysis.opportunities[0]!.references[0],
              repository: " owner/rep``o ",
              path: "docs/evil`name.md\nnext",
            },
          ],
        },
      ],
    });

    const markdown = renderReviewOpportunitiesMarkdown(hostile);

    expect(markdown).toContain("```  owner/rep``o  ```");
    expect(markdown).toContain("``docs/evil`name.md next``");
    expect(markdown).not.toContain("docs/evil`name.md\nnext");
  });
});

describe("review opportunity CLI", () => {
  test.each([
    { args: [] },
    { args: ["--format"] },
    { args: ["--format", "yaml"] },
    { args: ["--format", "json", "extra"] },
  ])("rejects unsupported arguments: $args", async ({ args }) => {
    await expect(
      reviewOpportunitiesMain({ cwd: process.cwd(), args }),
    ).rejects.toThrow("Usage: review-opportunities --format <json|markdown>");
  });

  test("loads the checked-in preferred corpus and emits byte-stable canonical JSON", async () => {
    const first = await reviewOpportunitiesMain({
      cwd: process.cwd(),
      args: ["--format", "json"],
    });
    const second = await reviewOpportunitiesMain({
      cwd: process.cwd(),
      args: ["--format", "json"],
    });

    expect(second).toBe(first);
    expect(first.endsWith("\n")).toBe(true);
    expect(ReviewOpportunityAnalysisSchema.parse(JSON.parse(first))).toEqual(
      JSON.parse(first),
    );
  });

  test("the documented silent package command emits parseable JSON only", async () => {
    const windows = process.platform === "win32";
    const executable = windows ? (process.env.ComSpec ?? "cmd.exe") : "npm";
    const args = windows
      ? [
          "/d",
          "/s",
          "/c",
          "npm.cmd run --silent review-opportunities -- --format json",
        ]
      : ["run", "--silent", "review-opportunities", "--", "--format", "json"];
    const { stdout, stderr } = await execFileAsync(executable, args, {
      cwd: process.cwd(),
      maxBuffer: 5_000_000,
    });

    expect(stderr).toBe("");
    expect(ReviewOpportunityAnalysisSchema.parse(JSON.parse(stdout))).toEqual(
      JSON.parse(stdout),
    );
  });

  test("emits byte-stable Markdown from the checked-in preferred corpus", async () => {
    const first = await reviewOpportunitiesMain({
      cwd: process.cwd(),
      args: ["--format", "markdown"],
    });
    const second = await reviewOpportunitiesMain({
      cwd: process.cwd(),
      args: ["--format", "markdown"],
    });

    expect(second).toBe(first);
    expect(first).toContain("# Contextual Review Opportunities");
    expect(first.endsWith("\n")).toBe(true);
  });
});
