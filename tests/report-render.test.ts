import { readFile } from "node:fs/promises";

import { describe, expect, test } from "vitest";

import { reportIdentity } from "../src/publish/report-path.js";
import { renderReportHtml } from "../src/publish/render-report.js";

async function reportWithHostileText() {
  const raw = JSON.parse(
    await readFile(
      new URL("./fixtures/contracts/report.v3.valid.json", import.meta.url),
      "utf8",
    ),
  ) as Record<string, unknown>;
  const modelReview = structuredClone(raw.model_review) as {
    concerns: Array<Record<string, unknown>>;
  };
  modelReview.concerns[0] = {
    ...modelReview.concerns[0],
    title: 'Comparison: 2 < 3 & "quoted" > baseline',
  };
  const report = { ...raw, model_review: modelReview };
  return { ...report, report_id: reportIdentity(report as never) };
}

describe("static report rendering", () => {
  test("escapes accepted special characters and emits script-free restrictive HTML", async () => {
    const html = renderReportHtml(await reportWithHostileText());

    expect(html).toContain("Content-Security-Policy");
    expect(html).toContain("default-src &#39;none&#39;");
    expect(html).not.toMatch(/<script\b/iu);
    expect(html).not.toMatch(/<img\b/iu);
    expect(html).not.toMatch(/<[^>]+\sonerror\s*=/iu);
    expect(html).toContain(
      "Comparison: 2 &lt; 3 &amp; &quot;quoted&quot; &gt; baseline",
    );
    expect(html).toContain("not a safety certification");
  });

  test("links only to the repository, immutable commit, rule docs, and Tavernary", async () => {
    const html = renderReportHtml(await reportWithHostileText());
    const links = [...html.matchAll(/href="([^"]+)"/gu)].map(
      (match) => match[1],
    );

    expect(links).toEqual([
      "https://github.com/owner/repo",
      `https://github.com/owner/repo/commit/${"a".repeat(40)}`,
      "https://tavernary.org/",
    ]);
  });
});
