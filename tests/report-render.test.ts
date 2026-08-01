import { readFile } from "node:fs/promises";

import { describe, expect, test } from "vitest";

import { reportIdentity } from "../src/publish/report-path.js";
import { renderReportHtml } from "../src/publish/render-report.js";

async function reportWithHostileText() {
  const raw = JSON.parse(
    await readFile(
      new URL("./fixtures/contracts/report.valid.json", import.meta.url),
      "utf8",
    ),
  ) as Record<string, unknown>;
  const findings = structuredClone(raw.findings) as Array<
    Record<string, unknown>
  >;
  findings[0] = {
    ...findings[0],
    title: '<img src=x onerror="alert(1)"> suspicious markup',
  };
  const report = { ...raw, findings };
  return { ...report, report_id: reportIdentity(report as never) };
}

describe("static report rendering", () => {
  test("escapes hostile values and emits script-free restrictive HTML", async () => {
    const html = renderReportHtml(await reportWithHostileText());

    expect(html).toContain("Content-Security-Policy");
    expect(html).toContain("default-src &#39;none&#39;");
    expect(html).not.toMatch(/<script\b/iu);
    expect(html).not.toMatch(/<img\b/iu);
    expect(html).not.toMatch(/<[^>]+\sonerror\s*=/iu);
    expect(html).toContain("&lt;img src=x onerror=&quot;alert(1)&quot;&gt;");
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
      "https://mentallyquill.github.io/TavernKeeper/rules/credential-exfiltration/",
      "https://tavernary.org/",
    ]);
  });
});
