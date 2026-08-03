import { readFile } from "node:fs/promises";

import { describe, expect, test } from "vitest";

import type { ScanReportV4 } from "../src/contracts/reports.js";
import { reportIdentity } from "../src/publish/report-path.js";
import { renderReportHtml } from "../src/publish/render-report.js";

async function reportWithFinding() {
  const raw = JSON.parse(
    await readFile(
      new URL("./fixtures/contracts/report.v4.valid.json", import.meta.url),
      "utf8",
    ),
  ) as ScanReportV4;
  const report = {
    ...raw,
    result: "red" as const,
    summary: {
      headline: "Reportable concerns detected",
      detail: "1 reportable concern met the deterministic threshold.",
    },
    coverage: {
      ...raw.coverage,
      evidence_validation: {
        status: "completed" as const,
        validated_findings: 1,
      },
    },
    finding_counts: {
      total: 1,
      reportable: 1,
      informational: 0,
      reportable_severity: { critical: 0, high: 1, medium: 0 },
      severity: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
      confidence: { high: 1, medium: 0, low: 0 },
      policy_status: { reportable: 1, informational: 0 },
      categories: [{ category: "credential-theft", count: 1 }],
    },
    findings: [
      {
        origin: "tavernkeeper",
        rule_id: "credential-exfiltration",
        category: "credential-theft",
        severity: "high" as const,
        confidence: "high" as const,
        policy_status: "reportable" as const,
        path: "src/index.ts",
        line_start: 7,
        line_end: 7,
        evidence_sha: null,
        title: 'Comparison: 2 < 3 & "quoted" > baseline',
        explanation:
          "Credential access and outbound transmission were detected.",
        remediation: "Review the data flow and remove unintended transmission.",
        fingerprint: "b".repeat(64),
      },
    ],
  };
  return { ...report, report_id: reportIdentity(report) };
}

describe("static deterministic report rendering", () => {
  test("renders full V4 evidence and script-free restrictive HTML", async () => {
    const report = await reportWithFinding();
    const html = renderReportHtml(report);
    expect(html).toContain("Content-Security-Policy");
    expect(html).toContain("default-src &#39;none&#39;");
    expect(html).not.toMatch(/<script\b/iu);
    expect(html).not.toMatch(/<img\b/iu);
    expect(html).toContain(report.target_sha);
    expect(html).toContain("deterministic-static-analysis");
    expect(html).toContain("tavernkeeper-static");
    expect(html).toContain("dependency lockfiles");
    expect(html).toContain("reportable");
    expect(html).toContain("Review the data flow");
    expect(html).toContain(
      "Comparison: 2 &lt; 3 &amp; &quot;quoted&quot; &gt; baseline",
    );
    expect(html).toContain("not a safety certification");
  });

  test("links only to the repository, immutable commit, and Tavernary", async () => {
    const report = await reportWithFinding();
    const links = [
      ...renderReportHtml(report).matchAll(/href="([^"]+)"/gu),
    ].map((match) => match[1]);
    expect(links).toEqual([
      "https://github.com/owner/repo",
      `https://github.com/owner/repo/commit/${report.target_sha}`,
      "https://tavernary.org/",
    ]);
  });
});
