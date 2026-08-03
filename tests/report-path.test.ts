import { readFile } from "node:fs/promises";

import { describe, expect, test } from "vitest";

import type { ScanReportV4 } from "../src/contracts/reports.js";
import {
  historyPath,
  historyUrl,
  reportIdentity,
  reportPath,
  reportUrl,
} from "../src/publish/report-path.js";

async function fixtureReport() {
  const raw = JSON.parse(
    await readFile(
      new URL("./fixtures/contracts/report.v4.valid.json", import.meta.url),
      "utf8",
    ),
  ) as ScanReportV4;
  return { ...raw, report_id: reportIdentity(raw) };
}

describe("immutable V4 report identity", () => {
  test("derives the canonical no-mode path and public URL", async () => {
    const report = await fixtureReport();
    expect(reportIdentity(report)).toMatch(/^[0-9a-f]{64}$/u);
    expect(reportPath(report)).toBe(
      `reports/github/42/${report.target_sha}/2/1`,
    );
    expect(reportUrl(report)).toBe(
      `https://mentallyquill.github.io/TavernKeeper/reports/github/42/${report.target_sha}/2/1/`,
    );
    expect(historyPath(report)).toBe("reports/github/42/history");
    expect(historyUrl(report)).toBe(
      "https://mentallyquill.github.io/TavernKeeper/reports/github/42/history/",
    );
  });

  test("binds identity to the complete V4 public body except report_id", async () => {
    const report = await fixtureReport();
    const identity = reportIdentity(report);
    expect(reportIdentity({ ...report, report_id: "f".repeat(64) })).toBe(
      identity,
    );
    expect(
      reportIdentity({
        ...report,
        summary: { ...report.summary, detail: "A different safe detail." },
      }),
    ).not.toBe(identity);
  });
});
