import { describe, expect, test } from "vitest";

import type { ScanReportV2 } from "../src/contracts/reports.js";
import { readFile } from "node:fs/promises";
import {
  historyPath,
  historyUrl,
  reportIdentity,
  reportPath,
  reportUrl,
} from "../src/publish/report-path.js";

const sha = "a".repeat(40);
const report = {
  provider: "github",
  repository_id: 42,
  target_sha: sha,
  scanner_policy_version: "1",
  mode: "standard",
  report_version: 1,
} as ScanReportV2;

describe("immutable report identity", () => {
  test("derives the exact canonical identity, path, and public URL", () => {
    expect(reportIdentity(report)).toMatch(/^[0-9a-f]{64}$/u);
    expect(reportPath(report)).toBe(`reports/github/42/${sha}/1/standard/1`);
    expect(reportUrl(report)).toBe(
      `https://mentallyquill.github.io/TavernKeeper/reports/github/42/${sha}/1/standard/1/`,
    );
    expect(historyPath(report)).toBe("reports/github/42/history");
    expect(historyUrl(report)).toBe(
      "https://mentallyquill.github.io/TavernKeeper/reports/github/42/history/",
    );
    expect(
      reportIdentity({
        ...report,
        completed_at: "2030-01-01T00:00:00.000Z",
      } as typeof report),
    ).toBe(reportIdentity(report));
  });

  test("binds V3 identity to the complete public body except report_id", async () => {
    const raw = JSON.parse(
      await readFile(
        new URL("./fixtures/contracts/report.v3.valid.json", import.meta.url),
        "utf8",
      ),
    );
    const identity = reportIdentity(raw);

    expect(reportIdentity({ ...raw, report_id: "f".repeat(64) })).toBe(
      identity,
    );
    expect(
      reportIdentity({
        ...raw,
        model_review: { ...raw.model_review, recap: "A different recap." },
      }),
    ).not.toBe(identity);
  });
});
