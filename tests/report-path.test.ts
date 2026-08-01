import { describe, expect, test } from "vitest";

import type { ScanReport } from "../src/contracts/reports.js";
import {
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
} as ScanReport;

describe("immutable report identity", () => {
  test("derives the exact canonical identity, path, and public URL", () => {
    expect(reportIdentity(report)).toMatch(/^[0-9a-f]{64}$/u);
    expect(reportPath(report)).toBe(`reports/github/42/${sha}/1/standard/1`);
    expect(reportUrl(report)).toBe(
      `https://mentallyquill.github.io/TavernKeeper/reports/github/42/${sha}/1/standard/1/`,
    );
    expect(
      reportIdentity({
        ...report,
        completed_at: "2030-01-01T00:00:00.000Z",
      } as typeof report),
    ).toBe(reportIdentity(report));
  });
});
