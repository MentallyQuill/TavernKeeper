import { describe, expect, test } from "vitest";

import {
  historyPath,
  historyUrl,
  reportIdentity,
  reportPath,
  reportUrl,
} from "../src/publish/report-path.js";
import { fixtureReportV5 } from "./helpers/v5-report.js";

describe("immutable V5 report identity", () => {
  test("binds the complete contextual body into its report ID and path", async () => {
    const report = await fixtureReportV5();
    expect(reportIdentity(report)).toBe(report.report_id);
    expect(reportPath(report)).toBe(
      `reports/github/42/${report.target_sha}/2/${report.report_id}`,
    );
    expect(reportUrl(report)).toBe(
      `https://mentallyquill.github.io/TavernKeeper/${reportPath(report)}/`,
    );
    expect(historyPath(report)).toBe("reports/github/42/history");
    expect(historyUrl(report)).toBe(
      "https://mentallyquill.github.io/TavernKeeper/reports/github/42/history/",
    );

    const changed = {
      ...report,
      limitations: ["A different advisory limitation applies."],
    };
    expect(reportIdentity(changed)).not.toBe(report.report_id);
  });
});
