import { describe, expect, test } from "vitest";

import { sanitizeReportV5 } from "../src/publish/sanitize.js";
import { fixtureReportV5 } from "./helpers/v5-report.js";

describe("V5 report publication sanitizer", () => {
  test("accepts a complete body-bound contextual report", async () => {
    const report = await fixtureReportV5();
    expect(sanitizeReportV5(report)).toEqual(report);
  });

  test("rejects unknown fields and mismatched immutable identities", async () => {
    const report = await fixtureReportV5();
    expect(() =>
      sanitizeReportV5({ ...report, raw_model_response: "hidden" }),
    ).toThrow(/schema/iu);
    expect(() =>
      sanitizeReportV5({ ...report, report_id: "f".repeat(64) }),
    ).toThrow(/identity|schema/iu);
  });
});
