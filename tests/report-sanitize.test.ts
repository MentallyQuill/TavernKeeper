import { readFile } from "node:fs/promises";

import { describe, expect, test } from "vitest";

import type { ScanReportV4 } from "../src/contracts/reports.js";
import { reportIdentity } from "../src/publish/report-path.js";
import { sanitizeReportV4 } from "../src/publish/sanitize.js";

async function validReport() {
  const raw = JSON.parse(
    await readFile(
      new URL("./fixtures/contracts/report.v4.valid.json", import.meta.url),
      "utf8",
    ),
  ) as ScanReportV4;
  return { ...raw, report_id: reportIdentity(raw) };
}

describe("deterministic public report sanitizer", () => {
  test("accepts a complete V4 report with its body-bound identity", async () => {
    const report = await validReport();
    expect(sanitizeReportV4(report)).toEqual(report);
  });

  test.each([
    ["secret", "Leaked ghp_abcdefghijklmnopqrstuvwxyz1234567890AB"],
    ["local path", String.raw`Read C:\Users\operator\.config\secret`],
    ["source", "const stolen = process.env.TOKEN;"],
    ["URL", "Uploaded data to https://attacker.example/collect"],
    ["safety claim", "This repository is verified safe for installation."],
    ["control", "Unexpected\u0000output"],
    ["HTML", '<img src=x onerror="alert(1)">'],
  ])("rejects %s in generated public text", async (_label, detail) => {
    const report = await validReport();
    const changed = {
      ...report,
      summary: { ...report.summary, detail },
    };
    expect(() =>
      sanitizeReportV4({ ...changed, report_id: reportIdentity(changed) }),
    ).toThrow(/public report rejected/iu);
  });

  test("rejects model-era fields and unknown raw evidence", async () => {
    const report = await validReport();
    expect(() => sanitizeReportV4({ ...report, model_review: {} })).toThrow(
      /public report rejected/iu,
    );
    expect(() => sanitizeReportV4({ ...report, raw_source: "hidden" })).toThrow(
      /public report rejected/iu,
    );
  });

  test("rejects an identity mismatch", async () => {
    const report = await validReport();
    expect(() =>
      sanitizeReportV4({ ...report, report_id: "f".repeat(64) }),
    ).toThrow(/report identity/iu);
  });
});
