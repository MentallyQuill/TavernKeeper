import { readFile } from "node:fs/promises";

import { describe, expect, test } from "vitest";

import type { ScanReport } from "../src/contracts/reports.js";
import { reportIdentity } from "../src/publish/report-path.js";
import { sanitizeReport } from "../src/publish/sanitize.js";

async function validReport() {
  const raw = JSON.parse(
    await readFile(
      new URL("./fixtures/contracts/report.valid.json", import.meta.url),
      "utf8",
    ),
  ) as Record<string, unknown>;
  return {
    ...raw,
    report_id: reportIdentity(raw as never),
  } as unknown as ScanReport;
}

describe("public report sanitizer", () => {
  test("accepts a complete schema-valid report with its canonical identity", async () => {
    const report = await validReport();

    expect(sanitizeReport(report)).toEqual(report);
  });

  test("does not mistake repository identity text for a model safety claim", async () => {
    const report = await validReport();
    const renamed = {
      ...report,
      repository: "owner/safe-project",
      canonical_url: "https://github.com/owner/safe-project",
    };

    expect(sanitizeReport(renamed)).toEqual(renamed);
  });

  test.each([
    [
      "secret-shaped output",
      "Leaked token ghp_abcdefghijklmnopqrstuvwxyz1234567890AB",
    ],
    [
      "local filesystem path",
      String.raw`Read C:\Users\operator\.config\secret`,
    ],
    ["source excerpt", "const stolen = process.env.TOKEN;"],
    ["unapproved URL", "Uploaded data to https://attacker.example/collect"],
    ["safety claim", "This repository is verified safe for installation."],
    ["control character", "Unexpected\u0000model output"],
  ])("rejects %s", async (_label, explanation) => {
    const report = await validReport();
    const findings = structuredClone(report.findings) as Array<
      Record<string, unknown>
    >;
    findings[0] = { ...findings[0], explanation };

    expect(() => sanitizeReport({ ...report, findings })).toThrow(
      /public report rejected/iu,
    );
  });

  test("rejects a report ID that does not match the immutable identity", async () => {
    const report = await validReport();

    expect(() =>
      sanitizeReport({ ...report, report_id: "f".repeat(64) }),
    ).toThrow(/report identity/iu);
  });

  test("rejects a rule link that normalizes outside public rule documentation", async () => {
    const report = await validReport();
    const findings = structuredClone(report.findings);
    findings[0] = {
      ...findings[0]!,
      reference_url:
        "https://mentallyquill.github.io/TavernKeeper/rules/../../unexpected",
    };

    expect(() => sanitizeReport({ ...report, findings })).toThrow(
      /public report rejected/iu,
    );
  });

  test("rejects unknown report fields and derived-result drift", async () => {
    const report = await validReport();

    expect(() => sanitizeReport({ ...report, raw_source: "hidden" })).toThrow(
      /public report rejected/iu,
    );
    expect(() => sanitizeReport({ ...report, result: "green" })).toThrow(
      /public report rejected/iu,
    );
  });
});
