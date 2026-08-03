import { readFile } from "node:fs/promises";

import {
  ScanReportV5Schema,
  type ScanReportV5,
} from "../../src/contracts/reports-v5.js";
import { reportIdentity } from "../../src/publish/report-path.js";

export async function fixtureReportV5(
  overrides: Partial<ScanReportV5> = {},
): Promise<ScanReportV5> {
  const fixture = JSON.parse(
    await readFile(
      new URL("../fixtures/contracts/report.v5.valid.json", import.meta.url),
      "utf8",
    ),
  ) as ScanReportV5;
  const body = {
    ...fixture,
    ...overrides,
    report_id: "0".repeat(64),
    report_digest: "0".repeat(64),
  };
  const identity = reportIdentity(body);
  return ScanReportV5Schema.parse({
    ...body,
    report_id: identity,
    report_digest: identity,
  });
}
