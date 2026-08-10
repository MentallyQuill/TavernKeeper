import { readFile } from "node:fs/promises";

import {
  ScanReportV5Schema,
  type ScanReportV5,
} from "../../src/contracts/reports-v5.js";
import {
  ReviewCacheManifestSchema,
  type ReviewCacheManifest,
} from "../../src/model/review-cache.js";
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

export function fixtureReviewCache(report: ScanReportV5): ReviewCacheManifest {
  return ReviewCacheManifestSchema.parse({
    schema_version: 1,
    repository_id: report.repository_id,
    repository: report.repository,
    source_report: {
      report_id: report.report_id,
      target_sha: report.target_sha,
      scanner_policy_version: report.scanner_policy_version,
    },
    review_identity: {
      scanner_version: report.scanner_version,
      scanner_policy_version: report.scanner_policy_version,
      rule_catalog_version: report.rule_catalog_version,
      tools: report.coverage.tools.map(({ name, version }) => ({
        name,
        version,
      })),
      contextual_policy_version: report.contextual_review_policy_version,
      prompt_version: report.prompt_version,
      assessment_schema_version: report.assessment_schema_version,
      provider: report.contextual_reviewer.provider,
      endpoint_origin: `https://${report.contextual_reviewer.provider}`,
      model: report.contextual_reviewer.model,
    },
    entries: [],
  });
}
