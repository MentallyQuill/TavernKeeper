import { describe, expect, test } from "vitest";

import {
  ReportIndexSchema,
  ScanReportSchema,
} from "../src/contracts/reports.js";
import { TargetManifestSchema } from "../src/contracts/targets.js";

const fullSha = "a".repeat(40);

describe("public contracts", () => {
  test("accepts exact-SHA Tavernary targets and rejects branch names", () => {
    const manifest = {
      schema_version: 1,
      generated_at: "2026-07-31T12:00:00.000Z",
      repositories: [
        {
          source_id: "github-42",
          provider: "github",
          repository_id: 42,
          repository: "owner/repo",
          target_sha: fullSha,
          canonical_url: "https://github.com/owner/repo",
        },
      ],
    };

    expect(TargetManifestSchema.safeParse(manifest).success).toBe(true);
    expect(
      TargetManifestSchema.safeParse({
        ...manifest,
        repositories: [{ ...manifest.repositories[0], target_sha: "main" }],
      }).success,
    ).toBe(false);
  });

  test("requires advisory statuses and sanitized normalized findings", () => {
    const report = {
      schema_version: 1,
      scanner_version: "0.1.0",
      source_id: "github-42",
      provider: "github",
      repository_id: 42,
      repository: "owner/repo",
      target_sha: fullSha,
      scanned_at: "2026-07-31T12:05:00.000Z",
      mode: "standard",
      status: "review-suggested",
      summary: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
      coverage: {
        complete: true,
        history_commits: 20,
        inventory: { files: 3, bytes: 120 },
        tools: [{ name: "built-in", status: "completed", version: "0.1.0" }],
        model: { status: "disabled", provider: null, model: null },
      },
      findings: [
        {
          detector: "built-in",
          rule_id: "credential-exfiltration",
          severity: "high",
          path: "src/index.ts",
          line: 7,
          title: "Credential read followed by network send",
          evidence: "process.env.[REDACTED] -> fetch(â€¦)",
          fingerprint: "b".repeat(64),
        },
      ],
    };

    expect(ScanReportSchema.safeParse(report).success).toBe(true);
    expect(
      ScanReportSchema.safeParse({ ...report, status: "safe" }).success,
    ).toBe(false);
    expect(
      ReportIndexSchema.safeParse({
        schema_version: 1,
        generated_at: report.scanned_at,
        reports: [
          {
            source_id: report.source_id,
            provider: report.provider,
            repository_id: report.repository_id,
            repository: report.repository,
            target_sha: report.target_sha,
            scanned_at: report.scanned_at,
            mode: report.mode,
            status: report.status,
            summary: report.summary,
            coverage: { complete: true },
            report_url: `https://mentallyquill.github.io/TavernKeeper/reports/github/42/${fullSha}/`,
          },
        ],
      }).success,
    ).toBe(true);
  });
});
