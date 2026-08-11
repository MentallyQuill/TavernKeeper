import { describe, expect, test } from "vitest";

import { selectPolicyRescanRepositoryIds } from "../src/cli/policy-rescan.js";
import type {
  ReportIndexEntryV5,
  ReportIndexV5,
} from "../src/contracts/reports-v5.js";
import type {
  CurrentTarget,
  CurrentTargetManifest,
} from "../src/contracts/targets.js";

function target(repositoryId: number): CurrentTarget {
  return {
    source_id: `github-${repositoryId}`,
    provider: "github",
    repository_id: repositoryId,
    repository: `owner/repo-${repositoryId}`,
    target_sha: repositoryId.toString(16).padStart(40, "0"),
    canonical_url: `https://github.com/owner/repo-${repositoryId}`,
    project_kinds: ["extension"],
    catalog_priority: {
      top_30: false,
      first_cataloged_at: "2026-01-01T00:00:00.000Z",
    },
  };
}

function manifest(...repositoryIds: number[]): CurrentTargetManifest {
  return {
    schema_version: 2,
    generated_at: "2026-08-10T12:00:00.000Z",
    repositories: repositoryIds.map(target),
  };
}

function report(
  repositoryId: number,
  recommendedRisk: "low" | "material" | "high",
): ReportIndexEntryV5 {
  const reportId = repositoryId.toString(16).padStart(64, "0");
  const targetSha = repositoryId.toString(16).padStart(40, "0");
  const selected = recommendedRisk === "low" ? 0 : 1;
  return {
    report_id: reportId,
    report_digest: reportId,
    report_version: 1,
    supersedes_report_id: null,
    scanner_version: "1.0.0",
    scanner_policy_version: "5",
    rule_catalog_version: "1",
    package_schema_version: 1,
    contextual_review_policy_version: "5",
    ecosystem_context_version: "sillytavern-community-v1",
    prompt_version: "contextual-review-v7",
    assessment_schema_version: "contextual-assessment-v2",
    source_id: `github-${repositoryId}`,
    provider: "github",
    repository_id: repositoryId,
    repository: `owner/repo-${repositoryId}`,
    target_sha: targetSha,
    completed_at: "2026-08-10T12:00:00.000Z",
    assessment_method: "deterministic-evidence-contextual-review",
    counts: {
      candidates: selected,
      assessments: selected,
      observations: 0,
      items: selected,
      disposition: {
        expected_behavior: 0,
        minor_weakness: 0,
        material_vulnerability: recommendedRisk === "material" ? 1 : 0,
        credible_malicious_behavior: recommendedRisk === "high" ? 1 : 0,
      },
      impact: {
        none: 0,
        low: 0,
        medium: recommendedRisk === "material" ? 1 : 0,
        high: recommendedRisk === "high" ? 1 : 0,
        critical: 0,
      },
      exploitability: {
        unlikely: 0,
        plausible: selected,
        readily_exploitable: 0,
      },
      confidence: { low: 0, medium: 0, high: selected },
      recommended_risk: {
        low: 0,
        material: recommendedRisk === "material" ? 1 : 0,
        high: recommendedRisk === "high" ? 1 : 0,
      },
    },
    coverage: {
      history_commits: 1,
      inventory_files: 1,
      inventory_bytes: 1,
      tools_completed: 7,
      tools_not_applicable: 0,
      evidence_validated: selected,
      metadata_only_candidates: 0,
      review_required: selected,
      review_completed: selected,
      javascript_analysis_status: "complete",
    },
    report_url:
      `https://mentallyquill.github.io/TavernKeeper/reports/github/` +
      `${repositoryId}/${targetSha}/5/${reportId}/`,
    history_url:
      `https://mentallyquill.github.io/TavernKeeper/reports/github/` +
      `${repositoryId}/history/`,
  };
}

function index(...reports: ReportIndexEntryV5[]): ReportIndexV5 {
  return {
    schema_version: 5,
    generated_at: "2026-08-10T12:00:00.000Z",
    reports,
  };
}

describe("policy rescan repository selection", () => {
  test("all preserves target manifest order", () => {
    expect(
      selectPolicyRescanRepositoryIds({
        scope: "all",
        manifest: manifest(100, 200, 400),
        index: index(report(400, "high"), report(100, "low")),
      }),
    ).toEqual([100, 200, 400]);
  });

  test("yellow preserves manifest order for material and high reports", () => {
    expect(
      selectPolicyRescanRepositoryIds({
        scope: "yellow",
        manifest: manifest(100, 200, 400),
        index: index(
          report(400, "high"),
          report(100, "low"),
          report(200, "material"),
        ),
      }),
    ).toEqual([200, 400]);
  });

  test("yellow excludes preferred reports for repositories removed from the manifest", () => {
    expect(
      selectPolicyRescanRepositoryIds({
        scope: "yellow",
        manifest: manifest(100, 200),
        index: index(report(300, "high"), report(200, "material")),
      }),
    ).toEqual([200]);
  });

  test("rejects unsupported scopes", () => {
    expect(() =>
      selectPolicyRescanRepositoryIds({
        scope: "teal",
        manifest: manifest(100),
        index: index(report(100, "low")),
      }),
    ).toThrow();
  });

  test("rejects an empty yellow campaign", () => {
    expect(() =>
      selectPolicyRescanRepositoryIds({
        scope: "yellow",
        manifest: manifest(100),
        index: index(report(100, "low")),
      }),
    ).toThrow(/yellow policy rescan selected no repositories/iu);
  });
});
