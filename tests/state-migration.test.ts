import { describe, expect, test } from "vitest";

import type { ReportIndexV5 } from "../src/contracts/reports-v5.js";
import type { TargetManifestV3, TargetV3 } from "../src/contracts/targets.js";
import { failureFingerprint } from "../src/operations/failure.js";
import { migrateOperationsState } from "../src/operations/migrate-state.js";
import {
  COVERAGE_CAMPAIGN_ID,
  parseOperationsState,
} from "../src/operations/state.js";

const at = "2026-08-04T12:00:00.000Z";
const initialFailedAt = "2026-08-01T00:00:00.000Z";
const emptyIndex: ReportIndexV5 = {
  schema_version: 5,
  generated_at: at,
  reports: [],
};

function indexWithReport(targetValue: TargetV3): ReportIndexV5 {
  const reportId = targetValue.repository_id.toString(16).padStart(64, "0");
  return {
    schema_version: 5,
    generated_at: at,
    reports: [
      {
        report_id: reportId,
        report_digest: reportId,
        report_version: 1,
        supersedes_report_id: null,
        scanner_version: "1.0.0",
        scanner_policy_version: "3",
        rule_catalog_version: "1",
        package_schema_version: 1,
        contextual_review_policy_version: "1",
        ecosystem_context_version: "sillytavern-community-v1",
        prompt_version: "contextual-review-v1",
        assessment_schema_version: "contextual-assessment-v1",
        source_id: targetValue.source_id,
        provider: "github",
        repository_id: targetValue.repository_id,
        repository: targetValue.repository,
        target_sha: targetValue.target_sha,
        completed_at: "2026-08-04T08:00:00.000Z",
        assessment_method: "deterministic-evidence-contextual-review",
        counts: {
          candidates: 0,
          assessments: 0,
          observations: 0,
          items: 0,
          disposition: {
            expected_behavior: 0,
            minor_weakness: 0,
            material_vulnerability: 0,
            credible_malicious_behavior: 0,
          },
          impact: { none: 0, low: 0, medium: 0, high: 0, critical: 0 },
          exploitability: {
            unlikely: 0,
            plausible: 0,
            readily_exploitable: 0,
          },
          confidence: { high: 0, medium: 0, low: 0 },
          recommended_risk: { low: 0, material: 0, high: 0 },
        },
        coverage: {
          history_commits: 1,
          inventory_files: 1,
          inventory_bytes: 1,
          tools_completed: 4,
          tools_not_applicable: 3,
          evidence_validated: 0,
          metadata_only_candidates: 0,
          review_required: 0,
          review_completed: 0,
          javascript_analysis_status: "legacy",
        },
        report_url:
          "https://mentallyquill.github.io/TavernKeeper/reports/github/" +
          `${targetValue.repository_id}/${targetValue.target_sha}/3/${reportId}/`,
        history_url:
          "https://mentallyquill.github.io/TavernKeeper/reports/github/" +
          `${targetValue.repository_id}/history/`,
      },
    ],
  };
}

function target(repositoryId: number, rank: number): TargetV3 {
  return {
    source_id: `github-${repositoryId}`,
    provider: "github",
    repository_id: repositoryId,
    repository: `owner/repo-${repositoryId}`,
    target_sha: String(repositoryId % 10).repeat(40),
    canonical_url: `https://github.com/owner/repo-${repositoryId}`,
    project_kinds: ["extension"],
    catalog_priority: {
      top_30: rank <= 30,
      first_cataloged_at: "2026-07-01T00:00:00.000Z",
      popularity_rank: rank,
    },
  };
}

function manifest(...targets: TargetV3[]): TargetManifestV3 {
  return {
    schema_version: 3,
    generated_at: at,
    repositories: [...targets].sort(
      (left, right) => left.repository_id - right.repository_id,
    ),
  };
}

function v2Retry(targetValue: TargetV3, exhausted = false) {
  const failure = {
    code: "SCANNER_FAILED",
    domain: "target" as const,
    component: "opengrep" as const,
  };
  return {
    source_id: targetValue.source_id,
    repository_id: targetValue.repository_id,
    repository: targetValue.repository,
    target_sha: targetValue.target_sha,
    failure,
    error_fingerprint: failureFingerprint(failure),
    initial_failed_at: initialFailedAt,
    last_failed_at: "2026-08-04T08:00:00.000Z",
    attempt: exhausted ? 4 : 3,
    next_retry_at: exhausted ? null : "2026-08-04T10:00:00.000Z",
    exhausted,
  };
}

function v2State(
  targets: TargetV3[],
  pause: null | {
    kind: "staff" | "system";
    reason_code: string;
    paused_at: string;
  } = null,
  sharedHolds: Array<{
    error_fingerprint: string;
    failure: {
      code: string;
      domain: "target" | "shared" | "security";
      component: "contextual-model";
    };
    first_failed_at: string;
    last_failed_at: string;
    consecutive_failures: number;
    next_probe_at: string;
    notified: boolean;
  }> = [],
) {
  return {
    schema_version: 2,
    updated_at: "2026-08-04T08:00:00.000Z",
    coverage_started_at: "2026-08-03T16:00:00.000Z",
    pause,
    target_retries: targets.map((value) => v2Retry(value, true)),
    shared_holds: sharedHolds,
    active_scans: [],
    policy_campaigns: [],
  };
}

describe("automatic operations-state migration", () => {
  test("defaults an older schema-3 document to no coverage campaigns", () => {
    const parsed = parseOperationsState({
      schema_version: 3,
      updated_at: at,
      coverage_started_at: null,
      emergency_stop: null,
      automatic_holds: [],
      catalog_observation: null,
      scan_queue: { next_ticket: 1, entries: [] },
      active_scans: [],
      policy_campaigns: [],
    });

    expect(parsed.coverage_campaigns).toEqual([]);
  });

  test("accepts one bounded coverage campaign with an exact union", () => {
    const parsed = parseOperationsState({
      schema_version: 3,
      updated_at: at,
      coverage_started_at: null,
      emergency_stop: null,
      automatic_holds: [],
      catalog_observation: null,
      scan_queue: { next_ticket: 1, entries: [] },
      active_scans: [],
      policy_campaigns: [],
      coverage_campaigns: [
        {
          id: COVERAGE_CAMPAIGN_ID,
          scanner_policy_version: "3",
          created_at: at,
          status: "active",
          popular_repository_ids: [1, 3],
          latest_release_repository_ids: [2, 3],
          repository_ids: [1, 2, 3],
          remaining_repository_ids: [2, 3],
        },
      ],
    });

    expect(parsed.coverage_campaigns[0]).toMatchObject({
      repository_ids: [1, 2, 3],
      remaining_repository_ids: [2, 3],
    });
  });

  test.each([
    {
      name: "oversized popular selection",
      popular: Array.from({ length: 21 }, (_, index) => index + 1),
      latest: [],
      selected: Array.from({ length: 21 }, (_, index) => index + 1),
      remaining: Array.from({ length: 21 }, (_, index) => index + 1),
      status: "active",
    },
    {
      name: "duplicate component ID",
      popular: [1, 1],
      latest: [],
      selected: [1],
      remaining: [1],
      status: "active",
    },
    {
      name: "unsorted component IDs",
      popular: [2, 1],
      latest: [],
      selected: [1, 2],
      remaining: [1, 2],
      status: "active",
    },
    {
      name: "inexact union",
      popular: [1],
      latest: [2],
      selected: [1],
      remaining: [1],
      status: "active",
    },
    {
      name: "remaining ID outside selection",
      popular: [1],
      latest: [],
      selected: [1],
      remaining: [1, 2],
      status: "active",
    },
    {
      name: "unsorted remaining IDs",
      popular: [1, 2],
      latest: [],
      selected: [1, 2],
      remaining: [2, 1],
      status: "active",
    },
    {
      name: "active status with no remaining members",
      popular: [1],
      latest: [],
      selected: [1],
      remaining: [],
      status: "active",
    },
    {
      name: "completed status with a remaining member",
      popular: [1],
      latest: [],
      selected: [1],
      remaining: [1],
      status: "completed",
    },
  ])("rejects a coverage campaign with $name", (fixture) => {
    expect(() =>
      parseOperationsState({
        schema_version: 3,
        updated_at: at,
        coverage_started_at: null,
        emergency_stop: null,
        automatic_holds: [],
        catalog_observation: null,
        scan_queue: { next_ticket: 1, entries: [] },
        active_scans: [],
        policy_campaigns: [],
        coverage_campaigns: [
          {
            id: COVERAGE_CAMPAIGN_ID,
            scanner_policy_version: "3",
            created_at: at,
            status: fixture.status,
            popular_repository_ids: fixture.popular,
            latest_release_repository_ids: fixture.latest,
            repository_ids: fixture.selected,
            remaining_repository_ids: fixture.remaining,
          },
        ],
      }),
    ).toThrow();
  });

  test("queues ordinary freshness while restoring exact legacy retries", () => {
    const failed = target(41, 1);
    const healthy = target(42, 2);
    const migrated = migrateOperationsState(v2State([failed]), {
      manifest: manifest(failed, healthy),
      index: emptyIndex,
      at,
      scannerPolicyVersion: "3",
    });

    expect(migrated.state).toMatchObject({
      schema_version: 3,
      emergency_stop: null,
      scan_queue: { next_ticket: 3 },
    });
    expect(migrated.state.catalog_observation?.repositories).toEqual([
      { repository_id: 41, target_sha: failed.target_sha },
      { repository_id: 42, target_sha: healthy.target_sha },
    ]);
    expect(
      migrated.state.scan_queue.entries.map(({ repository_id, ticket }) => [
        repository_id,
        ticket,
      ]),
    ).toEqual([
      [42, 1],
      [41, 2],
    ]);
    expect(
      migrated.state.scan_queue.entries.find(
        ({ repository_id }) => repository_id === 41,
      ),
    ).toMatchObject({
      consecutive_failures: 4,
      total_failures: 4,
      chronic: false,
      last_failure: { component: "opengrep" },
    });
  });

  test("drops a stale retry but queues its missing current-SHA report", () => {
    const stale = { ...target(41, 1), target_sha: "a".repeat(40) };
    const current = { ...stale, target_sha: "b".repeat(40) };

    const migrated = migrateOperationsState(v2State([stale]), {
      manifest: manifest(current),
      index: indexWithReport(stale),
      at,
      scannerPolicyVersion: "3",
    });

    expect(migrated.state.catalog_observation?.repositories).toEqual([
      { repository_id: 41, target_sha: current.target_sha },
    ]);
    expect(migrated.state.scan_queue).toEqual({
      next_ticket: 2,
      entries: [
        expect.objectContaining({
          repository_id: 41,
          target_sha: current.target_sha,
          consecutive_failures: 0,
          catalog_change: "updated",
          rescan_not_before: "2026-08-11T08:00:00.000Z",
        }),
      ],
    });
    expect(migrated.summary.legacy_retries_preserved).toBe(0);
  });

  test("normalizes duplicate retries independently of input order", () => {
    const current = target(41, 1);
    const stale = { ...current, target_sha: "a".repeat(40) };
    const exactLow = { ...v2Retry(current), attempt: 2 };
    const exactHigh = { ...v2Retry(current, true), attempt: 4 };
    const staleHigh = { ...v2Retry(stale, true), attempt: 4 };
    const permutations = [
      [exactLow, staleHigh, exactHigh],
      [exactHigh, staleHigh, exactLow],
    ];

    for (const targetRetries of permutations) {
      const migrated = migrateOperationsState(
        { ...v2State([]), target_retries: targetRetries },
        {
          manifest: manifest(current),
          index: emptyIndex,
          at,
          scannerPolicyVersion: "3",
        },
      );

      expect(migrated.state.scan_queue.entries).toEqual([
        expect.objectContaining({
          repository_id: 41,
          target_sha: current.target_sha,
          consecutive_failures: 4,
          total_failures: 4,
        }),
      ]);
      expect(migrated.summary.legacy_retries_preserved).toBe(1);
    }
  });

  test("drops removed and mismatched retries but queues current freshness", () => {
    const current = target(41, 1);
    const mismatched = { ...current, target_sha: "a".repeat(40) };
    const removed = target(42, 2);
    const migrated = migrateOperationsState(
      {
        ...v2State([]),
        target_retries: [v2Retry(mismatched, true), v2Retry(removed, true)],
      },
      {
        manifest: manifest(current),
        index: emptyIndex,
        at,
        scannerPolicyVersion: "3",
      },
    );

    expect(migrated.state.scan_queue.entries).toEqual([
      expect.objectContaining({
        repository_id: 41,
        target_sha: current.target_sha,
        consecutive_failures: 0,
      }),
    ]);
    expect(migrated.summary.legacy_retries_preserved).toBe(0);
  });

  test("converts an automatic security stop into an immediately due probe", () => {
    const failed = target(41, 1);
    const migrated = migrateOperationsState(
      v2State([failed], {
        kind: "system",
        reason_code: "SECURITY_HOLD",
        paused_at: initialFailedAt,
      }),
      {
        manifest: manifest(failed),
        index: emptyIndex,
        at,
        scannerPolicyVersion: "3",
      },
    );

    expect(migrated.state.emergency_stop).toBeNull();
    expect(migrated.state.automatic_holds).toEqual([
      expect.objectContaining({
        failure: expect.objectContaining({
          code: "SECURITY_HOLD",
          domain: "security",
        }),
        consecutive_failures: 1,
        next_probe_at: at,
        chronic: false,
      }),
    ]);
    expect(migrated.state.scan_queue.entries).toEqual([
      expect.objectContaining({ repository_id: 41, consecutive_failures: 4 }),
    ]);
    expect(migrated.summary).toMatchObject({
      migrated_from: 2,
      automatic_stops_cleared: 1,
      automatic_holds_preserved: 1,
      legacy_retries_preserved: 1,
    });
  });

  test("preserves only an explicit staff emergency stop", () => {
    const migrated = migrateOperationsState(
      v2State([], {
        kind: "staff",
        reason_code: "STAFF_PAUSE",
        paused_at: initialFailedAt,
      }),
      {
        manifest: manifest(target(41, 1)),
        index: emptyIndex,
        at,
        scannerPolicyVersion: "3",
      },
    );

    expect(migrated.state.emergency_stop).toEqual({
      kind: "staff",
      reason_code: "STAFF_PAUSE",
      paused_at: initialFailedAt,
    });
  });

  test("preserves a legacy shared hold as a finite automatic circuit", () => {
    const failure = {
      code: "MODEL_PROVIDER",
      domain: "shared" as const,
      component: "contextual-model" as const,
    };
    const migrated = migrateOperationsState(
      v2State([], null, [
        {
          error_fingerprint: failureFingerprint(failure),
          failure,
          first_failed_at: initialFailedAt,
          last_failed_at: "2026-08-04T11:45:00.000Z",
          consecutive_failures: 5,
          next_probe_at: "2026-08-04T13:00:00.000Z",
          notified: true,
        },
      ]),
      {
        manifest: manifest(target(41, 1)),
        index: emptyIndex,
        at,
        scannerPolicyVersion: "3",
      },
    );

    expect(migrated.state.automatic_holds).toEqual([
      expect.objectContaining({
        error_fingerprint: failureFingerprint(failure),
        failure,
        consecutive_failures: 5,
        next_probe_at: "2026-08-04T13:00:00.000Z",
        chronic: true,
      }),
    ]);
    expect(migrated.summary.automatic_holds_preserved).toBe(1);
  });
});
