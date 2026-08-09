import { describe, expect, test } from "vitest";

import type { ReportIndexV5 } from "../src/contracts/reports-v5.js";
import type { TargetManifestV3, TargetV3 } from "../src/contracts/targets.js";
import { failureFingerprint } from "../src/operations/failure.js";
import { migrateOperationsState } from "../src/operations/migrate-state.js";

const at = "2026-08-04T12:00:00.000Z";
const initialFailedAt = "2026-08-01T00:00:00.000Z";
const emptyIndex: ReportIndexV5 = {
  schema_version: 5,
  generated_at: at,
  reports: [],
};

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
  test("baselines ordinary catalog entries while restoring legacy retries", () => {
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
      scan_queue: { next_ticket: 2 },
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
    ).toEqual([[41, 1]]);
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
