import { describe, expect, test } from "vitest";

import type { TargetManifestV3, TargetV3 } from "../src/contracts/targets.js";
import { buildScanClaims } from "../src/cli/claim-scans.js";
import {
  initialOperationsState,
  pauseSystem,
} from "../src/operations/state.js";
import { recordFailure } from "../src/operations/retry.js";
import { appendQueuedTarget } from "../src/queue/durable-queue.js";

const now = "2026-08-10T14:00:00.000Z";
const index = { schema_version: 5 as const, generated_at: now, reports: [] };

function target(repositoryId: number): TargetV3 {
  return {
    source_id: `github-${repositoryId}`,
    provider: "github",
    repository_id: repositoryId,
    repository: `owner/repo-${repositoryId}`,
    target_sha: repositoryId.toString(16).padStart(40, "0"),
    canonical_url: `https://github.com/owner/repo-${repositoryId}`,
    project_kinds: ["extension"],
    catalog_priority: {
      top_30: repositoryId <= 30,
      first_cataloged_at: "2026-07-01T00:00:00.000Z",
      popularity_rank: repositoryId,
    },
  };
}

function manifest(...targets: TargetV3[]): TargetManifestV3 {
  return {
    schema_version: 3,
    generated_at: now,
    repositories: targets,
  };
}

function observedEmptyState() {
  return {
    ...initialOperationsState(now),
    catalog_observation: { initialized_at: now, repositories: [] },
  };
}

describe("scan claim orchestration", () => {
  test("synchronizes and claims exactly two new submissions", () => {
    const result = buildScanClaims({
      manifest: manifest(target(41), target(42), target(43)),
      index,
      state: observedEmptyState(),
      now,
      runId: "actions-100",
      scannerPolicyVersion: "4",
      contextualReviewPolicyVersion: "4",
    });

    expect(result.include.map(({ repository_id }) => repository_id)).toEqual([
      41, 42,
    ]);
    expect(result.include.map(({ reason }) => reason)).toEqual(["new", "new"]);
    expect(result.state.active_scans).toHaveLength(2);
    expect(result.state.scan_queue.entries).toHaveLength(3);
    expect(result.total_remaining).toBe(1);
  });

  test("an explicit staff stop synchronizes without claiming", () => {
    const stopped = pauseSystem(observedEmptyState(), {
      kind: "staff",
      reasonCode: "CUTOVER",
      at: now,
    });
    const result = buildScanClaims({
      manifest: manifest(target(41), target(42)),
      index,
      state: stopped,
      now: "2026-08-10T14:01:00.000Z",
      runId: "actions-101",
      scannerPolicyVersion: "4",
      contextualReviewPolicyVersion: "4",
    });

    expect(result.include).toEqual([]);
    expect(result.state.active_scans).toEqual([]);
    expect(result.emergency_stopped).toBe(true);
  });

  test("a canary claim keeps its staff reason but consumes future eligibility", () => {
    const value = target(41);
    const queued = appendQueuedTarget(observedEmptyState(), value, {
      staffRequested: true,
    });
    const canary = pauseSystem(queued, {
      kind: "staff",
      reasonCode: "POLICY_V4_CANARY_GATE",
      at: now,
    });

    const result = buildScanClaims({
      manifest: manifest(value),
      index,
      state: canary,
      now: "2026-08-10T14:01:00.000Z",
      runId: "actions-canary-100",
      scannerPolicyVersion: "4",
      contextualReviewPolicyVersion: "4",
    });

    expect(result.include).toEqual([
      expect.objectContaining({ repository_id: 41, reason: "staff" }),
    ]);
    expect(result.state.active_scans).toHaveLength(1);
    expect(result.state.scan_queue.entries[0]).not.toHaveProperty(
      "staff_requested",
    );

    const failedAt = "2026-08-10T14:02:00.000Z";
    const failed = recordFailure(result.state, {
      target: value,
      failure: {
        code: "PREPARATION_FAILED",
        domain: "target",
        component: "orchestrator",
        diagnostic: "preparation_scanner_contract",
      },
      at: failedAt,
    }).state;
    expect(failed.active_scans).toEqual([]);
    expect(failed.scan_queue.entries[0]).toMatchObject({
      consecutive_failures: 1,
      total_failures: 1,
      last_failed_at: failedAt,
    });
    expect(failed.scan_queue.entries[0]).not.toHaveProperty("staff_requested");

    const replanned = buildScanClaims({
      manifest: manifest(value),
      index,
      state: failed,
      now: "2026-08-10T15:00:00.000Z",
      runId: "actions-canary-101",
      scannerPolicyVersion: "4",
      contextualReviewPolicyVersion: "4",
    });
    expect(replanned.include).toEqual([]);
    expect(replanned.state.active_scans).toEqual([]);
    expect(replanned.emergency_stopped).toBe(true);
    expect(replanned.delayed_entries).toBe(0);
    expect(replanned.next_wake_at).toBeNull();
  });
});
