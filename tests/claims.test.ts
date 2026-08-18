import { describe, expect, test } from "vitest";

import type { TargetV3 } from "../src/contracts/targets.js";
import { initialOperationsState } from "../src/operations/state.js";
import { claimScanSlots } from "../src/queue/claims.js";
import type { PlannedTarget } from "../src/queue/backlog.js";
import { appendQueuedTarget } from "../src/queue/durable-queue.js";

const now = "2026-08-10T14:00:00.000Z";

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
      top_30: true,
      first_cataloged_at: "2026-07-01T00:00:00.000Z",
      popularity_rank: repositoryId,
    },
  };
}

function queued(...targets: TargetV3[]) {
  let state = initialOperationsState(now);
  for (const value of targets) state = appendQueuedTarget(state, value);
  return state;
}

function planned(
  state: ReturnType<typeof queued>,
  targets: TargetV3[],
): PlannedTarget[] {
  return targets.map((value) => ({
    target: value,
    reason: "new",
    queueEntry: state.scan_queue.entries.find(
      ({ repository_id }) => repository_id === value.repository_id,
    )!,
  }));
}

describe("durable scan claims", () => {
  test("consumes a staff request only when its target receives a lease", () => {
    const staffTarget = target(41);
    const ordinaryTarget = target(42);
    let state = appendQueuedTarget(initialOperationsState(now), staffTarget, {
      staffRequested: true,
    });
    state = appendQueuedTarget(state, ordinaryTarget, {
      staffRequested: true,
    });

    const result = claimScanSlots({
      state,
      plannedTargets: planned(state, [staffTarget]),
      now,
      runId: "run-staff-100",
    });

    expect(result.claimed[0]?.queueEntry.staff_requested).toBe(true);
    expect(
      result.state.scan_queue.entries.find(
        ({ repository_id }) => repository_id === staffTarget.repository_id,
      ),
    ).not.toHaveProperty("staff_requested");
    expect(
      result.state.scan_queue.entries.find(
        ({ repository_id }) => repository_id === ordinaryTarget.repository_id,
      ),
    ).toHaveProperty("staff_requested", true);
  });

  test("claims at most two exact targets", () => {
    const targets = [target(41), target(42), target(43)];
    const state = queued(...targets);

    const result = claimScanSlots({
      state,
      plannedTargets: planned(state, targets),
      now,
      runId: "run-100",
    });

    expect(
      result.claimed.map(({ target: value }) => value.repository_id),
    ).toEqual([41, 42]);
    expect(result.state.active_scans).toEqual([
      {
        source_id: "github-41",
        repository_id: 41,
        target_sha: targets[0]!.target_sha,
        started_at: now,
        run_id: "run-100-41",
      },
      {
        source_id: "github-42",
        repository_id: 42,
        target_sha: targets[1]!.target_sha,
        started_at: now,
        run_id: "run-100-42",
      },
    ]);
  });

  test("fills only the free global slot", () => {
    const targets = [target(41), target(42), target(43)];
    const base = queued(...targets);
    const state = {
      ...base,
      active_scans: [
        {
          source_id: targets[0]!.source_id,
          repository_id: targets[0]!.repository_id,
          target_sha: targets[0]!.target_sha,
          started_at: "2026-08-10T13:30:00.000Z",
          run_id: "run-existing-41",
        },
      ],
    };

    const result = claimScanSlots({
      state,
      plannedTargets: planned(base, targets.slice(1)),
      now,
      runId: "run-101",
    });

    expect(
      result.claimed.map(({ target: value }) => value.repository_id),
    ).toEqual([42]);
    expect(result.state.active_scans).toHaveLength(2);
  });

  test("expires claims at two hours and safely reclaims their target", () => {
    const value = target(41);
    const base = queued(value);
    const state = {
      ...base,
      active_scans: [
        {
          source_id: value.source_id,
          repository_id: value.repository_id,
          target_sha: value.target_sha,
          started_at: "2026-08-10T12:00:00.000Z",
          run_id: "run-stale-41",
        },
      ],
    };

    const result = claimScanSlots({
      state,
      plannedTargets: planned(base, [value]),
      now,
      runId: "run-102",
    });

    expect(result.expired).toBe(1);
    expect(result.claimed).toHaveLength(1);
    expect(result.state.active_scans[0]?.run_id).toBe("run-102-41");
  });

  test("does not duplicate an already active exact target", () => {
    const value = target(41);
    const base = queued(value);
    const state = {
      ...base,
      active_scans: [
        {
          source_id: value.source_id,
          repository_id: value.repository_id,
          target_sha: value.target_sha,
          started_at: "2026-08-10T13:59:00.000Z",
          run_id: "run-existing-41",
        },
      ],
    };

    const result = claimScanSlots({
      state,
      plannedTargets: planned(base, [value]),
      now,
      runId: "run-103",
    });

    expect(result.claimed).toEqual([]);
    expect(result.state.active_scans).toEqual(state.active_scans);
  });
});
