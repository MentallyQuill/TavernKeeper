import { describe, expect, test } from "vitest";

import type { TargetManifestV3, TargetV3 } from "../src/contracts/targets.js";
import { buildScanClaims } from "../src/cli/claim-scans.js";
import {
  initialOperationsState,
  pauseSystem,
} from "../src/operations/state.js";

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
});
