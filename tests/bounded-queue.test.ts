import { describe, expect, test } from "vitest";

import type { ReportIndexV5 } from "../src/contracts/reports-v5.js";
import type { TargetManifestV3, TargetV3 } from "../src/contracts/targets.js";
import {
  COVERAGE_CAMPAIGN_ID,
  initialOperationsState,
  type OperationsState,
} from "../src/operations/state.js";
import { projectReportToIndexV5 } from "../src/publish/publisher.js";
import { planBatch } from "../src/queue/backlog.js";
import { appendQueuedTarget } from "../src/queue/durable-queue.js";
import { syncScanQueue } from "../src/queue/sync.js";
import { fixtureReportV5 } from "./helpers/v5-report.js";

const now = "2026-08-10T14:00:00.000Z";
const emptyIndex: ReportIndexV5 = {
  schema_version: 5,
  generated_at: now,
  reports: [],
};

function target(repositoryId: number, rank: number, sha = repositoryId) {
  return {
    source_id: `github-${repositoryId}`,
    provider: "github" as const,
    repository_id: repositoryId,
    repository: `owner/repo-${repositoryId}`,
    target_sha: sha.toString(16).padStart(40, "0"),
    canonical_url: `https://github.com/owner/repo-${repositoryId}`,
    project_kinds: ["extension" as const],
    catalog_priority: {
      top_30: rank <= 30,
      first_cataloged_at: "2026-07-01T00:00:00.000Z",
      popularity_rank: rank,
    },
  } satisfies TargetV3;
}

function manifest(...targets: TargetV3[]): TargetManifestV3 {
  return {
    schema_version: 3,
    generated_at: now,
    repositories: [...targets].sort(
      (left, right) => left.repository_id - right.repository_id,
    ),
  };
}

function campaign(repositoryIds: number[]) {
  return {
    id: COVERAGE_CAMPAIGN_ID,
    scanner_policy_version: "4",
    created_at: now,
    status: "active" as const,
    popular_repository_ids: [...repositoryIds].sort((a, b) => a - b),
    latest_release_repository_ids: [] as number[],
    repository_ids: [...repositoryIds].sort((a, b) => a - b),
    remaining_repository_ids: [...repositoryIds].sort((a, b) => a - b),
  };
}

function observing(targets: TargetV3[]): OperationsState {
  return {
    ...initialOperationsState(now),
    catalog_observation: {
      initialized_at: now,
      repositories: targets
        .map(({ repository_id, target_sha }) => ({
          repository_id,
          target_sha,
        }))
        .sort((left, right) => left.repository_id - right.repository_id),
    },
  };
}

describe("bounded catalog queue", () => {
  test("marks a retained SHA mismatch as updated", async () => {
    const previous = target(41, 1, 410);
    const updated = target(41, 1, 411);
    const report = await fixtureReportV5({
      source_id: previous.source_id,
      repository_id: previous.repository_id,
      repository: previous.repository,
      target_sha: previous.target_sha,
      canonical_url: previous.canonical_url,
      completed_at: "2026-08-09T13:00:00.000Z",
    });
    const state = appendQueuedTarget(observing([updated]), updated);

    const synchronized = syncScanQueue({
      manifest: manifest(updated),
      index: {
        schema_version: 5,
        generated_at: now,
        reports: [projectReportToIndexV5(report)],
      },
      state,
      now,
      scannerPolicyVersion: "4",
      contextualReviewPolicyVersion: "4",
    });

    expect(synchronized.state.scan_queue.entries[0]?.catalog_change).toBe(
      "updated",
    );
  });

  test("keeps new, updated, coverage, and ordinary missing-report work", () => {
    const ordinary = target(41, 1);
    const selected = target(42, 2);
    const updatedBefore = target(43, 3, 430);
    const updated = target(43, 3, 431);
    const submitted = target(44, 4);
    const observed = [ordinary, selected, updatedBefore];
    let state = observing(observed);
    for (const value of [ordinary, selected, updated, submitted])
      state = appendQueuedTarget(state, value, {
        ...(value.repository_id === submitted.repository_id
          ? { catalogChange: "new" as const }
          : {}),
        ...(value.repository_id === updated.repository_id
          ? { catalogChange: "updated" as const }
          : {}),
      });
    state = { ...state, coverage_campaigns: [campaign([42])] };

    const synchronized = syncScanQueue({
      manifest: manifest(ordinary, selected, updated, submitted),
      index: emptyIndex,
      state,
      now: "2026-08-10T14:01:00.000Z",
      scannerPolicyVersion: "4",
      contextualReviewPolicyVersion: "4",
    });

    expect(
      synchronized.state.scan_queue.entries.map(
        ({ repository_id }) => repository_id,
      ),
    ).toEqual([41, 42, 43, 44]);
    expect(synchronized.summary.removed).toBe(0);
  });

  test("prioritizes new, updated, coverage, then ordinary freshness work", () => {
    const selected = target(41, 1);
    const updated = target(42, 2);
    const submitted = target(43, 3);
    const ordinary = target(44, 4);
    let state = observing([selected, updated, submitted, ordinary]);
    for (const value of [selected, updated, submitted, ordinary])
      state = appendQueuedTarget(state, value, {
        ...(value.repository_id === updated.repository_id
          ? { catalogChange: "updated" as const }
          : {}),
        ...(value.repository_id === submitted.repository_id
          ? { catalogChange: "new" as const }
          : {}),
      });
    state = { ...state, coverage_campaigns: [campaign([41])] };

    expect(
      planBatch(
        manifest(selected, updated, submitted, ordinary),
        emptyIndex,
        state,
        now,
        "4",
        "4",
      ).targets.map(({ target: value, reason }) => [
        value.repository_id,
        reason,
      ]),
    ).toEqual([
      [43, "new"],
      [42, "changed"],
      [41, "coverage"],
      [44, "changed"],
    ]);
  });

  test("keeps a selected current SHA behind the 48-hour deadline", async () => {
    const selected = target(41, 1);
    const report = await fixtureReportV5({
      source_id: selected.source_id,
      repository_id: selected.repository_id,
      repository: selected.repository,
      target_sha: selected.target_sha,
      canonical_url: selected.canonical_url,
      completed_at: "2026-08-10T13:00:00.000Z",
    });
    const indexedReport = projectReportToIndexV5(report);
    const state = {
      ...observing([selected]),
      coverage_campaigns: [campaign([41])],
    };

    const synchronized = syncScanQueue({
      manifest: manifest(selected),
      index: {
        schema_version: 5,
        generated_at: now,
        reports: [indexedReport],
      },
      state,
      now,
      scannerPolicyVersion: "4",
      contextualReviewPolicyVersion: "4",
    });

    expect(synchronized.state.scan_queue.entries).toHaveLength(1);
    expect(synchronized.state.scan_queue.entries[0]?.rescan_not_before).toBe(
      "2026-08-12T13:00:00.000Z",
    );
    expect(
      planBatch(
        manifest(selected),
        { schema_version: 5, generated_at: now, reports: [indexedReport] },
        synchronized.state,
        now,
        "4",
        "4",
      ).targets,
    ).toEqual([]);
  });
});
