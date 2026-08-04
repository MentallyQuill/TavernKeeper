import { readFile } from "node:fs/promises";

import { describe, expect, test } from "vitest";

import type { ReportIndexV5 } from "../src/contracts/reports-v5.js";
import type { TargetManifestV3, TargetV3 } from "../src/contracts/targets.js";
import { initialOperationsState } from "../src/operations/state.js";
import { serializeOperationsState } from "../src/operations/state.js";
import {
  appendQueuedTarget,
  rotateFailedTarget,
} from "../src/queue/durable-queue.js";
import { syncScanQueue } from "../src/queue/sync.js";

const now = "2026-08-04T12:00:00.000Z";
const emptyIndex: ReportIndexV5 = {
  schema_version: 5,
  generated_at: now,
  reports: [],
};

function target(
  repositoryId: number,
  rank: number,
  shaDigit?: string,
): TargetV3 {
  return {
    source_id: `github-${repositoryId}`,
    provider: "github",
    repository_id: repositoryId,
    repository: `owner/repo-${repositoryId}`,
    target_sha: (shaDigit ?? String(repositoryId % 10)).repeat(40),
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
    generated_at: now,
    repositories: [...targets].sort(
      (left, right) => left.repository_id - right.repository_id,
    ),
  };
}

describe("scan queue synchronization", () => {
  test("seeds the initial queue by popularity rank", () => {
    const result = syncScanQueue({
      manifest: manifest(target(41, 3), target(42, 1), target(43, 2)),
      index: emptyIndex,
      state: initialOperationsState(now),
      now,
      scannerPolicyVersion: "3",
    });

    expect(
      result.state.scan_queue.entries.map(({ repository_id, ticket }) => [
        repository_id,
        ticket,
      ]),
    ).toEqual([
      [42, 1],
      [43, 2],
      [41, 3],
    ]);
  });

  test("appends later arrivals after a previously requeued failure", () => {
    const firstManifest = manifest(target(41, 1), target(42, 2));
    let state = syncScanQueue({
      manifest: firstManifest,
      index: emptyIndex,
      state: initialOperationsState(now),
      now,
      scannerPolicyVersion: "3",
    }).state;
    state = rotateFailedTarget(state, {
      target: target(41, 1),
      failure: {
        code: "SCANNER_FAILED",
        domain: "target",
        component: "opengrep",
      },
      at: now,
    }).state;

    const synchronized = syncScanQueue({
      manifest: manifest(...firstManifest.repositories, target(43, 3)),
      index: emptyIndex,
      state,
      now: "2026-08-04T12:01:00.000Z",
      scannerPolicyVersion: "3",
    }).state;

    expect(
      synchronized.scan_queue.entries.map(({ repository_id, ticket }) => [
        repository_id,
        ticket,
      ]),
    ).toEqual([
      [42, 2],
      [41, 3],
      [43, 4],
    ]);
  });

  test("preserves a ticket while replacing a changed SHA", () => {
    const original = target(41, 1, "a");
    let state = appendQueuedTarget(initialOperationsState(now), original);
    state = rotateFailedTarget(state, {
      target: original,
      failure: {
        code: "SCANNER_FAILED",
        domain: "target",
        component: "opengrep",
      },
      at: now,
    }).state;

    const synchronized = syncScanQueue({
      manifest: manifest(target(41, 1, "b")),
      index: emptyIndex,
      state,
      now: "2026-08-04T12:01:00.000Z",
      scannerPolicyVersion: "3",
    }).state;

    expect(synchronized.scan_queue.entries[0]).toMatchObject({
      target_sha: "b".repeat(40),
      ticket: 2,
      consecutive_failures: 0,
      total_failures: 1,
      not_before: null,
    });
  });

  test("removes exact targets already covered by the current policy", async () => {
    const index = JSON.parse(
      await readFile(
        new URL("./fixtures/contracts/index.v5.valid.json", import.meta.url),
        "utf8",
      ),
    ) as ReportIndexV5;
    const covered = target(42, 1, "a");
    const state = appendQueuedTarget(initialOperationsState(now), covered);

    const synchronized = syncScanQueue({
      manifest: manifest(covered),
      index,
      state,
      now,
      scannerPolicyVersion: "2",
    });

    expect(synchronized.state.scan_queue.entries).toEqual([]);
    expect(synchronized.summary.removed).toBe(1);
  });

  test("is byte-stable when inputs do not change", () => {
    const input = {
      manifest: manifest(target(41, 1), target(42, 2)),
      index: emptyIndex,
      state: initialOperationsState(now),
      now,
      scannerPolicyVersion: "3",
    };
    const first = syncScanQueue(input);
    const second = syncScanQueue({ ...input, state: first.state });

    expect(second.changed).toBe(false);
    expect(serializeOperationsState(second.state)).toBe(
      serializeOperationsState(first.state),
    );
  });
});
