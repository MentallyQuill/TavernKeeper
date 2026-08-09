import { readFile } from "node:fs/promises";

import { describe, expect, test } from "vitest";

import type { ReportIndexV5 } from "../src/contracts/reports-v5.js";
import type { TargetManifestV3, TargetV3 } from "../src/contracts/targets.js";
import {
  initialOperationsState,
  serializeOperationsState,
} from "../src/operations/state.js";
import { planBatch } from "../src/queue/backlog.js";
import {
  appendQueuedTarget,
  removeSuccessfulTarget,
  rotateFailedTarget,
} from "../src/queue/durable-queue.js";
import { syncScanQueue } from "../src/queue/sync.js";

const now = "2026-08-04T12:00:00.000Z";
const emptyIndex: ReportIndexV5 = {
  schema_version: 5,
  generated_at: now,
  reports: [],
};

const reportCompletedAt = "2026-08-02T12:00:00.000Z";
const indexWithPreviousRepositoryReport: ReportIndexV5 = {
  schema_version: 5,
  generated_at: now,
  reports: [
    {
      report_id: "c".repeat(64),
      report_digest: "c".repeat(64),
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
      source_id: "github-41",
      provider: "github",
      repository_id: 41,
      repository: "owner/repo-41",
      target_sha: "a".repeat(40),
      completed_at: reportCompletedAt,
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
        confidence: { low: 0, medium: 0, high: 0 },
        recommended_risk: { low: 0, material: 0, high: 0 },
      },
      coverage: {
        history_commits: 1,
        inventory_files: 1,
        inventory_bytes: 12,
        tools_completed: 4,
        tools_not_applicable: 3,
        evidence_validated: 0,
        review_required: 0,
        review_completed: 0,
        javascript_analysis_status: "legacy",
      },
      report_url:
        "https://mentallyquill.github.io/TavernKeeper/reports/github/41/" +
        `${"a".repeat(40)}/3/${"c".repeat(64)}/`,
      history_url:
        "https://mentallyquill.github.io/TavernKeeper/reports/github/41/history/",
    },
  ],
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

  test("defers an automatic changed-SHA rescan for 48 hours after its report", () => {
    const synchronized = syncScanQueue({
      manifest: manifest(target(41, 1, "b")),
      index: indexWithPreviousRepositoryReport,
      state: initialOperationsState(now),
      now,
      scannerPolicyVersion: "3",
    }).state;

    expect(synchronized.scan_queue.entries).toMatchObject([
      {
        target_sha: "b".repeat(40),
        rescan_not_before: "2026-08-04T12:00:00.000Z",
      },
    ]);
  });

  test("plans a synchronized changed-SHA rescan at its exact deadline", () => {
    const changed = target(41, 1, "b");
    const synchronized = syncScanQueue({
      manifest: manifest(changed),
      index: indexWithPreviousRepositoryReport,
      state: initialOperationsState(now),
      now,
      scannerPolicyVersion: "3",
    }).state;

    expect(
      planBatch(
        manifest(changed),
        indexWithPreviousRepositoryReport,
        synchronized,
        "2026-08-04T11:59:59.999Z",
        "3",
      ),
    ).toMatchObject({
      targets: [],
      delayedEntries: 1,
      nextWakeAt: "2026-08-04T12:00:00.000Z",
    });
    expect(
      planBatch(
        manifest(changed),
        indexWithPreviousRepositoryReport,
        synchronized,
        "2026-08-04T12:00:00.000Z",
        "3",
      ).targets,
    ).toEqual([
      expect.objectContaining({
        target: expect.objectContaining({ repository_id: 41 }),
        reason: "changed",
      }),
    ]);
  });

  test("retains the automatic rescan deadline when the manifest SHA changes again", () => {
    const first = syncScanQueue({
      manifest: manifest(target(41, 1, "b")),
      index: indexWithPreviousRepositoryReport,
      state: initialOperationsState(now),
      now,
      scannerPolicyVersion: "3",
    }).state;

    const synchronized = syncScanQueue({
      manifest: manifest(target(41, 1, "c")),
      index: indexWithPreviousRepositoryReport,
      state: first,
      now: "2026-08-04T12:01:00.000Z",
      scannerPolicyVersion: "3",
    }).state;

    expect(synchronized.scan_queue.entries).toMatchObject([
      {
        target_sha: "c".repeat(40),
        rescan_not_before: "2026-08-04T12:00:00.000Z",
      },
    ]);
  });

  test("omits an automatic-rescan deadline for first, staff, and active-policy work", () => {
    const firstScan = syncScanQueue({
      manifest: manifest(target(42, 1)),
      index: emptyIndex,
      state: initialOperationsState(now),
      now,
      scannerPolicyVersion: "3",
    }).state.scan_queue.entries[0]!;
    const staffState = appendQueuedTarget(
      initialOperationsState(now),
      target(41, 1, "a"),
      { staffRequested: true },
    );
    const staffScan = syncScanQueue({
      manifest: manifest(target(41, 1, "b")),
      index: indexWithPreviousRepositoryReport,
      state: staffState,
      now,
      scannerPolicyVersion: "3",
    }).state.scan_queue.entries[0]!;
    const policyScan = syncScanQueue({
      manifest: manifest(target(41, 1, "b")),
      index: indexWithPreviousRepositoryReport,
      state: {
        ...initialOperationsState(now),
        policy_campaigns: [
          {
            id: "refresh-41",
            scanner_policy_version: "3",
            repository_ids: [41],
            created_at: now,
            status: "active",
          },
        ],
      },
      now,
      scannerPolicyVersion: "3",
    }).state.scan_queue.entries[0]!;

    expect(firstScan).not.toHaveProperty("rescan_not_before");
    expect(staffScan).not.toHaveProperty("rescan_not_before");
    expect(policyScan).not.toHaveProperty("rescan_not_before");
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

  test("completes policy campaign progress instead of reseeding successful targets", () => {
    const covered = target(41, 1, "a");
    const campaignState = {
      ...appendQueuedTarget(initialOperationsState(now), covered),
      policy_campaigns: [
        {
          id: "policy-3-regression",
          scanner_policy_version: "3",
          repository_ids: [41],
          created_at: now,
          status: "active" as const,
        },
      ],
    };
    const waiting = syncScanQueue({
      manifest: manifest(covered),
      index: indexWithPreviousRepositoryReport,
      state: campaignState,
      now: "2026-08-04T12:01:00.000Z",
      scannerPolicyVersion: "3",
    });
    expect(waiting.state.scan_queue.entries).toEqual([
      expect.objectContaining({ repository_id: 41 }),
    ]);
    expect(waiting.state.policy_campaigns).toEqual([
      expect.objectContaining({
        id: "policy-3-regression",
        repository_ids: [41],
        status: "active",
      }),
    ]);

    const postCampaignIndex = {
      ...indexWithPreviousRepositoryReport,
      generated_at: "2026-08-04T12:01:30.000Z",
      reports: indexWithPreviousRepositoryReport.reports.map((report) => ({
        ...report,
        completed_at: "2026-08-04T12:01:30.000Z",
      })),
    };
    const publishedState = removeSuccessfulTarget(
      waiting.state,
      covered,
      "2026-08-04T12:01:30.000Z",
    );
    const completed = syncScanQueue({
      manifest: manifest(covered),
      index: postCampaignIndex,
      state: publishedState,
      now: "2026-08-04T12:02:00.000Z",
      scannerPolicyVersion: "3",
    });
    expect(completed.state.scan_queue.entries).toEqual([]);
    expect(completed.state.policy_campaigns).toEqual([
      expect.objectContaining({
        id: "policy-3-regression",
        repository_ids: [],
        status: "completed",
      }),
    ]);

    const stable = syncScanQueue({
      manifest: manifest(covered),
      index: postCampaignIndex,
      state: completed.state,
      now: "2026-08-04T12:03:00.000Z",
      scannerPolicyVersion: "3",
    });
    expect(stable.changed).toBe(false);
    expect(stable.state.scan_queue.entries).toEqual([]);
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
