import { readFile } from "node:fs/promises";

import { describe, expect, test } from "vitest";

import type { ReportIndexV5 } from "../src/contracts/reports-v5.js";
import type { TargetManifestV3, TargetV3 } from "../src/contracts/targets.js";
import { failureFingerprint } from "../src/operations/failure.js";
import {
  COVERAGE_CAMPAIGN_ID,
  initialOperationsState,
  serializeOperationsState,
} from "../src/operations/state.js";
import { planBatch } from "../src/queue/backlog.js";
import {
  addBackUnscannableTarget,
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
        metadata_only_candidates: 0,
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

function stateObserving(...targets: TargetV3[]) {
  return {
    ...initialOperationsState(now),
    catalog_observation: {
      initialized_at: now,
      repositories: [...targets]
        .sort((left, right) => left.repository_id - right.repository_id)
        .map(({ repository_id, target_sha }) => ({
          repository_id,
          target_sha,
        })),
    },
  };
}

function coverageCampaign(
  repositoryIds: number[],
  createdAt = now,
  remainingRepositoryIds = repositoryIds,
) {
  return {
    id: COVERAGE_CAMPAIGN_ID,
    scanner_policy_version: "3",
    created_at: createdAt,
    status: "active" as const,
    popular_repository_ids: [...repositoryIds],
    latest_release_repository_ids: [] as number[],
    repository_ids: [...repositoryIds],
    remaining_repository_ids: [...remainingRepositoryIds],
  };
}

function indexWithRepositoryReport(
  repositoryId: number,
  shaDigit: string,
  completedAt = reportCompletedAt,
): ReportIndexV5 {
  const reportedTarget = target(repositoryId, 1, shaDigit);
  return {
    ...indexWithPreviousRepositoryReport,
    generated_at: completedAt,
    reports: indexWithPreviousRepositoryReport.reports.map((report) => ({
      ...report,
      source_id: reportedTarget.source_id,
      repository_id: reportedTarget.repository_id,
      repository: reportedTarget.repository,
      target_sha: reportedTarget.target_sha,
      completed_at: completedAt,
      report_url:
        `https://mentallyquill.github.io/TavernKeeper/reports/github/${repositoryId}/` +
        `${reportedTarget.target_sha}/3/${report.report_digest}/`,
      history_url: `https://mentallyquill.github.io/TavernKeeper/reports/github/${repositoryId}/history/`,
    })),
  };
}

describe("scan queue synchronization", () => {
  test("queues coverage targets and ordinary targets missing a current report", () => {
    const first = target(41, 1, "a");
    const ordinary = target(42, 2, "b");
    const second = target(43, 3, "c");
    const state = {
      ...stateObserving(first, ordinary, second),
      coverage_campaigns: [coverageCampaign([41, 43])],
    };

    const synchronized = syncScanQueue({
      manifest: manifest(first, ordinary, second),
      index: emptyIndex,
      state,
      now: "2026-08-04T12:01:00.000Z",
      scannerPolicyVersion: "3",
    });

    expect(
      synchronized.state.scan_queue.entries.map((entry) => ({
        repository_id: entry.repository_id,
        target_sha: entry.target_sha,
        staff_requested: entry.staff_requested,
        catalog_change: entry.catalog_change,
        rescan_not_before: entry.rescan_not_before,
      })),
    ).toEqual([
      {
        repository_id: 41,
        target_sha: first.target_sha,
        staff_requested: undefined,
        catalog_change: undefined,
        rescan_not_before: undefined,
      },
      {
        repository_id: 42,
        target_sha: ordinary.target_sha,
        staff_requested: undefined,
        catalog_change: undefined,
        rescan_not_before: undefined,
      },
      {
        repository_id: 43,
        target_sha: second.target_sha,
        staff_requested: undefined,
        catalog_change: undefined,
        rescan_not_before: undefined,
      },
    ]);
  });

  test("delays a selected same-SHA target for seven days after its pre-campaign report", () => {
    const selected = target(41, 1, "a");
    const reportAt = "2026-08-04T08:00:00.000Z";
    const state = {
      ...stateObserving(selected),
      coverage_campaigns: [coverageCampaign([41])],
    };

    const synchronized = syncScanQueue({
      manifest: manifest(selected),
      index: indexWithRepositoryReport(41, "a", reportAt),
      state,
      now: "2026-08-04T12:01:00.000Z",
      scannerPolicyVersion: "3",
    });

    expect(synchronized.state.coverage_campaigns[0]).toMatchObject({
      status: "active",
      remaining_repository_ids: [41],
    });
    expect(synchronized.state.scan_queue.entries).toEqual([
      expect.objectContaining({
        repository_id: 41,
        rescan_not_before: "2026-08-11T08:00:00.000Z",
      }),
    ]);
  });

  test("treats a selected prior-SHA report as cooldown evidence without catalog authority", () => {
    const selected = target(41, 1, "b");
    const state = {
      ...stateObserving(selected),
      coverage_campaigns: [coverageCampaign([41])],
    };

    const synchronized = syncScanQueue({
      manifest: manifest(selected),
      index: indexWithRepositoryReport(41, "a", "2026-08-04T08:00:00.000Z"),
      state,
      now: "2026-08-04T12:01:00.000Z",
      scannerPolicyVersion: "3",
    });

    expect(synchronized.state.scan_queue.entries).toEqual([
      expect.objectContaining({
        repository_id: 41,
        target_sha: selected.target_sha,
        rescan_not_before: "2026-08-11T08:00:00.000Z",
      }),
    ]);
    expect(synchronized.state.scan_queue.entries[0]).not.toHaveProperty(
      "catalog_change",
    );
  });

  test("retains a selected target's existing failure deadline and state", () => {
    const selected = target(41, 1, "a");
    const failed = rotateFailedTarget(
      appendQueuedTarget(stateObserving(selected), selected),
      {
        target: selected,
        failure: {
          code: "SCANNER_FAILED",
          domain: "target",
          component: "opengrep",
        },
        at: now,
      },
    ).state;
    const original = failed.scan_queue.entries[0]!;

    const synchronized = syncScanQueue({
      manifest: manifest(selected),
      index: emptyIndex,
      state: {
        ...failed,
        coverage_campaigns: [coverageCampaign([41])],
      },
      now: "2026-08-04T12:01:00.000Z",
      scannerPolicyVersion: "3",
    });

    expect(synchronized.state.scan_queue.entries).toEqual([
      expect.objectContaining({
        repository_id: 41,
        ticket: original.ticket,
        consecutive_failures: 1,
        total_failures: 1,
        not_before: original.not_before,
        last_failure: original.last_failure,
      }),
    ]);
    expect(synchronized.state.scan_queue.entries[0]).not.toHaveProperty(
      "staff_requested",
    );
    expect(synchronized.state.scan_queue.entries[0]).not.toHaveProperty(
      "catalog_change",
    );
  });

  test("advances only completed or removed coverage members and preserves the selection", () => {
    const completed = target(41, 1, "a");
    const pending = target(42, 2, "b");
    const removed = target(43, 3, "c");
    const state = {
      ...stateObserving(completed, pending, removed),
      coverage_campaigns: [coverageCampaign([41, 42, 43])],
    };
    const postCampaignReport = indexWithRepositoryReport(
      41,
      "a",
      "2026-08-04T12:01:00.000Z",
    );

    const synchronized = syncScanQueue({
      manifest: manifest(completed, pending),
      index: postCampaignReport,
      state,
      now: "2026-08-04T12:02:00.000Z",
      scannerPolicyVersion: "3",
    });

    expect(synchronized.state.coverage_campaigns).toEqual([
      {
        ...coverageCampaign([41, 42, 43]),
        remaining_repository_ids: [42],
      },
    ]);
    expect(
      synchronized.state.scan_queue.entries.map(
        ({ repository_id }) => repository_id,
      ),
    ).toEqual([42]);
  });

  test("permanently completes a coverage campaign when no member remains", () => {
    const selected = target(41, 1, "a");
    const state = {
      ...stateObserving(selected),
      coverage_campaigns: [coverageCampaign([41])],
    };
    const postCampaignReport = indexWithRepositoryReport(
      41,
      "a",
      "2026-08-04T12:01:00.000Z",
    );
    const completed = syncScanQueue({
      manifest: manifest(selected),
      index: postCampaignReport,
      state,
      now: "2026-08-04T12:02:00.000Z",
      scannerPolicyVersion: "3",
    }).state;

    expect(completed.coverage_campaigns).toEqual([
      {
        ...coverageCampaign([41]),
        remaining_repository_ids: [],
        status: "completed",
      },
    ]);

    const stable = syncScanQueue({
      manifest: manifest(selected),
      index: postCampaignReport,
      state: completed,
      now: "2026-08-04T12:03:00.000Z",
      scannerPolicyVersion: "3",
    });
    expect(stable.changed).toBe(false);
    expect(stable.state.coverage_campaigns[0]?.status).toBe("completed");
    expect(stable.state.scan_queue.entries).toEqual([]);
  });

  test("initializes catalog observation while retaining missing exact reports", () => {
    const legacy = manifest(target(41, 1), target(42, 2));
    const preBaseline = {
      ...appendQueuedTarget(
        appendQueuedTarget(
          initialOperationsState(now),
          legacy.repositories[0]!,
        ),
        legacy.repositories[1]!,
        { staffRequested: true },
      ),
      emergency_stop: {
        kind: "staff" as const,
        reason_code: "CATALOG_WIDE_RESCAN_BLOCKED",
        paused_at: now,
      },
    };

    const result = syncScanQueue({
      manifest: legacy,
      index: emptyIndex,
      state: preBaseline,
      now,
      scannerPolicyVersion: "4",
    });

    expect(result.state.scan_queue.entries).toEqual([
      expect.objectContaining({ repository_id: 41 }),
      expect.objectContaining({ repository_id: 42 }),
    ]);
    expect(result.state.scan_queue.entries[1]).not.toHaveProperty(
      "staff_requested",
    );
    expect(result.summary).toMatchObject({ retained: 2, removed: 0 });
    expect(result.state.catalog_observation?.repositories).toEqual([
      { repository_id: 41, target_sha: target(41, 1).target_sha },
      { repository_id: 42, target_sha: target(42, 2).target_sha },
    ]);
  });

  test("strips pre-baseline staff authority from report-backed changed-SHA work", () => {
    const changed = target(41, 1, "b");
    const preBaseline = appendQueuedTarget(
      initialOperationsState(now),
      changed,
      { staffRequested: true },
    );

    const synchronized = syncScanQueue({
      manifest: manifest(changed),
      index: indexWithPreviousRepositoryReport,
      state: preBaseline,
      now,
      scannerPolicyVersion: "3",
    }).state.scan_queue.entries[0]!;

    expect(synchronized).not.toHaveProperty("staff_requested");
    expect(synchronized).toMatchObject({
      repository_id: 41,
      target_sha: "b".repeat(40),
      rescan_not_before: "2026-08-09T12:00:00.000Z",
    });
  });

  test("cools a newly observed repository that already has report history", () => {
    const baseline = syncScanQueue({
      manifest: manifest(target(41, 1)),
      index: emptyIndex,
      state: initialOperationsState(now),
      now,
      scannerPolicyVersion: "4",
    }).state;

    const synchronized = syncScanQueue({
      manifest: manifest(target(41, 1), target(43, 3, "b")),
      index: indexWithRepositoryReport(43, "a"),
      state: baseline,
      now: "2026-08-04T12:01:00.000Z",
      scannerPolicyVersion: "4",
    }).state;

    expect(
      synchronized.scan_queue.entries.find(
        ({ repository_id }) => repository_id === 43,
      ),
    ).toMatchObject({
      repository_id: 43,
      catalog_change: "new",
      rescan_not_before: "2026-08-09T12:00:00.000Z",
    });
  });

  test("keeps a removed and re-added repository behind its weekly cooldown", () => {
    const original = target(43, 3, "a");
    const baseline = syncScanQueue({
      manifest: manifest(target(41, 1), original),
      index: emptyIndex,
      state: initialOperationsState(now),
      now,
      scannerPolicyVersion: "4",
    }).state;
    const removed = syncScanQueue({
      manifest: manifest(target(41, 1)),
      index: indexWithRepositoryReport(43, "a"),
      state: baseline,
      now: "2026-08-04T12:01:00.000Z",
      scannerPolicyVersion: "4",
    }).state;

    const readded = syncScanQueue({
      manifest: manifest(target(41, 1), target(43, 3, "b")),
      index: indexWithRepositoryReport(43, "a"),
      state: removed,
      now: "2026-08-04T12:02:00.000Z",
      scannerPolicyVersion: "4",
    }).state.scan_queue.entries.find(
      ({ repository_id }) => repository_id === 43,
    )!;

    expect(readded).toMatchObject({
      repository_id: 43,
      catalog_change: "new",
      rescan_not_before: "2026-08-09T12:00:00.000Z",
    });
  });

  test("marks an unreported SHA update while preserving ordinary freshness work", () => {
    const baseline = syncScanQueue({
      manifest: manifest(target(41, 1, "a"), target(42, 2)),
      index: emptyIndex,
      state: initialOperationsState(now),
      now,
      scannerPolicyVersion: "4",
    }).state;

    const synchronized = syncScanQueue({
      manifest: manifest(target(41, 1, "b"), target(42, 2)),
      index: emptyIndex,
      state: baseline,
      now: "2026-08-04T12:01:00.000Z",
      scannerPolicyVersion: "4",
    }).state;

    expect(synchronized.scan_queue.entries).toHaveLength(2);
    expect(synchronized.scan_queue.entries[0]).toMatchObject({
      repository_id: 41,
      target_sha: "b".repeat(40),
      catalog_change: "updated",
    });
    expect(synchronized.scan_queue.entries[1]).toMatchObject({
      repository_id: 42,
    });
    expect(synchronized.scan_queue.entries[1]).not.toHaveProperty(
      "catalog_change",
    );
  });

  test("queues an unchanged target when its report uses an older scanner policy", () => {
    const baseline = syncScanQueue({
      manifest: manifest(target(41, 1, "a")),
      index: emptyIndex,
      state: initialOperationsState(now),
      now,
      scannerPolicyVersion: "4",
    }).state;

    const synchronized = syncScanQueue({
      manifest: manifest(target(41, 1, "a")),
      index: indexWithPreviousRepositoryReport,
      state: baseline,
      now: "2026-08-04T12:01:00.000Z",
      scannerPolicyVersion: "4",
    }).state;

    expect(synchronized.scan_queue.entries).toEqual([
      expect.objectContaining({
        repository_id: 41,
        target_sha: "a".repeat(40),
      }),
    ]);
  });

  test("queues an unchanged target when its contextual-review policy is stale", () => {
    const value = target(41, 1, "a");
    const synchronized = syncScanQueue({
      manifest: manifest(value),
      index: indexWithPreviousRepositoryReport,
      state: stateObserving(value),
      now: "2026-08-04T12:01:00.000Z",
      scannerPolicyVersion: "3",
      contextualReviewPolicyVersion: "2",
    }).state;

    expect(synchronized.scan_queue.entries).toEqual([
      expect.objectContaining({ repository_id: 41 }),
    ]);
  });

  test("appends later arrivals after a previously requeued failure", () => {
    const firstManifest = manifest(target(41, 1), target(42, 2));
    const baseline = syncScanQueue({
      manifest: manifest(),
      index: emptyIndex,
      state: initialOperationsState(now),
      now,
      scannerPolicyVersion: "3",
    }).state;
    let state = syncScanQueue({
      manifest: firstManifest,
      index: emptyIndex,
      state: baseline,
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

  test("preserves a failure episode while replacing a changed SHA", () => {
    const original = target(41, 1, "a");
    let state = appendQueuedTarget(
      {
        ...initialOperationsState(now),
        catalog_observation: {
          initialized_at: now,
          repositories: [
            { repository_id: 41, target_sha: original.target_sha },
          ],
        },
      },
      original,
    );
    state = rotateFailedTarget(state, {
      target: original,
      failure: {
        code: "SCANNER_FAILED",
        domain: "target",
        component: "opengrep",
      },
      at: now,
    }).state;
    state = rotateFailedTarget(state, {
      target: original,
      failure: {
        code: "SCANNER_FAILED",
        domain: "target",
        component: "opengrep",
      },
      at: "2026-08-04T12:01:00.000Z",
    }).state;
    const before = state.scan_queue.entries[0]!;

    const synchronized = syncScanQueue({
      manifest: manifest(target(41, 1, "b")),
      index: emptyIndex,
      state,
      now: "2026-08-04T12:02:00.000Z",
      scannerPolicyVersion: "3",
    }).state;

    expect(synchronized.scan_queue.entries[0]).toMatchObject({
      target_sha: "b".repeat(40),
      ticket: before.ticket,
      consecutive_failures: 2,
      total_failures: 2,
      not_before: "2026-08-11T12:01:00.000Z",
      last_failure: before.last_failure,
      last_failed_at: before.last_failed_at,
      failure_history: before.failure_history,
    });
  });

  test("converts a legacy third failure to a tombstone without reseeding", () => {
    const selected = target(41, 1, "a");
    let state = appendQueuedTarget(stateObserving(selected), selected);
    for (const failedAt of [
      "2026-08-04T12:00:00.000Z",
      "2026-08-04T12:01:00.000Z",
    ])
      state = rotateFailedTarget(state, {
        target: selected,
        failure: {
          code: "SCANNER_FAILED",
          domain: "target",
          component: "opengrep",
        },
        at: failedAt,
      }).state;
    const cooling = state.scan_queue.entries[0]!;
    const terminalAt = "2026-08-11T12:01:00.000Z";
    const terminalHistory = [
      ...(cooling.failure_history ?? []),
      {
        failed_at: terminalAt,
        failure: cooling.last_failure!,
        error_fingerprint: failureFingerprint(cooling.last_failure!),
      },
    ];
    const legacyState = {
      ...state,
      scan_queue: {
        ...state.scan_queue,
        entries: [
          {
            ...cooling,
            consecutive_failures: 3,
            total_failures: 3,
            not_before: "2026-08-11T18:01:00.000Z",
            last_failed_at: terminalAt,
            failure_history: terminalHistory,
          },
        ],
      },
    };

    const synchronized = syncScanQueue({
      manifest: manifest(selected),
      index: emptyIndex,
      state: legacyState,
      now: "2026-08-11T12:02:00.000Z",
      scannerPolicyVersion: "3",
    });

    expect(synchronized.state.scan_queue.entries).toEqual([]);
    expect(synchronized.state.unscannable_targets).toEqual([
      expect.objectContaining({
        repository_id: selected.repository_id,
        target_sha: selected.target_sha,
        consecutive_failures: 3,
        unscannable_at: "2026-08-11T12:02:00.000Z",
      }),
    ]);
    expect(synchronized.summary.terminalized).toBe(1);
  });

  test("makes a legacy first failure immediately retryable", () => {
    const selected = target(41, 1, "a");
    let state = rotateFailedTarget(
      appendQueuedTarget(stateObserving(selected), selected),
      {
        target: selected,
        failure: {
          code: "SCANNER_FAILED",
          domain: "target",
          component: "opengrep",
        },
        at: "2026-08-04T12:00:00.000Z",
      },
    ).state;
    state = {
      ...state,
      scan_queue: {
        ...state.scan_queue,
        entries: state.scan_queue.entries.map((entry) => ({
          ...entry,
          not_before: "2026-08-04T12:05:00.000Z",
        })),
      },
    };

    const synchronized = syncScanQueue({
      manifest: manifest(selected),
      index: emptyIndex,
      state,
      now: "2026-08-04T12:01:00.000Z",
      scannerPolicyVersion: "3",
    });

    expect(synchronized.state.scan_queue.entries[0]?.not_before).toBeNull();
  });

  test("gives a legacy second failure a full seven-day cooldown", () => {
    const selected = target(41, 1, "a");
    let state = appendQueuedTarget(stateObserving(selected), selected);
    for (const failedAt of [
      "2026-08-04T12:00:00.000Z",
      "2026-08-04T12:01:00.000Z",
    ])
      state = rotateFailedTarget(state, {
        target: selected,
        failure: {
          code: "SCANNER_FAILED",
          domain: "target",
          component: "opengrep",
        },
        at: failedAt,
      }).state;
    state = {
      ...state,
      scan_queue: {
        ...state.scan_queue,
        entries: state.scan_queue.entries.map((entry) => ({
          ...entry,
          not_before: "2026-08-04T12:31:00.000Z",
        })),
      },
    };

    const synchronized = syncScanQueue({
      manifest: manifest(selected),
      index: emptyIndex,
      state,
      now: "2026-08-04T12:02:00.000Z",
      scannerPolicyVersion: "3",
    });

    expect(synchronized.state.scan_queue.entries[0]?.not_before).toBe(
      "2026-08-11T12:01:00.000Z",
    );
  });

  test("does not re-enroll a tombstone for SHA, policy, or coverage demand", () => {
    const original = target(41, 1, "a");
    let state = appendQueuedTarget(stateObserving(original), original);
    for (const failedAt of [
      "2026-08-04T12:00:00.000Z",
      "2026-08-04T12:01:00.000Z",
      "2026-08-11T12:01:00.000Z",
    ])
      state = rotateFailedTarget(state, {
        target: original,
        failure: {
          code: "SCANNER_FAILED",
          domain: "target",
          component: "opengrep",
        },
        at: failedAt,
      }).state;
    state = {
      ...state,
      policy_campaigns: [
        {
          id: "policy-3-terminal",
          scanner_policy_version: "3",
          repository_ids: [41],
          created_at: now,
          status: "active" as const,
        },
      ],
      coverage_campaigns: [coverageCampaign([41])],
    };

    const synchronized = syncScanQueue({
      manifest: manifest(target(41, 1, "b")),
      index: emptyIndex,
      state,
      now: "2026-08-11T12:02:00.000Z",
      scannerPolicyVersion: "3",
    });

    expect(synchronized.state.scan_queue.entries).toEqual([]);
    expect(synchronized.state.policy_campaigns[0]).toMatchObject({
      repository_ids: [],
      status: "completed",
    });
    expect(synchronized.state.coverage_campaigns[0]).toMatchObject({
      remaining_repository_ids: [],
      status: "completed",
    });
  });

  test("keeps protected add-back eligible despite an exact current report", () => {
    const selected = target(41, 1, "a");
    let state = appendQueuedTarget(stateObserving(selected), selected);
    for (const failedAt of [
      "2026-08-04T12:00:00.000Z",
      "2026-08-04T12:01:00.000Z",
      "2026-08-11T12:01:00.000Z",
    ])
      state = rotateFailedTarget(state, {
        target: selected,
        failure: {
          code: "SCANNER_FAILED",
          domain: "target",
          component: "opengrep",
        },
        at: failedAt,
      }).state;

    const addedBack = addBackUnscannableTarget(state, selected.repository_id);
    const synchronized = syncScanQueue({
      manifest: manifest(selected),
      index: indexWithRepositoryReport(41, "a"),
      state: addedBack,
      now: "2026-08-11T12:02:00.000Z",
      scannerPolicyVersion: "3",
    });

    expect(synchronized.state.unscannable_targets).toEqual([]);
    expect(synchronized.state.scan_queue.entries).toEqual([
      expect.objectContaining({
        repository_id: 41,
        target_sha: selected.target_sha,
        consecutive_failures: 0,
        staff_requested: true,
        not_before: null,
      }),
    ]);
  });

  test("defers an automatic changed-SHA rescan for seven days after its report", () => {
    const synchronized = syncScanQueue({
      manifest: manifest(target(41, 1, "b")),
      index: indexWithPreviousRepositoryReport,
      state: stateObserving(target(41, 1, "a")),
      now,
      scannerPolicyVersion: "3",
    }).state;

    expect(synchronized.scan_queue.entries).toMatchObject([
      {
        target_sha: "b".repeat(40),
        catalog_change: "updated",
        rescan_not_before: "2026-08-09T12:00:00.000Z",
      },
    ]);
  });

  test("plans a synchronized changed-SHA rescan at its exact deadline", () => {
    const changed = target(41, 1, "b");
    const synchronized = syncScanQueue({
      manifest: manifest(changed),
      index: indexWithPreviousRepositoryReport,
      state: stateObserving(target(41, 1, "a")),
      now,
      scannerPolicyVersion: "3",
    }).state;

    expect(
      planBatch(
        manifest(changed),
        indexWithPreviousRepositoryReport,
        synchronized,
        "2026-08-09T11:59:59.999Z",
        "3",
      ),
    ).toMatchObject({
      targets: [],
      delayedEntries: 1,
      nextWakeAt: "2026-08-09T12:00:00.000Z",
    });
    expect(
      planBatch(
        manifest(changed),
        indexWithPreviousRepositoryReport,
        synchronized,
        "2026-08-09T12:00:00.000Z",
        "3",
      ).targets,
    ).toEqual([
      expect.objectContaining({
        target: expect.objectContaining({ repository_id: 41 }),
        reason: "changed",
      }),
    ]);
  });

  test("retains the deadline across SHA churn and extends it after a newer report", () => {
    const first = syncScanQueue({
      manifest: manifest(target(41, 1, "b")),
      index: indexWithPreviousRepositoryReport,
      state: stateObserving(target(41, 1, "a")),
      now,
      scannerPolicyVersion: "3",
    }).state;
    const firstEntry = first.scan_queue.entries[0]!;
    expect(firstEntry).toMatchObject({
      target_sha: "b".repeat(40),
      catalog_change: "updated",
      rescan_not_before: "2026-08-09T12:00:00.000Z",
    });

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
        ticket: firstEntry.ticket,
        catalog_change: "updated",
        rescan_not_before: "2026-08-09T12:00:00.000Z",
      },
    ]);

    const afterInFlightPublication = syncScanQueue({
      manifest: manifest(target(41, 1, "c")),
      index: indexWithRepositoryReport(41, "b", "2026-08-04T12:01:30.000Z"),
      state: synchronized,
      now: "2026-08-04T12:02:00.000Z",
      scannerPolicyVersion: "3",
    }).state;

    expect(afterInFlightPublication.scan_queue.entries).toMatchObject([
      {
        target_sha: "c".repeat(40),
        ticket: firstEntry.ticket,
        catalog_change: "updated",
        rescan_not_before: "2026-08-11T12:01:30.000Z",
      },
    ]);
  });

  test("omits an automatic-rescan deadline for first, staff, and active-policy work", () => {
    const emptyBaseline = syncScanQueue({
      manifest: manifest(),
      index: emptyIndex,
      state: initialOperationsState(now),
      now,
      scannerPolicyVersion: "3",
    }).state;
    const firstScan = syncScanQueue({
      manifest: manifest(target(42, 1)),
      index: emptyIndex,
      state: emptyBaseline,
      now,
      scannerPolicyVersion: "3",
    }).state.scan_queue.entries[0]!;
    const staffState = appendQueuedTarget(
      {
        ...initialOperationsState(now),
        catalog_observation: {
          initialized_at: now,
          repositories: [
            { repository_id: 41, target_sha: target(41, 1, "a").target_sha },
          ],
        },
      },
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
