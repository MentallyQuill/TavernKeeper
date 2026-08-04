import { describe, expect, test } from "vitest";

import type {
  ReportIndexEntryV5,
  ReportIndexV5,
} from "../src/contracts/reports-v5.js";
import type {
  TargetManifestV2,
  TargetManifestV3,
  TargetV2,
  TargetV3,
} from "../src/contracts/targets.js";
import {
  initialOperationsState,
  pauseSystem,
  type OperationsState,
} from "../src/operations/state.js";
import { recordFailure } from "../src/operations/retry.js";
import { planBatch } from "../src/queue/backlog.js";

const now = "2026-08-01T12:00:00.000Z";
const coverageStartedAt = "2026-07-31T12:00:00.000Z";

function target(
  repositoryId: number,
  options: { top30?: boolean; firstCatalogedAt?: string } = {},
): TargetV2 {
  return {
    source_id: `github-${repositoryId}`,
    provider: "github",
    repository_id: repositoryId,
    repository: `owner/repo-${repositoryId}`,
    target_sha: repositoryId.toString(16).padStart(40, "0"),
    canonical_url: `https://github.com/owner/repo-${repositoryId}`,
    project_kinds: ["extension"],
    catalog_priority: {
      top_30: options.top30 ?? false,
      first_cataloged_at:
        options.firstCatalogedAt ?? "2026-07-01T00:00:00.000Z",
    },
  };
}

function manifest(repositories: TargetV2[]): TargetManifestV2 {
  return {
    schema_version: 2,
    generated_at: now,
    repositories: [...repositories].sort(
      (left, right) => left.repository_id - right.repository_id,
    ),
  };
}

function targetV3(
  repositoryId: number,
  options: { rank: number; firstCatalogedAt?: string },
): TargetV3 {
  return {
    ...target(repositoryId, {
      top30: options.rank <= 30,
      ...(options.firstCatalogedAt === undefined
        ? {}
        : { firstCatalogedAt: options.firstCatalogedAt }),
    }),
    catalog_priority: {
      ...target(repositoryId).catalog_priority,
      first_cataloged_at:
        options.firstCatalogedAt ?? "2026-07-01T00:00:00.000Z",
      top_30: options.rank <= 30,
      popularity_rank: options.rank,
    },
  };
}

function manifestV3(repositories: TargetV3[]): TargetManifestV3 {
  return {
    schema_version: 3,
    generated_at: now,
    repositories: [...repositories].sort(
      (left, right) => left.repository_id - right.repository_id,
    ),
  };
}

const emptyIndex: ReportIndexV5 = {
  schema_version: 5,
  generated_at: now,
  reports: [],
};

function runningState(overrides: Partial<OperationsState> = {}) {
  return {
    ...initialOperationsState(coverageStartedAt),
    coverage_started_at: coverageStartedAt,
    ...overrides,
  } as OperationsState;
}

function report(targetValue: TargetV2, targetSha = targetValue.target_sha) {
  const reportId = targetValue.repository_id.toString(16).padStart(64, "0");
  const entry: ReportIndexEntryV5 = {
    report_id: reportId,
    report_digest: reportId,
    report_version: 1,
    supersedes_report_id: null,
    scanner_version: "1.0.0",
    scanner_policy_version: "2",
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
    target_sha: targetSha,
    completed_at: "2026-07-30T12:00:00.000Z",
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
      tools_completed: 3,
      tools_not_applicable: 3,
      evidence_validated: 0,
      review_required: 0,
      review_completed: 0,
    },
    report_url:
      `https://mentallyquill.github.io/TavernKeeper/reports/github/` +
      `${targetValue.repository_id}/${targetSha}/2/${reportId}/`,
    history_url:
      "https://mentallyquill.github.io/TavernKeeper/reports/github/" +
      `${targetValue.repository_id}/history/`,
  };
  return entry;
}

function identity(targetValue: TargetV2) {
  const {
    project_kinds: _projectKinds,
    catalog_priority: _catalogPriority,
    ...value
  } = targetValue;
  return value;
}

describe("derived scan backlog", () => {
  test("orders Top 30, new submissions, and old projects in batches of five", () => {
    const targets = manifest([
      target(2, { firstCatalogedAt: "2026-01-01T00:00:00.000Z" }),
      target(3, { firstCatalogedAt: "2026-02-01T00:00:00.000Z" }),
      target(30, { top30: true }),
      target(31, { top30: true }),
      target(44, { firstCatalogedAt: "2026-08-01T00:00:00.000Z" }),
      target(45, { firstCatalogedAt: "2026-08-01T01:00:00.000Z" }),
      target(46, { firstCatalogedAt: "2026-08-01T02:00:00.000Z" }),
    ]);

    const plan = planBatch(targets, emptyIndex, runningState(), now);

    expect(
      plan.targets.map(({ lane, target: item }) => [lane, item.repository_id]),
    ).toEqual([
      ["top-30", 30],
      ["top-30", 31],
      ["new-submission", 44],
      ["new-submission", 45],
      ["new-submission", 46],
    ]);
    expect(plan.targets).toHaveLength(5);
    expect(plan.totalRemaining).toBe(2);
  });

  test("sorts new and old lanes by first cataloged time", () => {
    const targets = manifest([
      target(1, { firstCatalogedAt: "2026-05-01T00:00:00.000Z" }),
      target(2, { firstCatalogedAt: "2026-01-01T00:00:00.000Z" }),
      target(3, { firstCatalogedAt: "2026-08-01T02:00:00.000Z" }),
      target(4, { firstCatalogedAt: "2026-08-01T01:00:00.000Z" }),
    ]);

    expect(
      planBatch(targets, emptyIndex, runningState(), now).targets.map(
        ({ lane, target: item }) => [lane, item.repository_id],
      ),
    ).toEqual([
      ["new-submission", 4],
      ["new-submission", 3],
      ["old-project", 2],
      ["old-project", 1],
    ]);
  });

  test("returns due retries to the target's source lane", () => {
    const retryTarget = target(44, {
      firstCatalogedAt: "2026-08-01T00:00:00.000Z",
    });
    const retryState = recordFailure(runningState(), {
      target: identity(retryTarget),
      failure: {
        code: "REPOSITORY_PARSE_FAILED",
        domain: "target",
        component: "orchestrator",
      },
      at: "2026-08-01T10:00:00.000Z",
    }).state;

    expect(
      planBatch(manifest([retryTarget]), emptyIndex, retryState, now).targets,
    ).toMatchObject([
      {
        lane: "new-submission",
        reason: "retry",
        target: { repository_id: 44 },
      },
    ]);
  });

  test("dispatches a model reply retry exactly at its five-minute boundary", () => {
    const retryTarget = target(44);
    const state = recordFailure(runningState(), {
      target: identity(retryTarget),
      failure: {
        code: "MODEL_INVALID_RESPONSE",
        domain: "target",
        component: "contextual-model",
      },
      at: "2026-08-01T11:00:00.000Z",
    }).state;

    expect(
      planBatch(
        manifest([retryTarget]),
        emptyIndex,
        state,
        "2026-08-01T11:04:59.999Z",
      ).targets,
    ).toEqual([]);
    expect(
      planBatch(
        manifest([retryTarget]),
        emptyIndex,
        state,
        "2026-08-01T11:05:00.000Z",
      ).targets,
    ).toMatchObject([{ reason: "retry", target: { repository_id: 44 } }]);
  });

  test("pause and shared hold still block unrelated retries", () => {
    const replyTarget = target(44);
    const recoveryTarget = target(45);
    const replyState = recordFailure(runningState(), {
      target: identity(replyTarget),
      failure: {
        code: "MODEL_INVALID_RESPONSE",
        domain: "target",
        component: "contextual-model",
      },
      at: "2026-08-01T10:00:00.000Z",
    }).state;
    const paused = pauseSystem(replyState, {
      kind: "staff",
      reasonCode: "STAFF_PAUSE",
      at: "2026-08-01T10:05:00.000Z",
    });

    expect(
      planBatch(
        manifest([replyTarget]),
        emptyIndex,
        paused,
        "2026-08-01T10:05:00.000Z",
      ),
    ).toMatchObject({ targets: [], totalRemaining: 1, blocked: true });

    const withBreaker = recordFailure(replyState, {
      target: identity(recoveryTarget),
      failure: {
        code: "MODEL_QUOTA",
        domain: "shared",
        component: "contextual-model",
      },
      at: "2026-08-01T09:00:00.000Z",
    }).state;
    const plan = planBatch(
      manifest([replyTarget, recoveryTarget]),
      emptyIndex,
      withBreaker,
      "2026-08-01T10:05:00.000Z",
    );

    expect(plan.targets).toMatchObject([
      { reason: "retry", target: { repository_id: 45 } },
    ]);
    expect(plan.totalRemaining).toBe(1);
  });

  test("age boosts a long-waiting old project without changing its lane", () => {
    const oldCoverage = "2026-05-01T00:00:00.000Z";
    const targets = manifest([
      target(2, { firstCatalogedAt: "2026-01-01T00:00:00.000Z" }),
      target(30, { top30: true, firstCatalogedAt: now }),
    ]);

    const plan = planBatch(
      targets,
      emptyIndex,
      runningState({ coverage_started_at: oldCoverage }),
      now,
    );

    expect(plan.targets[0]).toMatchObject({
      lane: "old-project",
      target: { repository_id: 2 },
    });
  });

  test("staff pause prevents dispatch without discarding backlog", () => {
    const state = pauseSystem(runningState(), {
      kind: "staff",
      reasonCode: "STAFF_PAUSE",
      at: now,
    });

    expect(
      planBatch(
        manifest([target(1), target(2), target(3)]),
        emptyIndex,
        state,
        now,
      ),
    ).toMatchObject({ targets: [], totalRemaining: 3, blocked: true });
  });

  test("a transient shared hold allows only its due recovery retry", () => {
    const recovery = target(2);
    const state = recordFailure(runningState(), {
      target: identity(recovery),
      failure: {
        code: "MODEL_QUOTA",
        domain: "shared",
        component: "contextual-model",
      },
      at: "2026-08-01T10:00:00.000Z",
    }).state;

    const plan = planBatch(
      manifest([target(1), recovery, target(3)]),
      emptyIndex,
      state,
      now,
    );

    expect(plan).toMatchObject({ blocked: false });
    expect(
      plan.targets.map(({ target: item, reason }) => [
        item.repository_id,
        reason,
      ]),
    ).toEqual([[recovery.repository_id, "retry"]]);
  });

  test("probes a due shared hold after its repository advances SHA", () => {
    const failedTarget = targetV3(100, { rank: 1 });
    const state = recordFailure(runningState(), {
      target: identity(failedTarget),
      failure: {
        code: "MODEL_PROVIDER",
        domain: "shared",
        component: "contextual-model",
      },
      at: "2026-08-01T11:00:00.000Z",
    }).state;
    const advancedTarget = {
      ...failedTarget,
      target_sha: "f".repeat(40),
    };

    const plan = planBatch(
      manifestV3([advancedTarget]),
      emptyIndex,
      state,
      now,
      "3",
    );

    expect(plan).toMatchObject({ blocked: false, sharedHolds: 1 });
    expect(plan.targets).toEqual([
      expect.objectContaining({
        reason: "retry",
        target: expect.objectContaining({
          repository_id: 100,
          target_sha: "f".repeat(40),
        }),
      }),
    ]);
  });

  test("rebinds a due shared probe when its repository leaves the catalog", () => {
    const removedTarget = targetV3(100, { rank: 1 });
    const state = recordFailure(runningState(), {
      target: identity(removedTarget),
      failure: {
        code: "MODEL_PROVIDER",
        domain: "shared",
        component: "contextual-model",
      },
      at: "2026-08-01T11:00:00.000Z",
    }).state;

    const plan = planBatch(
      manifestV3([targetV3(200, { rank: 2 })]),
      emptyIndex,
      state,
      now,
      "3",
    );

    expect(plan).toMatchObject({ blocked: false, sharedHolds: 1 });
    expect(plan.targets).toEqual([
      expect.objectContaining({
        reason: "retry",
        recoveryFingerprint: state.shared_holds[0]!.error_fingerprint,
        target: expect.objectContaining({ repository_id: 200 }),
      }),
    ]);
  });

  test("keeps one queue position when an active repository advances SHA", () => {
    const activeTarget = target(1);
    const state = runningState({
      active_scans: [
        {
          source_id: activeTarget.source_id,
          repository_id: activeTarget.repository_id,
          target_sha: "f".repeat(40),
          started_at: "2026-08-01T11:00:00.000Z",
          run_id: "run-1",
        },
      ],
    });

    const plan = planBatch(
      manifest([activeTarget, target(2)]),
      emptyIndex,
      state,
      now,
    );

    expect(plan.targets.map(({ target: item }) => item.repository_id)).toEqual([
      2,
    ]);
  });

  test("skips targets already covered at the current SHA and policy", () => {
    const covered = target(30, { top30: true });
    const index: ReportIndexV5 = {
      ...emptyIndex,
      reports: [report(covered)],
    };
    expect(
      planBatch(manifest([covered]), index, runningState(), now).targets,
    ).toEqual([]);
  });

  test("orders V3 initial coverage by exact popularity rank", () => {
    const plan = planBatch(
      manifestV3([
        targetV3(300, { rank: 3 }),
        targetV3(100, { rank: 1 }),
        targetV3(200, { rank: 2 }),
      ]),
      emptyIndex,
      runningState(),
      now,
      "3",
    );

    expect(plan.targets.map(({ target: item }) => item.repository_id)).toEqual([
      100, 200, 300,
    ]);
  });

  test("does not reselect an exhausted exact SHA as new", () => {
    const exhaustedTarget = targetV3(100, { rank: 1 });
    let state = runningState();
    for (const at of [
      "2026-08-01T08:00:00.000Z",
      "2026-08-01T08:05:00.000Z",
      "2026-08-01T08:30:00.000Z",
      "2026-08-01T10:00:00.000Z",
    ])
      state = recordFailure(state, {
        target: identity(exhaustedTarget),
        failure: {
          code: "SCANNER_FAILED",
          domain: "target",
          component: "opengrep",
        },
        at,
      }).state;

    const plan = planBatch(
      manifestV3([exhaustedTarget]),
      emptyIndex,
      state,
      now,
      "3",
    );
    expect(plan.targets).toEqual([]);
    expect(plan).toMatchObject({ runnableRemaining: 0, totalRemaining: 1 });
  });

  test("prioritizes due target retries ahead of new ranked work", () => {
    const retryTarget = targetV3(300, { rank: 3 });
    const state = recordFailure(runningState(), {
      target: identity(retryTarget),
      failure: {
        code: "SCANNER_FAILED",
        domain: "target",
        component: "opengrep",
      },
      at: "2026-08-01T11:00:00.000Z",
    }).state;
    const plan = planBatch(
      manifestV3([
        targetV3(100, { rank: 1 }),
        targetV3(200, { rank: 2 }),
        retryTarget,
      ]),
      emptyIndex,
      state,
      now,
      "3",
    );

    expect(plan.targets.map(({ target: item }) => item.repository_id)).toEqual([
      300, 100, 200,
    ]);
  });

  test("reports a future wake for a non-due shared hold", () => {
    const recovery = targetV3(100, { rank: 1 });
    const state = recordFailure(runningState(), {
      target: identity(recovery),
      failure: {
        code: "MODEL_PROVIDER",
        domain: "shared",
        component: "contextual-model",
      },
      at: "2026-08-01T11:59:00.000Z",
    }).state;
    const plan = planBatch(
      manifestV3([recovery, targetV3(200, { rank: 2 })]),
      emptyIndex,
      state,
      now,
      "3",
    );

    expect(plan).toMatchObject({
      targets: [],
      runnableRemaining: 0,
      delayedRetries: 1,
      sharedHolds: 1,
      nextWakeAt: "2026-08-01T12:04:00.000Z",
      blocked: true,
    });
  });

  test("admits at most two due shared probes, one per fingerprint", () => {
    const failures = [
      [100, "MODEL_PROVIDER"],
      [200, "MODEL_QUOTA"],
      [300, "SCANNER_UNAVAILABLE"],
    ] as const;
    let state = runningState();
    for (const [repositoryId, code] of failures)
      state = recordFailure(state, {
        target: identity(targetV3(repositoryId, { rank: repositoryId / 100 })),
        failure: {
          code,
          domain: "shared",
          component:
            code === "SCANNER_UNAVAILABLE"
              ? "orchestrator"
              : "contextual-model",
        },
        at: "2026-08-01T11:00:00.000Z",
      }).state;

    const plan = planBatch(
      manifestV3([
        targetV3(100, { rank: 1 }),
        targetV3(200, { rank: 2 }),
        targetV3(300, { rank: 3 }),
      ]),
      emptyIndex,
      state,
      now,
      "3",
    );
    expect(plan.targets).toHaveLength(2);
    expect(
      new Set(plan.targets.map(({ target: item }) => item.repository_id)).size,
    ).toBe(2);
  });

  test("does not count a delayed-only retry as runnable", () => {
    const delayed = targetV3(100, { rank: 1 });
    const state = recordFailure(runningState(), {
      target: identity(delayed),
      failure: {
        code: "SCANNER_FAILED",
        domain: "target",
        component: "opengrep",
      },
      at: "2026-08-01T11:59:00.000Z",
    }).state;
    const plan = planBatch(manifestV3([delayed]), emptyIndex, state, now, "3");

    expect(plan).toMatchObject({
      targets: [],
      totalRemaining: 1,
      runnableRemaining: 0,
      delayedRetries: 1,
      nextWakeAt: "2026-08-01T12:04:00.000Z",
    });
  });
});
