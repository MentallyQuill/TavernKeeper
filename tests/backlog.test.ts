import { describe, expect, test } from "vitest";

import type {
  ReportIndexEntryV4,
  ReportIndexV4,
} from "../src/contracts/reports.js";
import type { TargetManifestV2, TargetV2 } from "../src/contracts/targets.js";
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

const emptyIndex: ReportIndexV4 = {
  schema_version: 4,
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
  const entry: ReportIndexEntryV4 = {
    report_id: targetValue.repository_id.toString(16).padStart(64, "0"),
    report_version: 1,
    supersedes_report_id: null,
    scanner_version: "1.0.0",
    scanner_policy_version: "2",
    rule_catalog_version: "1",
    package_schema_version: 1,
    source_id: targetValue.source_id,
    provider: "github",
    repository_id: targetValue.repository_id,
    repository: targetValue.repository,
    target_sha: targetSha,
    completed_at: "2026-07-30T12:00:00.000Z",
    assessment_method: "deterministic-static-analysis",
    result: "teal",
    summary: {
      headline: "No reportable concerns detected",
      detail:
        "All required scanners completed, and no finding met the reportable threshold.",
    },
    finding_counts: {
      total: 0,
      reportable: 0,
      informational: 0,
      reportable_severity: { critical: 0, high: 0, medium: 0 },
      severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      confidence: { high: 0, medium: 0, low: 0 },
      policy_status: { reportable: 0, informational: 0 },
      categories: [],
    },
    coverage: {
      history_commits: 1,
      inventory_files: 1,
      inventory_bytes: 1,
      tools_completed: 3,
      tools_not_applicable: 3,
      evidence_validated: 0,
    },
    report_url:
      `https://mentallyquill.github.io/TavernKeeper/reports/github/` +
      `${targetValue.repository_id}/${targetSha}/2/1/`,
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
    expect(plan.remaining).toBe(2);
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
      code: "REPOSITORY_PARSE_FAILED",
      scope: "repository",
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
    ).toMatchObject({ targets: [], remaining: 3, blocked: true });
  });

  test("a transient system breaker allows only its due recovery retry", () => {
    const recovery = target(2);
    const state = recordFailure(runningState(), {
      target: identity(recovery),
      code: "MODEL_QUOTA",
      scope: "system",
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
    const index: ReportIndexV4 = {
      ...emptyIndex,
      reports: [report(covered)],
    };
    expect(
      planBatch(manifest([covered]), index, runningState(), now).targets,
    ).toEqual([]);
  });
});
