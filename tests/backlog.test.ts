import { describe, expect, test } from "vitest";

import type {
  ReportIndex,
  ReportIndexEntry,
} from "../src/contracts/reports.js";
import type { Target, TargetManifest } from "../src/contracts/targets.js";
import {
  initialOperationsState,
  pauseSystem,
} from "../src/operations/state.js";
import { recordFailure } from "../src/operations/retry.js";
import { planBatch } from "../src/queue/backlog.js";

const now = "2026-07-31T12:00:00.000Z";

function manifest(count: number): TargetManifest {
  return {
    schema_version: 1,
    generated_at: now,
    repositories: Array.from({ length: count }, (_, index) => {
      const repositoryId = index + 1;
      return {
        source_id: `github-${repositoryId}`,
        provider: "github",
        repository_id: repositoryId,
        repository: `owner/repo-${repositoryId}`,
        target_sha: repositoryId.toString(16).padStart(40, "0"),
        canonical_url: `https://github.com/owner/repo-${repositoryId}`,
      };
    }),
  };
}

const emptyIndex: ReportIndex = {
  schema_version: 1,
  generated_at: now,
  reports: [],
};

function report(
  target: Target,
  targetSha = target.target_sha,
): ReportIndexEntry {
  return {
    report_id: target.repository_id.toString(16).padStart(64, "0"),
    report_version: 1,
    supersedes_report_id: null,
    scanner_version: "1.0.0",
    scanner_policy_version: "1",
    prompt_policy_version: "1",
    source_id: target.source_id,
    provider: "github",
    repository_id: target.repository_id,
    repository: target.repository,
    target_sha: targetSha,
    completed_at: "2026-07-30T12:00:00.000Z",
    mode: "standard",
    result: "green",
    finding_counts: {
      total: 0,
      actionable: 0,
      severity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      confidence: { high: 0, medium: 0, low: 0 },
      disposition: { active: 0, dismissed: 0 },
      categories: [],
    },
    coverage: {
      history_commits: 1,
      inventory_files: 1,
      inventory_bytes: 1,
      tools_completed: 3,
      tools_not_applicable: 3,
      model_chunks: 1,
    },
    report_url:
      `https://mentallyquill.github.io/TavernKeeper/reports/github/` +
      `${target.repository_id}/${targetSha}/1/standard/1/`,
  };
}

describe("derived scan backlog", () => {
  test("selects at most five unique newly listed repositories", () => {
    const plan = planBatch(
      manifest(7),
      emptyIndex,
      initialOperationsState(now),
      now,
    );

    expect(plan.targets).toHaveLength(5);
    expect(
      new Set(plan.targets.map(({ target }) => target.repository_id)).size,
    ).toBe(5);
    expect(plan.targets.map(({ reason }) => reason)).toEqual([
      "new",
      "new",
      "new",
      "new",
      "new",
    ]);
    expect(plan.remaining).toBe(2);
  });

  test("orders new, changed, due retry, then policy work", () => {
    const targets = manifest(5);
    const [changed, covered, newlyListed, retrying, policy] =
      targets.repositories;
    const oldSha = "f".repeat(40);
    const index: ReportIndex = {
      ...emptyIndex,
      reports: [report(changed!, oldSha), report(covered!), report(policy!)],
    };
    const retryState = recordFailure(initialOperationsState(now), {
      target: retrying!,
      code: "REPOSITORY_PARSE_FAILED",
      scope: "repository",
      at: "2026-07-31T10:00:00.000Z",
    }).state;
    const state = {
      ...retryState,
      policy_campaigns: [
        {
          id: "policy-1",
          scanner_policy_version: "1",
          repository_ids: [policy!.repository_id],
          created_at: "2026-07-29T12:00:00.000Z",
          status: "active" as const,
        },
      ],
    };

    const plan = planBatch(targets, index, state, now);

    expect(
      plan.targets.map(({ target, reason }) => [target.repository_id, reason]),
    ).toEqual([
      [newlyListed!.repository_id, "new"],
      [changed!.repository_id, "changed"],
      [retrying!.repository_id, "retry"],
      [policy!.repository_id, "policy"],
    ]);
  });

  test("staff pause prevents dispatch without discarding backlog", () => {
    const state = pauseSystem(initialOperationsState(now), {
      kind: "staff",
      reasonCode: "STAFF_PAUSE",
      at: now,
    });

    expect(planBatch(manifest(3), emptyIndex, state, now)).toMatchObject({
      targets: [],
      remaining: 3,
      blocked: true,
    });
  });

  test("a transient system breaker allows only its due recovery retry", () => {
    const targets = manifest(3);
    const recovery = targets.repositories[1]!;
    const state = recordFailure(initialOperationsState(now), {
      target: recovery,
      code: "MODEL_QUOTA",
      scope: "system",
      at: "2026-07-31T10:00:00.000Z",
    }).state;

    const plan = planBatch(targets, emptyIndex, state, now);

    expect(plan).toMatchObject({ blocked: false });
    expect(
      plan.targets.map(({ target, reason }) => [target.repository_id, reason]),
    ).toEqual([[recovery.repository_id, "retry"]]);
  });

  test("keeps one queue position when an active repository advances SHA", () => {
    const targets = manifest(2);
    const activeTarget = targets.repositories[0]!;
    const state = {
      ...initialOperationsState(now),
      active_scans: [
        {
          source_id: activeTarget.source_id,
          repository_id: activeTarget.repository_id,
          target_sha: "f".repeat(40),
          started_at: "2026-07-31T11:00:00.000Z",
          run_id: "run-1",
        },
      ],
    };

    const plan = planBatch(targets, emptyIndex, state, now);

    expect(plan.targets.map(({ target }) => target.repository_id)).toEqual([2]);
  });
});
