import { describe, expect, test } from "vitest";

import type { ReportIndexV5 } from "../src/contracts/reports-v5.js";
import type { TargetManifestV3, TargetV3 } from "../src/contracts/targets.js";
import {
  COVERAGE_CAMPAIGN_ID,
  initialOperationsState,
  pauseSystem,
} from "../src/operations/state.js";
import {
  dueRetries,
  recordAutomaticProbeSuccess,
  recordFailure,
} from "../src/operations/retry.js";
import {
  appendQueuedTarget,
  rotateFailedTarget,
} from "../src/queue/durable-queue.js";
import { planBatch } from "../src/queue/backlog.js";

const now = "2026-08-04T12:00:00.000Z";
const emptyIndex: ReportIndexV5 = {
  schema_version: 5,
  generated_at: now,
  reports: [],
};

function target(repositoryId: number, rank: number): TargetV3 {
  return {
    source_id: `github-${repositoryId}`,
    provider: "github",
    repository_id: repositoryId,
    repository: `owner/repo-${repositoryId}`,
    target_sha: repositoryId.toString(16).padStart(40, "0"),
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

function queued(...targets: TargetV3[]) {
  let state = initialOperationsState(now);
  for (const value of targets) state = appendQueuedTarget(state, value);
  return state;
}

function withCoverageCampaign(
  state: ReturnType<typeof initialOperationsState>,
  repositoryIds: number[],
) {
  return {
    ...state,
    coverage_campaigns: [
      {
        id: COVERAGE_CAMPAIGN_ID,
        scanner_policy_version: "3",
        created_at: now,
        status: "active" as const,
        popular_repository_ids: [...repositoryIds],
        latest_release_repository_ids: [] as number[],
        repository_ids: [...repositoryIds],
        remaining_repository_ids: [...repositoryIds],
      },
    ],
  };
}

describe("durable backlog planning", () => {
  test("keeps coverage work behind its automatic rescan deadline", () => {
    const selected = target(41, 1);
    const base = withCoverageCampaign(queued(selected), [41]);
    const state = {
      ...base,
      scan_queue: {
        ...base.scan_queue,
        entries: base.scan_queue.entries.map((entry) => ({
          ...entry,
          rescan_not_before: "2026-08-04T13:00:00.000Z",
        })),
      },
    };

    expect(
      planBatch(manifest(selected), emptyIndex, state, now, "3"),
    ).toMatchObject({
      targets: [],
      delayedEntries: 1,
      nextWakeAt: "2026-08-04T13:00:00.000Z",
    });
    expect(
      planBatch(
        manifest(selected),
        emptyIndex,
        state,
        "2026-08-04T13:00:00.000Z",
        "3",
      ).targets.map(({ reason }) => reason),
    ).toEqual(["coverage"]);
  });

  test("uses retry, staff, policy, then coverage reason precedence", () => {
    const retry = target(41, 1);
    const staff = target(42, 2);
    const policy = target(43, 3);
    const coverage = target(44, 4);
    const base = withCoverageCampaign(
      queued(retry, staff, policy, coverage),
      [41, 42, 43, 44],
    );
    const state = {
      ...base,
      policy_campaigns: [
        {
          id: "policy-3-regression",
          scanner_policy_version: "3",
          repository_ids: [43],
          created_at: now,
          status: "active" as const,
        },
      ],
      scan_queue: {
        ...base.scan_queue,
        entries: base.scan_queue.entries.map((entry) => {
          if (entry.repository_id === 41)
            return {
              ...entry,
              consecutive_failures: 1,
              total_failures: 1,
              last_failure: {
                code: "SCANNER_FAILED",
                domain: "target" as const,
                component: "opengrep" as const,
              },
              last_failed_at: now,
            };
          if (entry.repository_id === 42)
            return { ...entry, staff_requested: true as const };
          return entry;
        }),
      },
    };

    expect(
      planBatch(
        manifest(retry, staff, policy, coverage),
        emptyIndex,
        state,
        now,
        "3",
      ).targets.map(({ target: value, reason }) => [
        value.repository_id,
        reason,
      ]),
    ).toEqual([
      [42, "staff"],
      [43, "policy"],
      [44, "coverage"],
      [41, "retry"],
    ]);
  });

  test("keeps new submissions ahead of coverage work", () => {
    const first = target(41, 1);
    const second = target(42, 2);
    const selected = target(43, 3);
    const base = withCoverageCampaign(queued(first, second, selected), [43]);
    const state = {
      ...base,
      scan_queue: {
        ...base.scan_queue,
        entries: base.scan_queue.entries.map((entry) => ({
          ...entry,
          ...(entry.repository_id === 41 || entry.repository_id === 42
            ? { catalog_change: "new" as const }
            : {}),
        })),
      },
    };

    expect(
      planBatch(
        manifest(first, second, selected),
        emptyIndex,
        state,
        now,
        "3",
      ).targets.map(({ target: value, reason }) => [
        value.repository_id,
        reason,
      ]),
    ).toEqual([
      [41, "new"],
      [42, "new"],
      [43, "coverage"],
    ]);
  });

  test("delays a changed-SHA automatic rescan until its exact deadline", () => {
    const value = target(41, 1);
    const base = queued(value);
    const state = {
      ...base,
      scan_queue: {
        ...base.scan_queue,
        entries: base.scan_queue.entries.map((entry) => ({
          ...entry,
          rescan_not_before: "2026-08-04T12:00:00.000Z",
        })),
      },
    };

    const beforeDeadline = planBatch(
      manifest(value),
      emptyIndex,
      state,
      "2026-08-04T11:59:59.999Z",
      "3",
    );
    expect(beforeDeadline.targets).toEqual([]);
    expect(beforeDeadline).toMatchObject({
      delayedEntries: 1,
      nextWakeAt: "2026-08-04T12:00:00.000Z",
    });
    expect(
      planBatch(
        manifest(value),
        emptyIndex,
        state,
        "2026-08-04T12:00:00.000Z",
        "3",
      ).targets.map(({ target: planned }) => planned.repository_id),
    ).toEqual([41]);
  });

  test("exempts staff, retry, and active policy work while preserving queue priority", () => {
    const staff = target(41, 1);
    const retry = target(42, 2);
    const policy = target(43, 3);
    const base = queued(staff, retry, policy);
    const state = {
      ...base,
      policy_campaigns: [
        {
          id: "refresh-43",
          scanner_policy_version: "3",
          repository_ids: [43],
          created_at: now,
          status: "active" as const,
        },
      ],
      scan_queue: {
        ...base.scan_queue,
        entries: base.scan_queue.entries.map((entry) => ({
          ...entry,
          rescan_not_before: "2026-08-04T13:00:00.000Z",
          ...(entry.repository_id === 41
            ? { staff_requested: true as const }
            : {}),
          ...(entry.repository_id === 42
            ? {
                consecutive_failures: 1,
                total_failures: 1,
                last_failure: {
                  code: "SCANNER_FAILED",
                  domain: "target" as const,
                  component: "opengrep" as const,
                },
                last_failed_at: now,
              }
            : {}),
        })),
      },
    };

    expect(
      planBatch(
        manifest(staff, retry, policy),
        emptyIndex,
        state,
        now,
        "3",
      ).targets.map(({ target: planned }) => planned.repository_id),
    ).toEqual([41, 43, 42]);
  });

  test("keeps retry scheduling governed by not_before", () => {
    const value = target(41, 1);
    const base = queued(value);
    const state = {
      ...base,
      scan_queue: {
        ...base.scan_queue,
        entries: base.scan_queue.entries.map((entry) => ({
          ...entry,
          consecutive_failures: 1,
          total_failures: 1,
          not_before: "2026-08-04T13:00:00.000Z",
          rescan_not_before: "2026-08-05T12:00:00.000Z",
          last_failure: {
            code: "SCANNER_FAILED",
            domain: "target" as const,
            component: "opengrep" as const,
          },
          last_failed_at: now,
        })),
      },
    };

    const plan = planBatch(manifest(value), emptyIndex, state, now, "3");
    expect(plan.targets).toEqual([]);
    expect(plan).toMatchObject({
      delayedEntries: 1,
      nextWakeAt: "2026-08-04T13:00:00.000Z",
    });
  });

  test("selects no more than five lowest due tickets", () => {
    const targets = Array.from({ length: 8 }, (_, index) =>
      target(index + 1, index + 1),
    );
    const plan = planBatch(
      manifest(...targets),
      emptyIndex,
      queued(...targets),
      now,
      "3",
    );

    expect(
      plan.targets.map(({ target: value }) => value.repository_id),
    ).toEqual([1, 2, 3, 4, 5]);
    expect(plan).toMatchObject({
      totalRemaining: 3,
      runnableRemaining: 3,
      delayedEntries: 0,
      nextWakeAt: null,
      emergencyStopped: false,
    });
  });

  test("selects due staff requests before ordinary tickets without bypassing cooldowns", () => {
    const targets = Array.from({ length: 6 }, (_, index) =>
      target(index + 1, index + 1),
    );
    let state = queued(...targets);
    state = appendQueuedTarget(state, targets[5]!, { staffRequested: true });

    expect(
      planBatch(manifest(...targets), emptyIndex, state, now, "3").targets.map(
        ({ target: value }) => value.repository_id,
      ),
    ).toEqual([6, 1, 2, 3, 4]);

    state = {
      ...state,
      scan_queue: {
        ...state.scan_queue,
        entries: state.scan_queue.entries.map((entry) =>
          entry.repository_id === 6
            ? {
                ...entry,
                consecutive_failures: 1,
                total_failures: 1,
                not_before: "2026-08-04T13:00:00.000Z",
                last_failure: {
                  code: "SCANNER_FAILED",
                  domain: "target" as const,
                  component: "opengrep" as const,
                },
                last_failed_at: now,
              }
            : entry,
        ),
      },
    };
    expect(
      planBatch(manifest(...targets), emptyIndex, state, now, "3").targets.map(
        ({ target: value }) => value.repository_id,
      ),
    ).toEqual([1, 2, 3, 4, 5]);
  });

  test("a cooling retry remains behind clean work when it becomes due", () => {
    const targets = [target(41, 1), target(42, 2), target(43, 3)];
    let state = queued(...targets);
    state = {
      ...state,
      scan_queue: {
        ...state.scan_queue,
        entries: state.scan_queue.entries.map((entry) =>
          entry.repository_id === 41
            ? {
                ...entry,
                consecutive_failures: 1,
                total_failures: 1,
                not_before: "2026-08-04T13:00:00.000Z",
                last_failure: {
                  code: "SCANNER_FAILED",
                  domain: "target" as const,
                  component: "opengrep" as const,
                },
                last_failed_at: now,
              }
            : entry,
        ),
      },
    };

    expect(
      planBatch(
        manifest(...targets),
        emptyIndex,
        state,
        "2026-08-04T12:30:00.000Z",
        "3",
      ).targets.map(({ target: value }) => value.repository_id),
    ).toEqual([42, 43]);
    expect(
      planBatch(
        manifest(...targets),
        emptyIndex,
        state,
        "2026-08-04T13:00:00.000Z",
        "3",
      ).targets.map(({ target: value }) => value.repository_id),
    ).toEqual([42, 43, 41]);
  });

  test("selects clean catalog work before a lower-ticket due retry", () => {
    const retry = target(41, 1);
    const clean = target(42, 2);
    let state = recordFailure(queued(retry), {
      target: retry,
      failure: {
        code: "SCANNER_FAILED",
        domain: "target",
        component: "opengrep",
      },
      at: "2026-08-04T11:00:00.000Z",
    }).state;
    state = appendQueuedTarget(state, clean);

    expect(
      planBatch(
        manifest(retry, clean),
        emptyIndex,
        state,
        now,
        "3",
      ).targets.map(({ target: value }) => value.repository_id),
    ).toEqual([42, 41]);
  });

  test("clean arrivals remain ahead of a rotated failure", () => {
    const first = target(41, 1);
    const second = target(42, 2);
    const later = target(43, 3);
    let state = rotateFailedTarget(queued(first, second), {
      target: first,
      failure: {
        code: "SCANNER_FAILED",
        domain: "target",
        component: "opengrep",
      },
      at: "2026-08-04T00:00:00.000Z",
    }).state;
    state = appendQueuedTarget(state, later);

    expect(
      planBatch(
        manifest(first, second, later),
        emptyIndex,
        state,
        now,
        "3",
      ).targets.map(({ target: value }) => value.repository_id),
    ).toEqual([42, 43, 41]);
  });

  test("a systemic failure requests a direct provider probe then resumes ticket order", () => {
    const targets = [target(41, 1), target(42, 2), target(43, 3)];
    const failure = {
      code: "MODEL_PROVIDER",
      domain: "shared" as const,
      component: "contextual-model" as const,
    };
    const held = recordFailure(queued(...targets), {
      target: targets[0]!,
      failure,
      at: now,
    }).state;

    const cooling = planBatch(
      manifest(...targets),
      emptyIndex,
      held,
      "2026-08-04T12:04:59.000Z",
      "3",
    );
    expect(cooling.targets).toEqual([]);
    expect(cooling).toMatchObject({
      automaticHolds: 1,
      recoveryProbes: 0,
      nextWakeAt: "2026-08-04T12:05:00.000Z",
    });

    const probing = planBatch(
      manifest(...targets),
      emptyIndex,
      held,
      "2026-08-04T12:05:00.000Z",
      "3",
    );
    expect(probing.targets).toEqual([]);
    expect(probing.providerProbeFingerprint).toBe(
      held.automatic_holds[0]!.error_fingerprint,
    );
    expect(probing.recoveryProbes).toBe(1);

    const recovered = recordAutomaticProbeSuccess(
      held,
      probing.providerProbeFingerprint!,
      "2026-08-04T12:05:01.000Z",
    );
    expect(
      planBatch(
        manifest(...targets),
        emptyIndex,
        recovered,
        "2026-08-04T12:05:01.000Z",
        "3",
      ).targets.map(({ target: value }) => value.repository_id),
    ).toEqual([41, 42, 43]);
  });

  test("a legacy repository-probe failure requests one immediate direct probe", () => {
    const value = target(41, 1);
    const failure = {
      code: "MODEL_PROVIDER",
      domain: "shared" as const,
      component: "contextual-model" as const,
    };
    const held = recordFailure(queued(value), {
      target: value,
      failure,
      at: now,
    }).state;
    const legacy = {
      ...held,
      scan_queue: {
        ...held.scan_queue,
        entries: held.scan_queue.entries.map((entry) => ({
          ...entry,
          consecutive_failures: 1,
          total_failures: 1,
          not_before: "2026-08-04T12:05:00.000Z",
          last_failure: failure,
          last_failed_at: now,
          failure_history: [
            {
              failed_at: now,
              failure,
              error_fingerprint: held.automatic_holds[0]!.error_fingerprint,
            },
          ],
        })),
      },
    };

    expect(
      planBatch(
        manifest(value),
        emptyIndex,
        legacy,
        "2026-08-04T12:01:00.000Z",
        "3",
      ),
    ).toMatchObject({
      targets: [],
      recoveryProbes: 1,
      providerProbeFingerprint: held.automatic_holds[0]!.error_fingerprint,
      nextWakeAt: null,
    });
  });

  test("an explicit operator probe bypasses only the automatic hold timer", () => {
    const value = target(41, 1);
    const held = recordFailure(queued(value), {
      target: value,
      failure: {
        code: "MODEL_PROVIDER",
        domain: "shared",
        component: "contextual-model",
      },
      at: now,
    }).state;

    expect(
      planBatch(
        manifest(value),
        emptyIndex,
        held,
        "2026-08-04T12:01:00.000Z",
        "3",
        "1",
        true,
      ),
    ).toMatchObject({
      targets: [],
      recoveryProbes: 1,
      providerProbeFingerprint: held.automatic_holds[0]!.error_fingerprint,
      nextWakeAt: null,
    });
  });

  test("a cooled automatic rescan cannot become a recovery probe before its deadline", () => {
    const cooled = target(41, 1);
    const failing = target(42, 2);
    const base = queued(cooled, failing);
    const cooling = {
      ...base,
      scan_queue: {
        ...base.scan_queue,
        entries: base.scan_queue.entries.map((entry) =>
          entry.repository_id === cooled.repository_id
            ? {
                ...entry,
                rescan_not_before: "2026-08-04T13:00:00.000Z",
              }
            : entry,
        ),
      },
    };
    const held = recordFailure(cooling, {
      target: failing,
      failure: {
        code: "MODEL_PROVIDER",
        domain: "shared",
        component: "contextual-model",
      },
      at: now,
    }).state;

    expect(
      dueRetries(held, "2026-08-04T12:05:00.000Z").map(
        ({ repository_id }) => repository_id,
      ),
    ).toEqual([]);
  });

  test("only an explicit staff emergency stop blocks planning", () => {
    const value = target(41, 1);
    const state = pauseSystem(queued(value), {
      kind: "staff",
      reasonCode: "STAFF_PAUSE",
      at: now,
    });
    const plan = planBatch(manifest(value), emptyIndex, state, now, "3");

    expect(plan.targets).toEqual([]);
    expect(plan).toMatchObject({
      totalRemaining: 1,
      runnableRemaining: 0,
      emergencyStopped: true,
    });
  });

  test("a matching policy canary gate runs one staff target and holds ordinary work", () => {
    const first = target(41, 1);
    const canary = target(42, 2);
    const secondCanary = target(43, 3);
    const base = queued(first, canary, secondCanary);
    const state = pauseSystem(
      {
        ...base,
        scan_queue: {
          ...base.scan_queue,
          entries: base.scan_queue.entries.map((entry) =>
            entry.repository_id === 42 || entry.repository_id === 43
              ? { ...entry, staff_requested: true as const }
              : entry,
          ),
        },
      },
      {
        kind: "staff",
        reasonCode: "POLICY_V4_CANARY_GATE",
        at: now,
      },
    );

    const plan = planBatch(
      manifest(first, canary, secondCanary),
      emptyIndex,
      state,
      now,
      "4",
    );

    expect(
      plan.targets.map(({ target: value }) => value.repository_id),
    ).toEqual([42]);
    expect(plan).toMatchObject({
      totalRemaining: 1,
      runnableRemaining: 1,
      emergencyStopped: true,
    });
  });

  test("fails closed when planning sees an unsynchronized target SHA", () => {
    const queuedTarget = target(41, 1);
    const changed = { ...queuedTarget, target_sha: "b".repeat(40) };

    expect(() =>
      planBatch(manifest(changed), emptyIndex, queued(queuedTarget), now, "3"),
    ).toThrow("not synchronized");
  });
});
