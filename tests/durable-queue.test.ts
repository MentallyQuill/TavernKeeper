import { describe, expect, test } from "vitest";

import type { Target } from "../src/contracts/targets.js";
import { failureFingerprint } from "../src/operations/failure.js";
import { initialOperationsState } from "../src/operations/state.js";
import {
  addBackUnscannableTarget,
  appendQueuedTarget,
  dueQueueEntries,
  prioritizeQueuedTargetRetry,
  removeSuccessfulTarget,
  revokeQueuedTargetStaffRequest,
  replaceQueuedTargetSha,
  rotateFailedTarget,
} from "../src/queue/durable-queue.js";

const at = "2026-08-04T00:00:00.000Z";

function target(repositoryId: number, shaDigit = "a"): Target {
  return {
    source_id: `github-${repositoryId}`,
    provider: "github",
    repository_id: repositoryId,
    repository: `owner/repo-${repositoryId}`,
    target_sha: shaDigit.repeat(40),
    canonical_url: `https://github.com/owner/repo-${repositoryId}`,
  };
}

const failure = {
  code: "SCANNER_FAILED",
  domain: "target" as const,
  component: "opengrep" as const,
};

describe("durable scan ticket operations", () => {
  test("uses the current policy for campaign cooldown bypass by default", () => {
    let state = appendQueuedTarget(initialOperationsState(at), target(42));
    state = {
      ...state,
      policy_campaigns: [
        {
          id: "policy-5-canary",
          scanner_policy_version: "5",
          repository_ids: [42],
          created_at: at,
          status: "active",
        },
      ],
      scan_queue: {
        ...state.scan_queue,
        entries: state.scan_queue.entries.map((entry) => ({
          ...entry,
          rescan_not_before: "2026-08-06T00:00:00.000Z",
        })),
      },
    };

    expect(
      dueQueueEntries(state, at).map(({ repository_id }) => repository_id),
    ).toEqual([42]);
  });

  test("appends targets after every ticket already assigned", () => {
    let state = initialOperationsState(at);
    state = appendQueuedTarget(state, target(42));
    state = appendQueuedTarget(state, target(43));

    expect(state.scan_queue).toMatchObject({
      next_ticket: 3,
      entries: [
        { repository_id: 42, ticket: 1 },
        { repository_id: 43, ticket: 2 },
      ],
    });
  });

  test("selects the lowest due tickets while preserving cooling positions", () => {
    let state = initialOperationsState(at);
    state = appendQueuedTarget(state, target(42));
    state = appendQueuedTarget(state, target(43));
    state = appendQueuedTarget(state, target(44));
    state = {
      ...state,
      scan_queue: {
        ...state.scan_queue,
        entries: state.scan_queue.entries.map((entry) =>
          entry.repository_id === 42
            ? {
                ...entry,
                consecutive_failures: 1,
                total_failures: 1,
                not_before: "2026-08-04T01:00:00.000Z",
                last_failure: failure,
                last_failed_at: at,
              }
            : entry,
        ),
      },
    };

    expect(
      dueQueueEntries(state, "2026-08-04T00:30:00.000Z").map(
        ({ repository_id }) => repository_id,
      ),
    ).toEqual([43, 44]);
    expect(
      dueQueueEntries(state, "2026-08-04T01:00:00.000Z").map(
        ({ repository_id }) => repository_id,
      ),
    ).toEqual([42, 43, 44]);
  });

  test("marks an exact staff retry runnable and priority without resetting history", () => {
    let state = appendQueuedTarget(initialOperationsState(at), target(42));
    state = rotateFailedTarget(state, {
      target: target(42),
      failure,
      at,
    }).state;

    const retried = prioritizeQueuedTargetRetry(state, 42);

    expect(retried.scan_queue.entries[0]).toMatchObject({
      repository_id: 42,
      consecutive_failures: 1,
      total_failures: 1,
      not_before: null,
      staff_requested: true,
    });
    expect(() => prioritizeQueuedTargetRetry(state, 404)).toThrow(
      /not queued/iu,
    );
  });

  test("revokes only future staff eligibility and is idempotent", () => {
    let state = appendQueuedTarget(initialOperationsState(at), target(42));
    state = rotateFailedTarget(state, {
      target: target(42),
      failure,
      at,
    }).state;
    state = prioritizeQueuedTargetRetry(state, 42);

    const revoked = revokeQueuedTargetStaffRequest(state, 42);

    expect(revoked.scan_queue.entries[0]).toMatchObject({
      repository_id: 42,
      ticket: 2,
      consecutive_failures: 1,
      total_failures: 1,
      not_before: null,
      last_failure: failure,
    });
    expect(revoked.scan_queue.entries[0]).not.toHaveProperty("staff_requested");
    expect(revokeQueuedTargetStaffRequest(revoked, 42)).toStrictEqual(revoked);
    expect(() => revokeQueuedTargetStaffRequest(state, 404)).toThrow(
      /not queued/iu,
    );
  });

  test("adds back exactly one unscannable repository", () => {
    let state = initialOperationsState(at);
    for (const repositoryId of [42, 43]) {
      state = appendQueuedTarget(state, target(repositoryId));
      for (const failedAt of [
        "2026-08-04T00:00:00.000Z",
        "2026-08-04T00:01:00.000Z",
        "2026-08-11T00:01:00.000Z",
      ])
        state = rotateFailedTarget(state, {
          target: target(repositoryId),
          failure,
          at: failedAt,
        }).state;
    }

    const addedBack = addBackUnscannableTarget(state, 42);

    expect(
      addedBack.unscannable_targets.map(({ repository_id }) => repository_id),
    ).toEqual([43]);
    expect(() => addBackUnscannableTarget(addedBack, 42)).toThrow(
      /not unscannable/iu,
    );
  });

  test("moves each failure exactly once to the current tail", () => {
    let state = initialOperationsState(at);
    state = appendQueuedTarget(state, target(42));
    state = appendQueuedTarget(state, target(43));

    const failed = rotateFailedTarget(state, {
      target: target(42),
      failure,
      at,
    });

    expect(failed.entry).toMatchObject({
      repository_id: 42,
      ticket: 3,
      consecutive_failures: 1,
      total_failures: 1,
      chronic: false,
    });
    expect(failed.state.scan_queue.next_ticket).toBe(4);
    expect(failed.becameChronic).toBe(false);
  });

  test("retains new-catalog provenance when a failed target rotates", () => {
    let state = appendQueuedTarget(initialOperationsState(at), target(42), {
      catalogChange: "new",
    });
    state = rotateFailedTarget(state, {
      target: target(42),
      failure,
      at,
    }).state;

    expect(state.scan_queue.entries[0]).toMatchObject({
      catalog_change: "new",
      consecutive_failures: 1,
    });
  });

  test("allows one immediate retry, cools for seven days, then terminates", () => {
    let state = appendQueuedTarget(initialOperationsState(at), target(42));
    const first = rotateFailedTarget(state, {
      target: target(42),
      failure,
      at: "2026-08-04T01:00:00.000Z",
    });
    expect(first).toMatchObject({ terminal: false, becameChronic: false });
    expect(first.entry).toMatchObject({
      ticket: 2,
      consecutive_failures: 1,
      not_before: null,
      chronic: false,
    });

    const second = rotateFailedTarget(first.state, {
      target: target(42),
      failure,
      at: "2026-08-04T02:00:00.000Z",
    });
    expect(second).toMatchObject({ terminal: false, becameChronic: true });
    expect(second.entry).toMatchObject({
      ticket: 3,
      consecutive_failures: 2,
      not_before: "2026-08-11T02:00:00.000Z",
      chronic: true,
    });

    const third = rotateFailedTarget(second.state, {
      target: target(42),
      failure,
      at: "2026-08-11T02:00:00.000Z",
    });
    expect(third).toMatchObject({ terminal: true, becameChronic: false });
    expect(third.state.scan_queue.entries).toEqual([]);
    expect(third.state.active_scans).toEqual([]);
    expect(third.state.unscannable_targets).toEqual([
      expect.objectContaining({
        repository_id: 42,
        consecutive_failures: 3,
        total_failures: 3,
        unscannable_at: "2026-08-11T02:00:00.000Z",
      }),
    ]);
    expect(() => appendQueuedTarget(third.state, target(42, "b"))).toThrow(
      /unscannable/iu,
    );
  });

  test("retains sanitized failure history in the terminal tombstone", () => {
    let state = appendQueuedTarget(initialOperationsState(at), target(42));
    const diagnostics = [
      "parser_syntax",
      "rule_timeout",
      "parser_syntax",
    ] as const;
    for (const [index, diagnostic] of diagnostics.entries()) {
      state = rotateFailedTarget(state, {
        target: target(42),
        failure: { ...failure, diagnostic },
        at: new Date(Date.UTC(2026, 7, 4, index + 1)).toISOString(),
      }).state;
    }

    const history = state.unscannable_targets[0]?.failure_history;
    expect(history).toHaveLength(3);
    expect(history?.map((entry) => entry.failure.diagnostic)).toEqual(
      diagnostics,
    );
    expect(
      history?.every(
        (entry) =>
          entry.error_fingerprint === failureFingerprint(entry.failure),
      ),
    ).toBe(true);
    expect(JSON.stringify(history)).not.toContain("private/source.ts");
  });

  test("replacing a SHA preserves its repository failure episode", () => {
    let state = appendQueuedTarget(initialOperationsState(at), target(42));
    state = rotateFailedTarget(state, {
      target: target(42),
      failure,
      at,
    }).state;
    state = rotateFailedTarget(state, {
      target: target(42),
      failure,
      at: "2026-08-04T00:01:00.000Z",
    }).state;
    const before = state.scan_queue.entries[0]!;

    const replaced = replaceQueuedTargetSha(
      state,
      target(42, "b"),
      "2026-08-04T00:02:00.000Z",
    );

    expect(replaced.scan_queue.entries[0]).toMatchObject({
      target_sha: "b".repeat(40),
      ticket: before.ticket,
      consecutive_failures: 2,
      total_failures: 2,
      not_before: "2026-08-11T00:01:00.000Z",
      last_failure: failure,
      last_failed_at: "2026-08-04T00:01:00.000Z",
      chronic: true,
      failure_history: before.failure_history,
    });
  });

  test("replacing a SHA preserves updated-catalog provenance and queue history", () => {
    let state = appendQueuedTarget(initialOperationsState(at), target(42), {
      catalogChange: "updated",
    });
    state = rotateFailedTarget(state, {
      target: target(42),
      failure,
      at,
    }).state;

    const replaced = replaceQueuedTargetSha(
      state,
      target(42, "b"),
      "2026-08-04T00:01:00.000Z",
    );

    expect(replaced.scan_queue.entries[0]).toMatchObject({
      target_sha: "b".repeat(40),
      catalog_change: "updated",
      ticket: 2,
      total_failures: 1,
    });
  });

  test("adds missing same-SHA provenance without clearing its cooldown", () => {
    let state = appendQueuedTarget(initialOperationsState(at), target(42));
    state = {
      ...state,
      scan_queue: {
        ...state.scan_queue,
        entries: state.scan_queue.entries.map((entry) => ({
          ...entry,
          rescan_not_before: "2026-08-06T00:00:00.000Z",
        })),
      },
    };

    const enriched = appendQueuedTarget(state, target(42), {
      catalogChange: "updated",
    });

    expect(enriched.scan_queue.entries[0]).toMatchObject({
      catalog_change: "updated",
      rescan_not_before: "2026-08-06T00:00:00.000Z",
    });
  });

  test("success removes only the exact immutable target", () => {
    let state = appendQueuedTarget(initialOperationsState(at), target(42));
    state = appendQueuedTarget(state, target(43));

    expect(
      removeSuccessfulTarget(state, target(42, "b"), at).scan_queue.entries,
    ).toHaveLength(2);
    expect(
      removeSuccessfulTarget(state, target(42), at).scan_queue.entries.map(
        ({ repository_id }) => repository_id,
      ),
    ).toEqual([43]);
  });
});
