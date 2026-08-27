import { describe, expect, test } from "vitest";

import type { Target } from "../src/contracts/targets.js";
import { failureFingerprint } from "../src/operations/failure.js";
import {
  initialOperationsState,
  pauseSystem,
} from "../src/operations/state.js";
import {
  dueRetries,
  recordAutomaticProbeFailure,
  recordAutomaticProbeSuccess,
  recordFailure,
  recordSuccess,
} from "../src/operations/retry.js";
import { appendQueuedTarget } from "../src/queue/durable-queue.js";

const target: Target = {
  source_id: "github-42",
  provider: "github",
  repository_id: 42,
  repository: "owner/repo",
  target_sha: "a".repeat(40),
  canonical_url: "https://github.com/owner/repo",
};
const secondTarget: Target = {
  ...target,
  source_id: "github-43",
  repository_id: 43,
  repository: "owner/second-repo",
  target_sha: "b".repeat(40),
  canonical_url: "https://github.com/owner/second-repo",
};

function queuedState() {
  return appendQueuedTarget(
    initialOperationsState("2026-08-03T23:00:00.000Z"),
    target,
  );
}

describe("automatic scan recovery", () => {
  test("shared hold timestamps are independent of failure arrival order", () => {
    const failure = {
      code: "MODEL_PROVIDER",
      domain: "shared" as const,
      component: "contextual-model" as const,
    };
    const state = appendQueuedTarget(queuedState(), secondTarget);
    const newestFirst = recordFailure(state, {
      target: secondTarget,
      failure,
      at: "2026-08-04T00:00:30.000Z",
    }).state;

    const repeated = recordFailure(newestFirst, {
      target,
      failure,
      at: "2026-08-04T00:00:10.000Z",
    }).state;

    expect(repeated.automatic_holds).toEqual([
      expect.objectContaining({
        first_failed_at: "2026-08-04T00:00:10.000Z",
        last_failed_at: "2026-08-04T00:00:30.000Z",
        consecutive_failures: 2,
        next_probe_at: "2026-08-04T00:30:30.000Z",
      }),
    ]);
  });

  test("only target failures rotate target retry state", () => {
    for (const domain of ["target", "shared", "security"] as const) {
      const failed = recordFailure(queuedState(), {
        target,
        failure: {
          code:
            domain === "security"
              ? "MODEL_AUTHENTICATION"
              : domain === "shared"
                ? "MODEL_PROVIDER"
                : "SCANNER_FAILED",
          domain,
          component: domain === "target" ? "opengrep" : "contextual-model",
        },
        at: "2026-08-04T00:00:00.000Z",
      });

      expect(failed).toMatchObject({ notification: "none", terminal: false });
      expect(failed.state.emergency_stop).toBeNull();
      expect(failed.entry).toMatchObject(
        domain === "target"
          ? { ticket: 2, consecutive_failures: 1 }
          : {
              ticket: 1,
              consecutive_failures: 0,
              total_failures: 0,
              last_failure: null,
              not_before: null,
            },
      );
      expect(failed.state.automatic_holds).toEqual(
        domain === "target"
          ? []
          : [
              expect.objectContaining({
                failure: expect.objectContaining({ domain }),
                consecutive_failures: 1,
                next_probe_at: "2026-08-04T00:05:00.000Z",
                chronic: false,
              }),
            ],
      );
    }
  });

  test("the second target failure cools and the third becomes unscannable", () => {
    let state = queuedState();
    const transitions = [];
    for (let attempt = 1; attempt <= 3; attempt += 1) {
      const failed = recordFailure(state, {
        target,
        failure: {
          code: "SCANNER_FAILED",
          domain: "target",
          component: "opengrep",
        },
        at:
          attempt < 3
            ? new Date(Date.UTC(2026, 7, 4, attempt)).toISOString()
            : "2026-08-11T02:00:00.000Z",
      });
      state = failed.state;
      transitions.push({
        terminal: failed.terminal,
        notification: failed.notification,
        notBefore: failed.entry.not_before,
      });
    }

    expect(transitions).toEqual([
      { terminal: false, notification: "none", notBefore: null },
      {
        terminal: false,
        notification: "chronic",
        notBefore: "2026-08-11T02:00:00.000Z",
      },
      { terminal: true, notification: "unscannable", notBefore: null },
    ]);
    expect(state.scan_queue.entries).toEqual([]);
    expect(state.unscannable_targets).toEqual([
      expect.objectContaining({ repository_id: 42, consecutive_failures: 3 }),
    ]);
  });

  test("target retries are immediate once and then cool for exactly seven days", () => {
    let state = queuedState();
    const nextRetries: Array<string | null> = [];
    for (let attempt = 0; attempt < 2; attempt += 1) {
      const at = new Date(Date.UTC(2026, 7, 4, attempt)).toISOString();
      const result = recordFailure(state, {
        target,
        failure: {
          code: "MODEL_INVALID_RESPONSE",
          domain: "target",
          component: "contextual-model",
        },
        at,
      });
      state = result.state;
      nextRetries.push(result.entry.not_before);
    }

    expect(nextRetries).toEqual([
      null,
      "2026-08-11T01:00:00.000Z",
    ]);
  });

  test("due retries follow ticket order and honor only explicit staff stop", () => {
    const failed = recordFailure(queuedState(), {
      target,
      failure: {
        code: "MODEL_AUTHENTICATION",
        domain: "security",
        component: "contextual-model",
      },
      at: "2026-08-04T00:00:00.000Z",
    }).state;

    expect(
      dueRetries(failed, "2026-08-04T00:05:00.000Z").map(
        ({ repository_id }) => repository_id,
      ),
    ).toEqual([]);
    const stopped = pauseSystem(failed, {
      kind: "staff",
      reasonCode: "STAFF_PAUSE",
      at: "2026-08-04T00:05:01.000Z",
    });
    expect(dueRetries(stopped, "2026-08-05T00:00:00.000Z")).toEqual([]);
  });

  test("success removes only the exact target", () => {
    expect(
      recordSuccess(queuedState(), target, "2026-08-04T00:01:00.000Z")
        .scan_queue.entries,
    ).toEqual([]);
  });

  test("a direct provider success clears only its matching hold and preserves the queue", () => {
    const failure = {
      code: "MODEL_PROVIDER",
      domain: "shared" as const,
      component: "contextual-model" as const,
    };
    let state = recordFailure(queuedState(), {
      target,
      failure,
      at: "2026-08-04T00:00:00.000Z",
    }).state;
    const queueBefore = state.scan_queue;
    state = recordAutomaticProbeSuccess(
      state,
      failureFingerprint(failure),
      "2026-08-04T00:05:01.000Z",
    );

    expect(state.automatic_holds).toEqual([]);
    expect(state.scan_queue).toEqual(queueBefore);
  });

  test("a failed direct probe advances only its hold and preserves the queue", () => {
    const sharedFailure = {
      code: "MODEL_PROVIDER",
      domain: "shared" as const,
      component: "contextual-model" as const,
    };
    const held = recordFailure(queuedState(), {
      target,
      failure: sharedFailure,
      at: "2026-08-04T00:00:00.000Z",
    }).state;
    const failedProbe = recordAutomaticProbeFailure(
      held,
      failureFingerprint(sharedFailure),
      "2026-08-04T00:05:01.000Z",
    );

    expect(failedProbe.scan_queue).toEqual(held.scan_queue);
    expect(failedProbe.automatic_holds).toEqual([
      expect.objectContaining({
        consecutive_failures: 2,
        last_failed_at: "2026-08-04T00:05:01.000Z",
        next_probe_at: "2026-08-04T00:35:01.000Z",
      }),
    ]);
  });

  test("a probe transition rejects an unknown hold fingerprint", () => {
    const providerFailure = {
      code: "MODEL_PROVIDER",
      domain: "shared" as const,
      component: "contextual-model" as const,
    };
    const held = recordFailure(queuedState(), {
      target,
      failure: providerFailure,
      at: "2026-08-04T00:00:00.000Z",
    }).state;
    expect(() =>
      recordAutomaticProbeFailure(
        held,
        "f".repeat(64),
        "2026-08-04T00:05:01.000Z",
      ),
    ).toThrow(/automatic recovery hold/iu);
  });

  test("a retried failed probe transition is idempotent at the same timestamp", () => {
    const failure = {
      code: "MODEL_PROVIDER",
      domain: "shared" as const,
      component: "contextual-model" as const,
    };
    const held = recordFailure(queuedState(), {
      target,
      failure,
      at: "2026-08-04T00:00:00.000Z",
    }).state;
    const fingerprint = failureFingerprint(failure);
    const once = recordAutomaticProbeFailure(
      held,
      fingerprint,
      "2026-08-04T00:05:01.000Z",
    );

    expect(
      recordAutomaticProbeFailure(
        once,
        fingerprint,
        "2026-08-04T00:05:01.000Z",
      ),
    ).toEqual(once);
  });
});
