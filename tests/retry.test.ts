import { describe, expect, test } from "vitest";

import type { Target } from "../src/contracts/targets.js";
import { failureFingerprint } from "../src/operations/failure.js";
import {
  initialOperationsState,
  pauseSystem,
} from "../src/operations/state.js";
import {
  dueRetries,
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

function queuedState() {
  return appendQueuedTarget(
    initialOperationsState("2026-08-03T23:00:00.000Z"),
    target,
  );
}

describe("automatic scan recovery", () => {
  test("every failure rotates the target while systemic failures add automatic backoff", () => {
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
      expect(failed.entry).toMatchObject({
        ticket: 2,
        consecutive_failures: 1,
      });
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

  test("the fifth failure is chronic but remains nonterminal and retryable", () => {
    let state = queuedState();
    for (let attempt = 1; attempt <= 5; attempt += 1) {
      const failed = recordFailure(state, {
        target,
        failure: {
          code: "SCANNER_FAILED",
          domain: "target",
          component: "opengrep",
        },
        at: new Date(Date.UTC(2026, 7, 4, attempt)).toISOString(),
      });
      state = failed.state;
      expect(failed.terminal).toBe(false);
      expect(failed.notification).toBe(attempt === 5 ? "chronic" : "none");
    }

    expect(state.scan_queue.entries[0]).toMatchObject({
      consecutive_failures: 5,
      chronic: true,
      ticket: 6,
      not_before: "2026-08-04T11:00:00.000Z",
    });
  });

  test("cooldowns use the latest failure and cap at six hours", () => {
    let state = queuedState();
    const nextRetries: Array<string | null> = [];
    for (let attempt = 0; attempt < 5; attempt += 1) {
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
      "2026-08-04T00:05:00.000Z",
      "2026-08-04T01:30:00.000Z",
      "2026-08-04T04:00:00.000Z",
      "2026-08-04T09:00:00.000Z",
      "2026-08-04T10:00:00.000Z",
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
    ).toEqual([42]);
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

  test("only a matching recovery probe clears an automatic hold", () => {
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
    state = recordSuccess(
      state,
      target,
      "2026-08-04T00:05:01.000Z",
      failureFingerprint(failure),
    );

    expect(state.automatic_holds).toEqual([]);
    expect(state.scan_queue.entries).toEqual([]);
  });

  test("a failed probe cannot clear a circuit it did not prove recovered", () => {
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
    const failedProbe = recordFailure(held, {
      target,
      failure: {
        code: "SCANNER_FAILED",
        domain: "target",
        component: "opengrep",
      },
      at: "2026-08-04T00:05:01.000Z",
      recoveryFingerprint: failureFingerprint(sharedFailure),
    }).state;

    expect(failedProbe.automatic_holds).toEqual(held.automatic_holds);
  });

  test("a different systemic probe failure cools both automatic circuits", () => {
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
    const failedProbe = recordFailure(held, {
      target,
      failure: {
        code: "MODEL_AUTHENTICATION",
        domain: "security",
        component: "contextual-model",
      },
      at: "2026-08-04T00:05:01.000Z",
      recoveryFingerprint: failureFingerprint(providerFailure),
    }).state;

    expect(failedProbe.automatic_holds).toHaveLength(2);
    expect(
      failedProbe.automatic_holds.map(({ next_probe_at }) => next_probe_at),
    ).toEqual(["2026-08-04T00:10:01.000Z", "2026-08-04T00:10:01.000Z"]);
  });
});
