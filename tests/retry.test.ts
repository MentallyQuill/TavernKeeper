import { describe, expect, test } from "vitest";

import type { Target } from "../src/contracts/targets.js";
import {
  initialOperationsState,
  pauseSystem,
} from "../src/operations/state.js";
import {
  dueRetries,
  recordFailure,
  recordSuccess,
} from "../src/operations/retry.js";

const target: Target = {
  source_id: "github-42",
  provider: "github",
  repository_id: 42,
  repository: "owner/repo",
  target_sha: "a".repeat(40),
  canonical_url: "https://github.com/owner/repo",
};

describe("scan retry schedule", () => {
  test("a failure clears the matching active scan before scheduling retry", () => {
    const initial = "2026-07-31T12:00:00.000Z";
    const active = {
      ...initialOperationsState(initial),
      active_scans: [
        {
          source_id: target.source_id,
          repository_id: target.repository_id,
          target_sha: target.target_sha,
          started_at: initial,
          run_id: "run-42",
        },
      ],
    };

    const failed = recordFailure(active, {
      target,
      code: "MODEL_QUOTA",
      scope: "system",
      at: initial,
    });

    expect(failed.state.active_scans).toEqual([]);
  });

  test("keeps provider outage retries at one, two, and three hours", () => {
    const initial = "2026-07-31T12:00:00.000Z";
    const first = recordFailure(initialOperationsState(initial), {
      target,
      code: "MODEL_QUOTA",
      scope: "system",
      at: initial,
    });

    expect(first.notification).toBe("none");
    expect(first.entry).toMatchObject({
      attempt: 1,
      next_retry_at: "2026-07-31T13:00:00.000Z",
      exhausted: false,
    });
    expect(dueRetries(first.state, "2026-07-31T12:59:59.999Z")).toEqual([]);
    expect(
      dueRetries(first.state, "2026-07-31T13:00:00.000Z").map(
        ({ attempt }) => attempt,
      ),
    ).toEqual([1]);

    const second = recordFailure(first.state, {
      target,
      code: "MODEL_QUOTA",
      scope: "system",
      at: "2026-07-31T13:05:00.000Z",
    });
    expect(second.entry).toMatchObject({
      attempt: 2,
      next_retry_at: "2026-07-31T14:00:00.000Z",
    });
    expect(
      dueRetries(second.state, "2026-07-31T14:00:00.000Z").map(
        ({ attempt }) => attempt,
      ),
    ).toEqual([2]);

    const recovered = recordSuccess(
      second.state,
      target,
      "2026-07-31T14:01:00.000Z",
    );
    expect(recovered.retries).toEqual([]);
    expect(recovered.circuit_breaker).toBeNull();
  });

  test.each([
    "MODEL_INVALID_RESPONSE",
    "MODEL_CONTEXT_INCOMPLETE",
    "MODEL_EVIDENCE_INVALID",
  ])("retries repository model reply failure %s every five minutes", (code) => {
    const initial = "2026-07-31T12:00:00.000Z";
    const first = recordFailure(initialOperationsState(initial), {
      target,
      code,
      scope: "repository",
      at: initial,
    });

    expect(first.entry).toMatchObject({
      attempt: 1,
      next_retry_at: "2026-07-31T12:05:00.000Z",
      exhausted: false,
    });
    expect(dueRetries(first.state, "2026-07-31T12:04:59.999Z")).toEqual([]);
    expect(
      dueRetries(first.state, "2026-07-31T12:05:00.000Z").map(
        ({ attempt }) => attempt,
      ),
    ).toEqual([1]);

    const second = recordFailure(first.state, {
      target,
      code,
      scope: "repository",
      at: "2026-07-31T12:05:30.000Z",
    });
    expect(second.entry.next_retry_at).toBe("2026-07-31T12:10:00.000Z");

    const third = recordFailure(second.state, {
      target,
      code,
      scope: "repository",
      at: "2026-07-31T12:10:30.000Z",
    });
    expect(third.entry.next_retry_at).toBe("2026-07-31T12:15:00.000Z");
  });

  test.each([
    ["MODEL_INVALID_RESPONSE", "system"],
    ["REPOSITORY_PARSE_FAILED", "repository"],
  ] as const)(
    "keeps non-reply failure %s with %s scope on the hourly schedule",
    (code, scope) => {
      const initial = "2026-07-31T12:00:00.000Z";
      const failed = recordFailure(initialOperationsState(initial), {
        target,
        code,
        scope,
        at: initial,
      });

      expect(failed.entry.next_retry_at).toBe("2026-07-31T13:00:00.000Z");
      expect(dueRetries(failed.state, "2026-07-31T12:59:59.999Z")).toEqual([]);
    },
  );

  test("notifies staff only after the third scheduled retry also fails", () => {
    const initial = "2026-07-31T12:00:00.000Z";
    const first = recordFailure(initialOperationsState(initial), {
      target,
      code: "MODEL_AUTHENTICATION",
      scope: "system",
      at: initial,
    });
    const second = recordFailure(first.state, {
      target,
      code: "MODEL_AUTHENTICATION",
      scope: "system",
      at: "2026-07-31T13:00:00.000Z",
    });
    const third = recordFailure(second.state, {
      target,
      code: "MODEL_AUTHENTICATION",
      scope: "system",
      at: "2026-07-31T14:00:00.000Z",
    });
    const exhausted = recordFailure(third.state, {
      target,
      code: "MODEL_AUTHENTICATION",
      scope: "system",
      at: "2026-07-31T15:00:00.000Z",
    });

    expect([
      first.notification,
      second.notification,
      third.notification,
      exhausted.notification,
    ]).toEqual(["none", "none", "none", "staff"]);
    expect(exhausted).toMatchObject({
      terminal: true,
      entry: { attempt: 3, next_retry_at: null, exhausted: true },
      state: { circuit_breaker: { terminal: true } },
    });
    expect(dueRetries(exhausted.state, "2026-07-31T16:00:00.000Z")).toEqual([]);
  });

  test("a system breaker permits only its recovery retry and a staff pause permits none", () => {
    const initial = "2026-07-31T12:00:00.000Z";
    const system = recordFailure(initialOperationsState(initial), {
      target,
      code: "MODEL_QUOTA",
      scope: "system",
      at: initial,
    }).state;
    const repositoryTarget: Target = {
      source_id: "github-43",
      provider: "github",
      repository_id: 43,
      repository: "owner/repo-43",
      target_sha: "b".repeat(40),
      canonical_url: "https://github.com/owner/repo-43",
    };
    const withRepositoryFailure = recordFailure(system, {
      target: repositoryTarget,
      code: "REPOSITORY_PARSE_FAILED",
      scope: "repository",
      at: initial,
    }).state;

    expect(
      dueRetries(withRepositoryFailure, "2026-07-31T13:00:00.000Z").map(
        ({ repository_id }) => repository_id,
      ),
    ).toEqual([42]);

    const paused = pauseSystem(withRepositoryFailure, {
      kind: "staff",
      reasonCode: "STAFF_PAUSE",
      at: "2026-07-31T12:30:00.000Z",
    });
    expect(dueRetries(paused, "2026-07-31T13:00:00.000Z")).toEqual([]);
  });
});
