import { describe, expect, test } from "vitest";

import type { Target } from "../src/contracts/targets.js";
import {
  initialOperationsState,
  pauseSystem,
  resumeSystem,
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

function anotherTarget(repositoryId = 43): Target {
  return {
    source_id: `github-${repositoryId}`,
    provider: "github",
    repository_id: repositoryId,
    repository: `owner/repo-${repositoryId}`,
    target_sha: String(repositoryId % 10).repeat(40),
    canonical_url: `https://github.com/owner/repo-${repositoryId}`,
  };
}

function runningState() {
  return resumeSystem(
    initialOperationsState("2026-08-03T23:00:00.000Z"),
    "2026-08-03T23:01:00.000Z",
  );
}

describe("automatic scan recovery", () => {
  test("a failure clears the matching active scan", () => {
    const at = "2026-08-04T00:00:00.000Z";
    const active = {
      ...runningState(),
      active_scans: [
        {
          source_id: target.source_id,
          repository_id: target.repository_id,
          target_sha: target.target_sha,
          started_at: at,
          run_id: "run-42",
        },
      ],
    };

    const failed = recordFailure(active, {
      target,
      failure: {
        code: "SCANNER_FAILED",
        domain: "target",
        component: "opengrep",
      },
      at,
    });

    expect(failed.state.active_scans).toEqual([]);
  });

  test("exhausting one target never creates a shared hold", () => {
    let state = runningState();
    for (const at of [
      "2026-08-04T00:00:00.000Z",
      "2026-08-04T00:05:00.000Z",
      "2026-08-04T00:30:00.000Z",
      "2026-08-04T02:00:00.000Z",
    ])
      state = recordFailure(state, {
        target,
        failure: {
          code: "SCANNER_FAILED",
          domain: "target",
          component: "opengrep",
        },
        at,
      }).state;

    expect(state.target_retries[0]).toMatchObject({
      attempt: 4,
      exhausted: true,
      next_retry_at: null,
    });
    expect(state.shared_holds).toEqual([]);
    expect(state.pause).toBeNull();
  });

  test("exhausts an exact SHA after four alternating target failures", () => {
    let state = runningState();
    const failures = [
      { code: "SCANNER_FAILED", component: "opengrep" },
      { code: "SCANNER_TIMEOUT", component: "opengrep" },
      { code: "SCANNER_FAILED", component: "gitleaks" },
      { code: "SCANNER_TIMEOUT", component: "gitleaks" },
    ] as const;
    failures.forEach((failure, index) => {
      state = recordFailure(state, {
        target,
        failure: { ...failure, domain: "target" },
        at: new Date(Date.UTC(2026, 7, 4, index)).toISOString(),
      }).state;
    });

    expect(state.target_retries[0]).toMatchObject({
      attempt: 4,
      exhausted: true,
      next_retry_at: null,
      failure: failures.at(-1),
    });
  });

  test("uses five-minute, thirty-minute, and two-hour target delays", () => {
    let state = runningState();
    const nextRetries: Array<string | null> = [];
    for (const at of [
      "2026-08-04T00:00:00.000Z",
      "2026-08-04T00:05:30.000Z",
      "2026-08-04T00:30:30.000Z",
    ]) {
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
      nextRetries.push(result.entry.next_retry_at);
    }

    expect(nextRetries).toEqual([
      "2026-08-04T00:05:00.000Z",
      "2026-08-04T00:30:00.000Z",
      "2026-08-04T02:00:00.000Z",
    ]);
  });

  test("shared failures keep probing after the notification threshold", () => {
    let state = runningState();
    for (let index = 0; index < 7; index += 1)
      state = recordFailure(state, {
        target,
        failure: {
          code: "MODEL_PROVIDER",
          domain: "shared",
          component: "contextual-model",
        },
        at: new Date(Date.UTC(2026, 7, 4, index)).toISOString(),
      }).state;

    expect(state.shared_holds[0]).toMatchObject({
      consecutive_failures: 7,
      notified: true,
      next_probe_at: "2026-08-04T09:00:00.000Z",
    });
    expect(state.target_retries[0]).toMatchObject({
      attempt: 4,
      exhausted: false,
    });
    expect(state.pause).toBeNull();
  });

  test("the first successful probe clears its hold even with other references", () => {
    const at = "2026-08-04T00:00:00.000Z";
    const first = recordFailure(runningState(), {
      target,
      failure: {
        code: "MODEL_PROVIDER",
        domain: "shared",
        component: "contextual-model",
      },
      at,
    });
    const secondTarget = anotherTarget();
    const second = recordFailure(first.state, {
      target: secondTarget,
      failure: first.entry.failure,
      at,
    });

    const recovered = recordSuccess(
      second.state,
      target,
      "2026-08-04T00:05:01.000Z",
    );

    expect(recovered.shared_holds).toEqual([]);
    expect(recovered.target_retries).toEqual([
      expect.objectContaining({ repository_id: secondTarget.repository_id }),
    ]);
  });

  test("a changed failure fingerprint prunes only an orphaned shared hold", () => {
    const at = "2026-08-04T00:00:00.000Z";
    const sharedFailure = {
      code: "MODEL_PROVIDER",
      domain: "shared" as const,
      component: "contextual-model" as const,
    };
    const first = recordFailure(runningState(), {
      target,
      failure: sharedFailure,
      at,
    });
    const secondTarget = anotherTarget();
    const second = recordFailure(first.state, {
      target: secondTarget,
      failure: sharedFailure,
      at,
    });
    const changed = recordFailure(second.state, {
      target,
      failure: {
        code: "SCANNER_FAILED",
        domain: "target",
        component: "opengrep",
      },
      at: "2026-08-04T00:01:00.000Z",
    });

    expect(changed.state.shared_holds).toHaveLength(1);

    const changedLastReference = recordFailure(changed.state, {
      target: secondTarget,
      failure: {
        code: "SCANNER_FAILED",
        domain: "target",
        component: "gitleaks",
      },
      at: "2026-08-04T00:02:00.000Z",
    });
    expect(changedLastReference.state.shared_holds).toEqual([]);
  });

  test("security failures persist a staff-visible security pause", () => {
    const failed = recordFailure(runningState(), {
      target,
      failure: {
        code: "MODEL_AUTHENTICATION",
        domain: "security",
        component: "contextual-model",
      },
      at: "2026-08-04T00:00:00.000Z",
    });

    expect(failed).toMatchObject({ notification: "staff", terminal: true });
    expect(failed.state.pause).toMatchObject({
      kind: "system",
      reason_code: "SECURITY_HOLD",
    });
    expect(dueRetries(failed.state, "2026-08-05T00:00:00.000Z")).toEqual([]);
  });

  test("shared holds admit one due probe per fingerprint", () => {
    const at = "2026-08-04T00:00:00.000Z";
    const first = recordFailure(runningState(), {
      target,
      failure: {
        code: "MODEL_PROVIDER",
        domain: "shared",
        component: "contextual-model",
      },
      at,
    });
    const second = recordFailure(first.state, {
      target: anotherTarget(),
      failure: first.entry.failure,
      at,
    });

    expect(dueRetries(second.state, "2026-08-04T00:04:59.999Z")).toEqual([]);
    expect(
      dueRetries(second.state, "2026-08-04T00:05:00.000Z").map(
        ({ repository_id }) => repository_id,
      ),
    ).toEqual([42]);

    const paused = pauseSystem(second.state, {
      kind: "staff",
      reasonCode: "STAFF_PAUSE",
      at: "2026-08-04T00:05:01.000Z",
    });
    expect(dueRetries(paused, "2026-08-04T01:00:00.000Z")).toEqual([]);
  });
});
