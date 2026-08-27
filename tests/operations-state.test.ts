import { describe, expect, test } from "vitest";

import { failureFingerprint } from "../src/operations/failure.js";
import {
  initialOperationsState,
  parseOperationsState,
  pauseSystem,
  releaseAutomaticHolds,
  resumeSystem,
  serializeOperationsState,
} from "../src/operations/state.js";

const at = "2026-08-04T00:00:00.000Z";

function entry(repositoryId: number, ticket: number) {
  return {
    source_id: `github-${repositoryId}`,
    repository_id: repositoryId,
    repository: `owner/repo-${repositoryId}`,
    target_sha: repositoryId.toString(16).padStart(40, "0"),
    ticket,
    consecutive_failures: 0,
    total_failures: 0,
    not_before: null,
    last_failure: null,
    last_failed_at: null,
    chronic: false,
  } as const;
}

const targetFailure = {
  code: "SCANNER_FAILED",
  domain: "target" as const,
  component: "opengrep" as const,
  diagnostic: "parser_syntax" as const,
};

function failedEntry(repositoryId: number, failures: number) {
  const failedAt = `2026-08-04T00:0${failures}:00.000Z`;
  return {
    ...entry(repositoryId, repositoryId),
    consecutive_failures: failures,
    total_failures: failures,
    not_before:
      failures === 1 ? null : "2026-08-11T00:02:00.000Z",
    last_failure: targetFailure,
    last_failed_at: failedAt,
    chronic: failures >= 2,
    failure_history: [
      {
        failed_at: failedAt,
        failure: targetFailure,
        error_fingerprint: failureFingerprint(targetFailure),
      },
    ],
  } as const;
}

function unscannable(repositoryId: number) {
  const failed = failedEntry(repositoryId, 3);
  return {
    source_id: failed.source_id,
    repository_id: failed.repository_id,
    repository: failed.repository,
    target_sha: failed.target_sha,
    unscannable_at: failed.last_failed_at,
    consecutive_failures: failed.consecutive_failures,
    total_failures: failed.total_failures,
    last_failure: failed.last_failure,
    last_failed_at: failed.last_failed_at,
    failure_history: failed.failure_history,
  };
}

describe("secret-free operations state V3", () => {
  test("creates a strict durable queue with bounded automatic recovery", () => {
    const state = initialOperationsState(at);

    expect(state).toMatchObject({
      schema_version: 3,
      emergency_stop: null,
      automatic_holds: [],
      unscannable_targets: [],
      scan_queue: { next_ticket: 1, entries: [] },
    });
    expect(state).not.toHaveProperty("pause");
    expect(state).not.toHaveProperty("target_retries");
    expect(state).not.toHaveProperty("shared_holds");
    expect(state).not.toHaveProperty("circuit_breaker");
  });

  test("records coverage start once across explicit staff stops", () => {
    const firstResume = "2026-08-04T12:00:00.000Z";
    const secondResume = "2026-08-05T12:00:00.000Z";
    const started = resumeSystem(initialOperationsState(at), firstResume);
    const paused = pauseSystem(started, {
      kind: "staff",
      reasonCode: "STAFF_PAUSE",
      at: "2026-08-04T13:00:00.000Z",
    });

    expect(resumeSystem(paused, secondResume).coverage_started_at).toBe(
      firstResume,
    );
  });

  test("releases automatic holds without changing staff stops or queued work", () => {
    const failure = {
      code: "MODEL_PROVIDER",
      domain: "shared" as const,
      component: "contextual-model" as const,
    };
    const held = parseOperationsState({
      ...pauseSystem(initialOperationsState(at), {
        kind: "staff",
        reasonCode: "STAFF_PAUSE",
        at,
      }),
      automatic_holds: [
        {
          error_fingerprint: failureFingerprint(failure),
          failure,
          first_failed_at: at,
          last_failed_at: at,
          consecutive_failures: 5,
          next_probe_at: "2026-08-04T06:00:00.000Z",
          chronic: true,
        },
      ],
      scan_queue: {
        next_ticket: 2,
        entries: [entry(42, 1)],
      },
    });
    const releasedAt = "2026-08-05T12:00:00.000Z";

    expect(releaseAutomaticHolds(held, releasedAt)).toEqual({
      ...held,
      updated_at: releasedAt,
      automatic_holds: [],
    });
  });

  test("leaves operational state unchanged when no automatic holds exist", () => {
    const state = initialOperationsState(at);

    expect(releaseAutomaticHolds(state, "2026-08-05T12:00:00.000Z")).toBe(
      state,
    );
  });

  test("rejects automatic system stops", () => {
    expect(() =>
      parseOperationsState({
        ...initialOperationsState(at),
        emergency_stop: {
          kind: "system",
          reason_code: "SECURITY_HOLD",
          paused_at: at,
        },
      }),
    ).toThrow();
  });

  test("serializes queue entries by ticket", () => {
    const state = parseOperationsState({
      ...initialOperationsState(at),
      scan_queue: {
        next_ticket: 4,
        entries: [entry(43, 3), entry(42, 1)],
      },
    });
    const serialized = serializeOperationsState(state);

    expect(serialized.indexOf('"ticket": 1')).toBeLessThan(
      serialized.indexOf('"ticket": 3'),
    );
    expect(serialized).not.toMatch(
      /api[_-]?key|credential|raw[_-]?error|response[_-]?body|prompt/iu,
    );
  });

  test("accepts and canonically sorts repository-level unscannable targets", () => {
    const parsed = parseOperationsState({
      ...initialOperationsState(at),
      unscannable_targets: [unscannable(43), unscannable(42)],
    });
    const serialized = JSON.parse(serializeOperationsState(parsed)) as {
      unscannable_targets: { repository_id: number }[];
    };

    expect(
      serialized.unscannable_targets.map(
        ({ repository_id }) => repository_id,
      ),
    ).toEqual([42, 43]);
  });

  test("rejects duplicate unscannable repository identities", () => {
    expect(() =>
      parseOperationsState({
        ...initialOperationsState(at),
        unscannable_targets: [unscannable(42), unscannable(42)],
      }),
    ).toThrow();
  });

  test.each(["queued", "active"])(
    "rejects an unscannable repository that is also %s",
    (overlap) => {
      const failed = unscannable(42);
      expect(() =>
        parseOperationsState({
          ...initialOperationsState(at),
          unscannable_targets: [failed],
          ...(overlap === "queued"
            ? {
                scan_queue: {
                  next_ticket: 43,
                  entries: [entry(42, 42)],
                },
              }
            : {
                active_scans: [
                  {
                    source_id: failed.source_id,
                    repository_id: failed.repository_id,
                    target_sha: failed.target_sha,
                    started_at: at,
                    run_id: "run-42",
                  },
                ],
              }),
        }),
      ).toThrow();
    },
  );

  test("normalizes pre-policy chronic flags before strict validation", () => {
    const legacy = {
      ...initialOperationsState(at),
      scan_queue: {
        next_ticket: 43,
        entries: [{ ...failedEntry(42, 2), chronic: false }],
      },
    };
    delete (legacy as { unscannable_targets?: unknown }).unscannable_targets;

    expect(parseOperationsState(legacy).scan_queue.entries[0]?.chronic).toBe(
      true,
    );
  });

  test("preserves a sorted catalog observation and queue change provenance", () => {
    const observed = parseOperationsState({
      ...initialOperationsState(at),
      catalog_observation: {
        initialized_at: at,
        repositories: [
          { repository_id: 42, target_sha: "a".repeat(40) },
          { repository_id: 43, target_sha: "b".repeat(40) },
        ],
      },
      scan_queue: {
        next_ticket: 2,
        entries: [{ ...entry(42, 1), catalog_change: "new" }],
      },
    });

    expect(serializeOperationsState(observed)).toContain(
      '"catalog_change": "new"',
    );
    expect(observed.catalog_observation).toEqual({
      initialized_at: at,
      repositories: [
        { repository_id: 42, target_sha: "a".repeat(40) },
        { repository_id: 43, target_sha: "b".repeat(40) },
      ],
    });
  });

  test.each([
    {
      name: "duplicate repository IDs",
      repositories: [
        { repository_id: 42, target_sha: "a".repeat(40) },
        { repository_id: 42, target_sha: "b".repeat(40) },
      ],
    },
    {
      name: "descending repository IDs",
      repositories: [
        { repository_id: 43, target_sha: "b".repeat(40) },
        { repository_id: 42, target_sha: "a".repeat(40) },
      ],
    },
    {
      name: "invalid target SHAs",
      repositories: [{ repository_id: 42, target_sha: "not-a-sha" }],
    },
  ])("rejects catalog observations with $name", ({ repositories }) => {
    expect(() =>
      parseOperationsState({
        ...initialOperationsState(at),
        catalog_observation: { initialized_at: at, repositories },
      }),
    ).toThrow();
  });

  test.each(["existing", "removed", "NEW", ""])(
    "rejects unsupported catalog change %j",
    (catalogChange) => {
      expect(() =>
        parseOperationsState({
          ...initialOperationsState(at),
          scan_queue: {
            next_ticket: 2,
            entries: [{ ...entry(42, 1), catalog_change: catalogChange }],
          },
        }),
      ).toThrow();
    },
  );

  test.each([
    {
      name: "repository identities",
      entries: [entry(42, 1), entry(42, 2)],
      nextTicket: 3,
    },
    {
      name: "tickets",
      entries: [entry(42, 1), entry(43, 1)],
      nextTicket: 2,
    },
  ])("rejects duplicate $name", ({ entries, nextTicket }) => {
    expect(() =>
      parseOperationsState({
        ...initialOperationsState(at),
        scan_queue: { next_ticket: nextTicket, entries },
      }),
    ).toThrow();
  });

  test("requires next_ticket to exceed every issued ticket", () => {
    expect(() =>
      parseOperationsState({
        ...initialOperationsState(at),
        scan_queue: { next_ticket: 3, entries: [entry(42, 3)] },
      }),
    ).toThrow();
  });

  test("validates chronic and failure timestamp consistency", () => {
    expect(() =>
      parseOperationsState({
        ...initialOperationsState(at),
        scan_queue: {
          next_ticket: 2,
          entries: [
            {
              ...entry(42, 1),
              consecutive_failures: 5,
              total_failures: 5,
              chronic: false,
            },
          ],
        },
      }),
    ).toThrow();
  });

  test("binds bounded queue history to its sanitized failure", () => {
    const failure = {
      code: "SCANNER_FAILED",
      domain: "target" as const,
      component: "opengrep" as const,
      diagnostic: "parser_syntax" as const,
    };
    const failedEntry = {
      ...entry(42, 1),
      consecutive_failures: 1,
      total_failures: 1,
      not_before: "2026-08-04T00:05:00.000Z",
      last_failure: failure,
      last_failed_at: at,
      failure_history: [
        {
          failed_at: at,
          failure,
          error_fingerprint: failureFingerprint(failure),
        },
      ],
    };

    expect(
      parseOperationsState({
        ...initialOperationsState(at),
        scan_queue: { next_ticket: 2, entries: [failedEntry] },
      }).scan_queue.entries[0]?.failure_history,
    ).toEqual(failedEntry.failure_history);
    expect(() =>
      parseOperationsState({
        ...initialOperationsState(at),
        scan_queue: {
          next_ticket: 2,
          entries: [
            {
              ...failedEntry,
              failure_history: [
                {
                  ...failedEntry.failure_history[0],
                  error_fingerprint: "f".repeat(64),
                },
              ],
            },
          ],
        },
      }),
    ).toThrow();
  });

  test("binds each automatic circuit to one sanitized systemic failure", () => {
    const failure = {
      code: "MODEL_PROVIDER",
      domain: "shared" as const,
      component: "contextual-model" as const,
    };
    const hold = {
      error_fingerprint: failureFingerprint(failure),
      failure,
      first_failed_at: at,
      last_failed_at: at,
      consecutive_failures: 1,
      next_probe_at: "2026-08-04T00:05:00.000Z",
      chronic: false,
    };
    expect(
      parseOperationsState({
        ...initialOperationsState(at),
        automatic_holds: [hold],
      }).automatic_holds,
    ).toEqual([hold]);
    expect(() =>
      parseOperationsState({
        ...initialOperationsState(at),
        automatic_holds: [hold, hold],
      }),
    ).toThrow();
    expect(() =>
      parseOperationsState({
        ...initialOperationsState(at),
        automatic_holds: [
          {
            ...hold,
            failure: { ...failure, domain: "target" },
          },
        ],
      }),
    ).toThrow();
  });
});
