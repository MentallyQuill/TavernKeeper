import { describe, expect, test } from "vitest";

import { failureFingerprint } from "../src/operations/failure.js";
import {
  initialOperationsState,
  parseOperationsState,
  pauseSystem,
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

describe("secret-free operations state V3", () => {
  test("creates a strict durable queue with bounded automatic recovery", () => {
    const state = initialOperationsState(at);

    expect(state).toMatchObject({
      schema_version: 3,
      emergency_stop: null,
      automatic_holds: [],
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
