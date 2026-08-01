import { readFile } from "node:fs/promises";

import { describe, expect, test } from "vitest";

import {
  initialOperationsState,
  parseOperationsState,
  serializeOperationsState,
} from "../src/operations/state.js";
import { recordFailure } from "../src/operations/retry.js";

describe("secret-free operational state", () => {
  test("ships paused until staff explicitly starts the initial rollout", async () => {
    const state = parseOperationsState(
      JSON.parse(
        await readFile(
          new URL("../operations/state.json", import.meta.url),
          "utf8",
        ),
      ),
    );

    expect(state).toMatchObject({
      pause: { kind: "staff", reason_code: "INITIAL_ROLLOUT" },
      circuit_breaker: null,
      retries: [],
      active_scans: [],
    });
  });

  test("rejects retry identities whose source ID does not match repository ID", () => {
    const now = "2026-07-31T12:00:00.000Z";
    const state = initialOperationsState(now);

    expect(() =>
      parseOperationsState({
        ...state,
        retries: [
          {
            source_id: "github-41",
            repository_id: 42,
            repository: "owner/repo",
            target_sha: "a".repeat(40),
            error_fingerprint: "b".repeat(64),
            error_code: "MODEL_QUOTA",
            scope: "system",
            initial_failed_at: now,
            last_failed_at: now,
            attempt: 1,
            next_retry_at: "2026-07-31T13:00:00.000Z",
            exhausted: false,
          },
        ],
      }),
    ).toThrow();
  });

  test("rejects non-exhausted retries without a scheduled next attempt", () => {
    const now = "2026-07-31T12:00:00.000Z";
    const state = initialOperationsState(now);

    expect(() =>
      parseOperationsState({
        ...state,
        retries: [
          {
            source_id: "github-42",
            repository_id: 42,
            repository: "owner/repo",
            target_sha: "a".repeat(40),
            error_fingerprint: "b".repeat(64),
            error_code: "MODEL_QUOTA",
            scope: "system",
            initial_failed_at: now,
            last_failed_at: now,
            attempt: 1,
            next_retry_at: null,
            exhausted: false,
          },
        ],
      }),
    ).toThrow();
  });

  test("serializes retry entries deterministically without diagnostic bodies", () => {
    const now = "2026-07-31T12:00:00.000Z";
    const first = recordFailure(initialOperationsState(now), {
      target: {
        source_id: "github-42",
        provider: "github",
        repository_id: 42,
        repository: "owner/repo-42",
        target_sha: "a".repeat(40),
        canonical_url: "https://github.com/owner/repo-42",
      },
      code: "MODEL_QUOTA",
      scope: "system",
      at: now,
    }).state;
    const second = recordFailure(first, {
      target: {
        source_id: "github-43",
        provider: "github",
        repository_id: 43,
        repository: "owner/repo-43",
        target_sha: "b".repeat(40),
        canonical_url: "https://github.com/owner/repo-43",
      },
      code: "MODEL_QUOTA",
      scope: "system",
      at: now,
    }).state;
    const reversed = parseOperationsState({
      ...second,
      retries: [...second.retries].reverse(),
    });

    const serialized = serializeOperationsState(second);
    expect(serializeOperationsState(reversed)).toBe(serialized);
    expect(serialized).not.toMatch(
      /api[_-]?key|credential|raw[_-]?error|response[_-]?body|prompt/iu,
    );
  });

  test("rejects multiple classified retry sequences for one target", () => {
    const now = "2026-07-31T12:00:00.000Z";
    const first = recordFailure(initialOperationsState(now), {
      target: {
        source_id: "github-42",
        provider: "github",
        repository_id: 42,
        repository: "owner/repo",
        target_sha: "a".repeat(40),
        canonical_url: "https://github.com/owner/repo",
      },
      code: "MODEL_QUOTA",
      scope: "system",
      at: now,
    }).state.retries[0]!;

    expect(() =>
      parseOperationsState({
        ...initialOperationsState(now),
        retries: [
          first,
          {
            ...first,
            error_fingerprint: "c".repeat(64),
            error_code: "MODEL_PROVIDER",
          },
        ],
      }),
    ).toThrow();
  });
});
