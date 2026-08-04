import { describe, expect, test } from "vitest";

import {
  initialOperationsState,
  parseOperationsState,
  pauseSystem,
  resumeSystem,
  serializeOperationsState,
} from "../src/operations/state.js";
import { recordFailure } from "../src/operations/retry.js";

describe("secret-free operations state V2", () => {
  test("creates strict V2 state without a singular circuit breaker", () => {
    const state = initialOperationsState("2026-08-04T00:00:00.000Z");

    expect(state).toMatchObject({
      schema_version: 2,
      target_retries: [],
      shared_holds: [],
    });
    expect(state).not.toHaveProperty("circuit_breaker");
    expect(state).not.toHaveProperty("retries");
  });

  test("records coverage start once on first resume", () => {
    const created = "2026-08-03T12:00:00.000Z";
    const firstResume = "2026-08-04T12:00:00.000Z";
    const secondResume = "2026-08-05T12:00:00.000Z";
    const started = resumeSystem(initialOperationsState(created), firstResume);
    const paused = pauseSystem(started, {
      kind: "staff",
      reasonCode: "STAFF_PAUSE",
      at: "2026-08-04T13:00:00.000Z",
    });

    expect(resumeSystem(paused, secondResume).coverage_started_at).toBe(
      firstResume,
    );
  });

  test("validates fingerprints against their complete descriptors", () => {
    const at = "2026-08-04T00:00:00.000Z";
    const retry = recordFailure(initialOperationsState(at), {
      target: {
        source_id: "github-42",
        provider: "github",
        repository_id: 42,
        repository: "owner/repo",
        target_sha: "a".repeat(40),
        canonical_url: "https://github.com/owner/repo",
      },
      failure: {
        code: "SCANNER_FAILED",
        domain: "target",
        component: "opengrep",
      },
      at,
    }).entry;

    expect(() =>
      parseOperationsState({
        ...initialOperationsState(at),
        target_retries: [{ ...retry, error_fingerprint: "b".repeat(64) }],
      }),
    ).toThrow();
  });

  test("serializes entries deterministically without diagnostic bodies", () => {
    const at = "2026-08-04T00:00:00.000Z";
    const first = recordFailure(initialOperationsState(at), {
      target: {
        source_id: "github-43",
        provider: "github",
        repository_id: 43,
        repository: "owner/repo-43",
        target_sha: "b".repeat(40),
        canonical_url: "https://github.com/owner/repo-43",
      },
      failure: {
        code: "MODEL_PROVIDER",
        domain: "shared",
        component: "contextual-model",
      },
      at,
    }).state;
    const second = recordFailure(first, {
      target: {
        source_id: "github-42",
        provider: "github",
        repository_id: 42,
        repository: "owner/repo-42",
        target_sha: "a".repeat(40),
        canonical_url: "https://github.com/owner/repo-42",
      },
      failure: {
        code: "SCANNER_FAILED",
        domain: "target",
        component: "opengrep",
      },
      at,
    }).state;
    const reversed = parseOperationsState({
      ...second,
      target_retries: [...second.target_retries].reverse(),
      shared_holds: [...second.shared_holds].reverse(),
    });

    const serialized = serializeOperationsState(second);
    expect(serializeOperationsState(reversed)).toBe(serialized);
    expect(serialized).not.toMatch(
      /api[_-]?key|credential|raw[_-]?error|response[_-]?body|prompt/iu,
    );
  });

  test("rejects duplicate retry identities", () => {
    const at = "2026-08-04T00:00:00.000Z";
    const retry = recordFailure(initialOperationsState(at), {
      target: {
        source_id: "github-42",
        provider: "github",
        repository_id: 42,
        repository: "owner/repo",
        target_sha: "a".repeat(40),
        canonical_url: "https://github.com/owner/repo",
      },
      failure: {
        code: "SCANNER_FAILED",
        domain: "target",
        component: "opengrep",
      },
      at,
    }).entry;

    expect(() =>
      parseOperationsState({
        ...initialOperationsState(at),
        target_retries: [retry, retry],
      }),
    ).toThrow();
  });
});
