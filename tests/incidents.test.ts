import { describe, expect, test } from "vitest";

import type { Target } from "../src/contracts/targets.js";
import { operationalIncidents } from "../src/cli/exhausted.js";
import { failureFingerprint } from "../src/operations/failure.js";
import { targetIncidentKey } from "../src/operations/incidents.js";
import { initialOperationsState } from "../src/operations/state.js";
import {
  appendQueuedTarget,
  rotateFailedTarget,
} from "../src/queue/durable-queue.js";

const target: Target = {
  source_id: "github-42",
  provider: "github",
  repository_id: 42,
  repository: "owner/repo",
  target_sha: "a".repeat(40),
  canonical_url: "https://github.com/owner/repo",
};

describe("operational incident identities", () => {
  test("keys a target incident independently of its failure class", () => {
    const first = targetIncidentKey(42, target.target_sha);

    expect(targetIncidentKey(42, target.target_sha)).toBe(first);
    expect(first).toMatch(/^[0-9a-f]{64}$/u);
    expect(targetIncidentKey(43, target.target_sha)).not.toBe(first);
    expect(targetIncidentKey(42, "b".repeat(40))).not.toBe(first);
  });

  test("exports one exact cooling target incident with bounded history", () => {
    let state = appendQueuedTarget(
      initialOperationsState("2026-08-04T00:00:00.000Z"),
      target,
    );
    for (let attempt = 0; attempt < 2; attempt += 1)
      state = rotateFailedTarget(state, {
        target,
        failure: {
          code: "SCANNER_FAILED",
          domain: "target",
          component: "opengrep",
          diagnostic: attempt % 2 === 0 ? "parser_syntax" : "rule_timeout",
        },
        at: new Date(Date.UTC(2026, 7, 4, attempt + 1)).toISOString(),
      }).state;

    expect(operationalIncidents(state).chronic_failures).toMatchObject([
      {
        target_incident_key: targetIncidentKey(42, target.target_sha),
        repository_id: 42,
        target_sha: target.target_sha,
        consecutive_failures: 2,
        failure_history: [
          { failure: { diagnostic: "parser_syntax" } },
          { failure: { diagnostic: "rule_timeout" } },
        ],
      },
    ]);
  });

  test("exports a terminal target separately from cooling work", () => {
    let state = appendQueuedTarget(
      initialOperationsState("2026-08-04T00:00:00.000Z"),
      target,
    );
    for (const [attempt, failedAt] of [
      "2026-08-04T01:00:00.000Z",
      "2026-08-04T02:00:00.000Z",
      "2026-08-11T02:00:00.000Z",
    ].entries())
      state = rotateFailedTarget(state, {
        target,
        failure: {
          code: "SCANNER_FAILED",
          domain: "target",
          component: "opengrep",
          diagnostic: attempt % 2 === 0 ? "parser_syntax" : "rule_timeout",
        },
        at: failedAt,
      }).state;

    const incidents = operationalIncidents(state);

    expect(incidents.chronic_failures).toEqual([]);
    expect(incidents.unscannable_targets).toEqual([
      expect.objectContaining({
        target_incident_key: targetIncidentKey(42, target.target_sha),
        repository_id: 42,
        repository: target.repository,
        target_sha: target.target_sha,
        consecutive_failures: 3,
        unscannable_at: "2026-08-11T02:00:00.000Z",
      }),
    ]);
  });

  test("exports a compatible last-only history for existing chronic state", () => {
    const failure = {
      code: "SCANNER_FAILED",
      domain: "target" as const,
      component: "opengrep" as const,
      diagnostic: "parser_syntax" as const,
    };
    const state = initialOperationsState("2026-08-04T00:00:00.000Z");
    const compatible = {
      ...state,
      scan_queue: {
        next_ticket: 2,
        entries: [
          {
            source_id: target.source_id,
            repository_id: target.repository_id,
            repository: target.repository,
            target_sha: target.target_sha,
            ticket: 1,
            consecutive_failures: 5,
            total_failures: 5,
            not_before: "2026-08-04T06:00:00.000Z",
            last_failure: failure,
            last_failed_at: "2026-08-04T00:00:00.000Z",
            chronic: true,
          },
        ],
      },
    };

    expect(
      operationalIncidents(compatible).chronic_failures[0]?.failure_history,
    ).toEqual([
      {
        failed_at: "2026-08-04T00:00:00.000Z",
        failure,
        error_fingerprint: failureFingerprint(failure),
      },
    ]);
  });
});
