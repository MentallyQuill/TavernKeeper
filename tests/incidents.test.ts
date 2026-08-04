import { describe, expect, test } from "vitest";

import { targetIncidentKey } from "../src/operations/incidents.js";
import { exhaustedIncidents } from "../src/cli/exhausted.js";
import { initialOperationsState } from "../src/operations/state.js";
import { recordFailure } from "../src/operations/retry.js";

describe("operational incident identities", () => {
  test("keys a target incident independently of its failure class", () => {
    const sha = "a".repeat(40);
    const first = targetIncidentKey(42, sha);
    const repeated = targetIncidentKey(42, sha);

    expect(repeated).toBe(first);
    expect(first).toMatch(/^[0-9a-f]{64}$/u);
    expect(targetIncidentKey(43, sha)).not.toBe(first);
    expect(targetIncidentKey(42, "b".repeat(40))).not.toBe(first);
  });

  test("exports one exact-target incident with bounded history", () => {
    const target = {
      source_id: "github-42",
      provider: "github" as const,
      repository_id: 42,
      repository: "owner/repo",
      target_sha: "a".repeat(40),
      canonical_url: "https://github.com/owner/repo",
    };
    let state = initialOperationsState("2026-08-04T00:00:00.000Z");
    for (let attempt = 0; attempt < 4; attempt += 1)
      state = recordFailure(state, {
        target,
        failure: {
          code: attempt % 2 === 0 ? "SCANNER_FAILED" : "SCANNER_TIMEOUT",
          domain: "target",
          component: "opengrep",
        },
        at: new Date(Date.UTC(2026, 7, 4, attempt)).toISOString(),
      }).state;

    expect(exhaustedIncidents(state).target_exhaustions).toMatchObject([
      {
        target_incident_key: targetIncidentKey(42, target.target_sha),
        repository_id: 42,
        target_sha: target.target_sha,
        failure_history: expect.arrayContaining([
          expect.objectContaining({
            failure: expect.objectContaining({ code: "SCANNER_FAILED" }),
          }),
          expect.objectContaining({
            failure: expect.objectContaining({ code: "SCANNER_TIMEOUT" }),
          }),
        ]),
      },
    ]);
  });
});
