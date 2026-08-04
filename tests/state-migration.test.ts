import { describe, expect, test } from "vitest";

import { migrateOperationsState } from "../src/operations/migrate-state.js";

const at = "2026-08-04T12:00:00.000Z";
const initialFailedAt = "2026-08-01T00:00:00.000Z";

function legacyRetry(
  repositoryId: number,
  input: {
    code: string;
    scope: "repository" | "system";
    exhausted?: boolean;
  },
) {
  return {
    source_id: `github-${repositoryId}`,
    repository_id: repositoryId,
    repository: `owner/repo-${repositoryId}`,
    target_sha: String(repositoryId % 10).repeat(40),
    error_fingerprint: "a".repeat(64),
    error_code: input.code,
    scope: input.scope,
    initial_failed_at: initialFailedAt,
    last_failed_at: initialFailedAt,
    attempt: input.exhausted === true ? 3 : 1,
    next_retry_at: input.exhausted === true ? null : "2026-08-01T01:00:00.000Z",
    exhausted: input.exhausted === true,
  };
}

describe("explicit operations-state migration", () => {
  test("maps a literal V1 state without preserving the singular breaker", () => {
    const migrated = migrateOperationsState(
      {
        schema_version: 1,
        updated_at: "2026-08-01T01:00:00.000Z",
        coverage_started_at: "2026-07-31T00:00:00.000Z",
        pause: null,
        circuit_breaker: {
          error_fingerprint: "a".repeat(64),
          engaged_at: initialFailedAt,
          terminal: false,
        },
        retries: [
          legacyRetry(41, {
            code: "MODEL_INVALID_RESPONSE",
            scope: "repository",
            exhausted: true,
          }),
          legacyRetry(42, { code: "MODEL_PROVIDER", scope: "system" }),
          legacyRetry(43, { code: "SCANNER_FAILED", scope: "system" }),
        ],
        active_scans: [
          {
            source_id: "github-44",
            repository_id: 44,
            target_sha: "4".repeat(40),
            started_at: initialFailedAt,
            run_id: "run-44",
          },
        ],
        policy_campaigns: [
          {
            id: "campaign-1",
            scanner_policy_version: "3",
            repository_ids: [41, 42, 43],
            created_at: initialFailedAt,
            status: "active",
          },
        ],
      },
      at,
    );

    expect(migrated.summary).toEqual({ target: 2, shared: 1, security: 0 });
    expect(migrated.state).toMatchObject({
      schema_version: 2,
      updated_at: at,
      coverage_started_at: "2026-07-31T00:00:00.000Z",
      pause: null,
      active_scans: [expect.objectContaining({ repository_id: 44 })],
      policy_campaigns: [expect.objectContaining({ id: "campaign-1" })],
      shared_holds: [
        expect.objectContaining({
          failure: {
            code: "MODEL_PROVIDER",
            domain: "shared",
            component: "contextual-model",
          },
        }),
      ],
    });
    expect(migrated.state).not.toHaveProperty("circuit_breaker");
    expect(
      migrated.state.target_retries.find(
        ({ repository_id }) => repository_id === 41,
      ),
    ).toMatchObject({
      exhausted: true,
      attempt: 4,
      failure: { domain: "target", component: "contextual-model" },
    });
    expect(
      migrated.state.target_retries.find(
        ({ repository_id }) => repository_id === 43,
      ),
    ).toMatchObject({
      failure: { domain: "target", component: "orchestrator" },
    });
  });

  test("rejects migration of state that is already V2", () => {
    expect(() =>
      migrateOperationsState(
        {
          schema_version: 2,
          updated_at: at,
          coverage_started_at: null,
          pause: null,
          target_retries: [],
          shared_holds: [],
          active_scans: [],
          policy_campaigns: [],
        },
        at,
      ),
    ).toThrow("already schema version 2");
  });

  test.each(["SCAN_PHASE_FAILED", "CLI_FAILED"])(
    "keeps ambiguous legacy %s failures target-local",
    (code) => {
      const migrated = migrateOperationsState(
        {
          schema_version: 1,
          updated_at: "2026-08-01T01:00:00.000Z",
          coverage_started_at: null,
          pause: null,
          circuit_breaker: null,
          retries: [legacyRetry(45, { code, scope: "system" })],
          active_scans: [],
          policy_campaigns: [],
        },
        at,
      );

      expect(migrated.summary).toEqual({
        target: 1,
        shared: 0,
        security: 0,
      });
      expect(migrated.state.pause).toBeNull();
      expect(migrated.state.target_retries[0]).toMatchObject({
        failure: { code, domain: "target", component: "orchestrator" },
        exhausted: false,
      });
    },
  );
});
