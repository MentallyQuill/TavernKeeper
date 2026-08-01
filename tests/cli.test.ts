import { readFile } from "node:fs/promises";

import { describe, expect, test } from "vitest";

import { buildReconcileMatrix } from "../src/cli/reconcile.js";
import { validateStaffScanRequest } from "../src/cli/staff-request.js";
import { initialOperationsState } from "../src/operations/state.js";

const now = "2026-07-31T18:00:00.000Z";

function target(repositoryId: number) {
  return {
    source_id: `github-${repositoryId}`,
    provider: "github" as const,
    repository_id: repositoryId,
    repository: `owner/repo-${repositoryId}`,
    target_sha: repositoryId.toString(16).padStart(40, "0"),
    canonical_url: `https://github.com/owner/repo-${repositoryId}`,
    project_kinds: ["extension"] as const,
    catalog_priority: {
      top_30: false,
      first_cataloged_at: "2026-07-01T00:00:00.000Z",
    },
  };
}

describe("JSON-only orchestration CLIs", () => {
  test("reconcile emits no more than five self-contained scan requests", () => {
    const matrix = buildReconcileMatrix({
      manifest: {
        schema_version: 2,
        generated_at: now,
        repositories: Array.from({ length: 8 }, (_, index) =>
          target(index + 1),
        ),
      },
      index: { schema_version: 1, generated_at: now, reports: [] },
      state: initialOperationsState(now),
      now,
      scannerPolicyVersion: "1",
    });

    expect(matrix.include).toHaveLength(5);
    expect(matrix.remaining).toBe(3);
    expect(matrix.include[0]).toMatchObject({
      repository_id: 1,
      mode: "standard",
      report_version: 1,
      supersedes_report_id: null,
      reason: "new",
    });
  });

  test("waits without selecting work from a frozen V1 target manifest", () => {
    expect(
      buildReconcileMatrix({
        manifest: { schema_version: 1, generated_at: now, repositories: [] },
        index: { schema_version: 1, generated_at: now, reports: [] },
        state: initialOperationsState(now),
        now,
        scannerPolicyVersion: "1",
      }),
    ).toMatchObject({ include: [], remaining: 0 });
  });

  test("staff scan requests accept repository identity and reject spend/config injection", () => {
    expect(
      validateStaffScanRequest({ repository_id: 42, mode: "deep" }),
    ).toEqual({ repository_id: 42, mode: "deep" });
    for (const forbidden of [
      { repository_id: 42, mode: "deep", model: "attacker/model" },
      { repository_id: 42, mode: "deep", token_budget: 1_000_000 },
      { repository_id: 42, mode: "deep", clone_url: "https://example.test/x" },
      { repository_id: 42, mode: "deep", command: "curl attacker" },
    ])
      expect(() => validateStaffScanRequest(forbidden)).toThrow();
  });

  test("non-model phases never read provider configuration", async () => {
    const texts = await Promise.all(
      ["prepare-target.ts", "finalize-target.ts"].map((name) =>
        readFile(new URL(`../src/cli/${name}`, import.meta.url), "utf8"),
      ),
    );

    expect(texts.join("\n")).not.toMatch(
      /TAVERNKEEPER_API_ENDPOINT|TAVERNKEEPER_API_KEY|TAVERNKEEPER_MODEL/u,
    );
  });
});
