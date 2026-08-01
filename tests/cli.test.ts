import { readFile } from "node:fs/promises";

import { describe, expect, test } from "vitest";

import { buildReconcileMatrix } from "../src/cli/reconcile.js";
import { validateStaffScanRequest } from "../src/cli/staff-request.js";
import { buildTargetedMatrix } from "../src/cli/targeted-scan.js";
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
      index: { schema_version: 2, generated_at: now, reports: [] },
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

  test("targeted scans derive a standard request from repository ID and live V2 data", () => {
    const targetValue = target(42);
    const matrix = buildTargetedMatrix({
      manifest: {
        schema_version: 2,
        generated_at: now,
        repositories: [targetValue],
      },
      index: { schema_version: 2, generated_at: now, reports: [] },
      state: initialOperationsState(now),
      repositoryId: 42,
      scannerPolicyVersion: "1",
    });

    expect(matrix).toMatchObject({ coalesced: false });
    expect(matrix.include).toEqual([
      expect.objectContaining({
        repository_id: 42,
        repository: "owner/repo-42",
        target_sha: targetValue.target_sha,
        reason: "staff",
        mode: "standard",
        report_version: 1,
      }),
    ]);
  });

  test("targeted scans coalesce an identical active repository and SHA", () => {
    const targetValue = target(42);
    const matrix = buildTargetedMatrix({
      manifest: {
        schema_version: 2,
        generated_at: now,
        repositories: [targetValue],
      },
      index: { schema_version: 2, generated_at: now, reports: [] },
      state: {
        ...initialOperationsState(now),
        active_scans: [
          {
            source_id: targetValue.source_id,
            repository_id: 42,
            target_sha: targetValue.target_sha,
            started_at: now,
            run_id: "already-running",
          },
        ],
      },
      repositoryId: 42,
      scannerPolicyVersion: "1",
    });

    expect(matrix).toEqual({ include: [], coalesced: true });
  });

  test("targeted scans reject IDs absent from the public V2 manifest", () => {
    expect(() =>
      buildTargetedMatrix({
        manifest: { schema_version: 2, generated_at: now, repositories: [] },
        index: { schema_version: 2, generated_at: now, reports: [] },
        state: initialOperationsState(now),
        repositoryId: 42,
        scannerPolicyVersion: "1",
      }),
    ).toThrow(/not in Tavernary's V2 manifest/iu);
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
