import { readFile } from "node:fs/promises";

import { describe, expect, test } from "vitest";

import { buildReconcileMatrix } from "../src/cli/reconcile.js";
import { validateStaffScanRequest } from "../src/cli/staff-request.js";
import { buildTargetedMatrix } from "../src/cli/targeted-scan.js";
import {
  initialOperationsState,
  pauseSystem,
} from "../src/operations/state.js";
import { recordFailure } from "../src/operations/retry.js";

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

function indexedReport(
  targetValue: ReturnType<typeof target>,
  completedAt: string,
) {
  const reportId = targetValue.repository_id.toString(16).padStart(64, "0");
  return {
    report_id: reportId,
    report_digest: reportId,
    report_version: 1,
    supersedes_report_id: null,
    scanner_version: "1.0.0",
    scanner_policy_version: "2",
    rule_catalog_version: "1",
    package_schema_version: 1,
    contextual_review_policy_version: "1",
    ecosystem_context_version: "sillytavern-community-v1",
    prompt_version: "contextual-review-v1",
    assessment_schema_version: "contextual-assessment-v1",
    source_id: targetValue.source_id,
    provider: "github" as const,
    repository_id: targetValue.repository_id,
    repository: targetValue.repository,
    target_sha: targetValue.target_sha,
    completed_at: completedAt,
    assessment_method: "deterministic-evidence-contextual-review" as const,
    counts: {
      candidates: 0,
      assessments: 0,
      observations: 0,
      items: 0,
      disposition: {
        expected_behavior: 0,
        minor_weakness: 0,
        material_vulnerability: 0,
        credible_malicious_behavior: 0,
      },
      impact: { none: 0, low: 0, medium: 0, high: 0, critical: 0 },
      exploitability: {
        unlikely: 0,
        plausible: 0,
        readily_exploitable: 0,
      },
      confidence: { high: 0, medium: 0, low: 0 },
      recommended_risk: { low: 0, material: 0, high: 0 },
    },
    coverage: {
      history_commits: 1,
      inventory_files: 1,
      inventory_bytes: 1,
      tools_completed: 4,
      tools_not_applicable: 3,
      evidence_validated: 0,
      review_required: 0,
      review_completed: 0,
    },
    report_url:
      "https://mentallyquill.github.io/TavernKeeper/reports/github/" +
      `${targetValue.repository_id}/${targetValue.target_sha}/2/${reportId}/`,
    history_url:
      "https://mentallyquill.github.io/TavernKeeper/reports/github/" +
      `${targetValue.repository_id}/history/`,
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
      index: { schema_version: 5, generated_at: now, reports: [] },
      state: initialOperationsState(now),
      now,
      scannerPolicyVersion: "2",
    });

    expect(matrix.include).toHaveLength(5);
    expect(matrix).toMatchObject({
      total_remaining: 3,
      runnable_remaining: 3,
      delayed_retries: 0,
      shared_holds: 0,
      primary_remaining: 3,
      automatic_retries: 0,
      manual_quarantines: 0,
      exhausted_targets: 0,
      next_wake_at: null,
      blocked: false,
    });
    expect(matrix.include[0]).toMatchObject({
      repository_id: 1,
      report_version: 1,
      supersedes_report_id: null,
      reason: "new",
    });
  });

  test("targeted scans derive one request from repository ID and live V5 data", () => {
    const targetValue = target(42);
    const matrix = buildTargetedMatrix({
      manifest: {
        schema_version: 2,
        generated_at: now,
        repositories: [targetValue],
      },
      index: { schema_version: 5, generated_at: now, reports: [] },
      state: initialOperationsState(now),
      repositoryId: 42,
      scannerPolicyVersion: "2",
      requestCreatedAt: now,
    });

    expect(matrix).toMatchObject({ coalesced: false });
    expect(matrix.include).toEqual([
      expect.objectContaining({
        repository_id: 42,
        repository: "owner/repo-42",
        target_sha: targetValue.target_sha,
        reason: "staff",
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
      index: { schema_version: 5, generated_at: now, reports: [] },
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
      scannerPolicyVersion: "2",
      requestCreatedAt: now,
    });

    expect(matrix).toEqual({ include: [], coalesced: true });
  });

  test("coalesces a queued request completed after the workflow was created", async () => {
    const targetValue = target(42);
    const report = indexedReport(targetValue, "2026-07-31T18:05:00.000Z");
    const matrix = buildTargetedMatrix({
      manifest: {
        schema_version: 2,
        generated_at: now,
        repositories: [targetValue],
      },
      index: { schema_version: 5, generated_at: now, reports: [report] },
      state: initialOperationsState(now),
      repositoryId: 42,
      scannerPolicyVersion: "2",
      requestCreatedAt: now,
    });

    expect(matrix).toEqual({ include: [], coalesced: true });
  });

  test("allows an intentional forced rescan requested after the prior report", async () => {
    const targetValue = target(42);
    const report = indexedReport(targetValue, "2026-07-31T17:55:00.000Z");
    const matrix = buildTargetedMatrix({
      manifest: {
        schema_version: 2,
        generated_at: now,
        repositories: [targetValue],
      },
      index: { schema_version: 5, generated_at: now, reports: [report] },
      state: initialOperationsState(now),
      repositoryId: 42,
      scannerPolicyVersion: "2",
      requestCreatedAt: now,
    });

    expect(matrix.coalesced).toBe(false);
    expect(matrix.include).toEqual([
      expect.objectContaining({
        repository_id: 42,
        report_version: 2,
        supersedes_report_id: report.report_id,
      }),
    ]);
  });

  test("lets a staff-targeted request override an already recorded retry", () => {
    const targetValue = target(42);
    const {
      project_kinds: _projectKinds,
      catalog_priority: _catalogPriority,
      ...targetIdentity
    } = targetValue;
    const retryState = recordFailure(initialOperationsState(now), {
      target: targetIdentity,
      failure: {
        code: "SCANNER_TIMEOUT",
        domain: "target",
        component: "opengrep",
      },
      at: now,
    }).state;
    const matrix = buildTargetedMatrix({
      manifest: {
        schema_version: 2,
        generated_at: now,
        repositories: [targetValue],
      },
      index: { schema_version: 5, generated_at: now, reports: [] },
      state: retryState,
      repositoryId: 42,
      scannerPolicyVersion: "2",
      requestCreatedAt: now,
    });

    expect(matrix.coalesced).toBe(false);
    expect(matrix.include).toEqual([
      expect.objectContaining({
        repository_id: 42,
        report_version: 1,
        supersedes_report_id: null,
      }),
    ]);
  });

  test("targeted wakes respect staff and security pauses", () => {
    const targetValue = target(42);
    for (const kind of ["staff", "system"] as const) {
      const state = pauseSystem(initialOperationsState(now), {
        kind,
        reasonCode: kind === "staff" ? "STAFF_PAUSE" : "SECURITY_HOLD",
        at: now,
      });
      expect(
        buildTargetedMatrix({
          manifest: {
            schema_version: 2,
            generated_at: now,
            repositories: [targetValue],
          },
          index: { schema_version: 5, generated_at: now, reports: [] },
          state,
          repositoryId: 42,
          scannerPolicyVersion: "2",
          requestCreatedAt: now,
        }),
      ).toEqual({ include: [], coalesced: true });
    }
  });

  test("targeted wakes cannot bypass shared-probe isolation", () => {
    const targetValue = target(42);
    const {
      project_kinds: _projectKinds,
      catalog_priority: _catalogPriority,
      ...targetIdentity
    } = targetValue;
    const state = recordFailure(initialOperationsState(now), {
      target: targetIdentity,
      failure: {
        code: "MODEL_PROVIDER",
        domain: "shared",
        component: "contextual-model",
      },
      at: now,
    }).state;

    expect(
      buildTargetedMatrix({
        manifest: {
          schema_version: 2,
          generated_at: now,
          repositories: [targetValue],
        },
        index: { schema_version: 5, generated_at: now, reports: [] },
        state,
        repositoryId: 42,
        scannerPolicyVersion: "2",
        requestCreatedAt: "2026-07-31T18:05:00.000Z",
      }),
    ).toEqual({ include: [], coalesced: true });
  });

  test("targeted scans reject IDs absent from the public target manifest", () => {
    expect(() =>
      buildTargetedMatrix({
        manifest: { schema_version: 2, generated_at: now, repositories: [] },
        index: { schema_version: 5, generated_at: now, reports: [] },
        state: initialOperationsState(now),
        repositoryId: 42,
        scannerPolicyVersion: "2",
        requestCreatedAt: now,
      }),
    ).toThrow(/not in Tavernary's current target manifest/iu);
  });

  test("waits without selecting work from a frozen V1 target manifest", () => {
    expect(
      buildReconcileMatrix({
        manifest: { schema_version: 1, generated_at: now, repositories: [] },
        index: { schema_version: 5, generated_at: now, reports: [] },
        state: initialOperationsState(now),
        now,
        scannerPolicyVersion: "2",
      }),
    ).toMatchObject({ include: [], total_remaining: 0 });
  });

  test("staff scan requests accept only repository identity", () => {
    expect(validateStaffScanRequest({ repository_id: 42 })).toEqual({
      repository_id: 42,
    });
    for (const forbidden of [
      { repository_id: 42, mode: "deep" },
      { repository_id: 42, model: "attacker/model" },
      { repository_id: 42, token_budget: 1_000_000 },
      { repository_id: 42, clone_url: "https://example.test/x" },
      { repository_id: 42, command: "curl attacker" },
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
