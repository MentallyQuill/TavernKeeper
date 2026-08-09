import { readFile } from "node:fs/promises";

import { describe, expect, test } from "vitest";

import { buildReconcileMatrix } from "../src/cli/reconcile.js";
import { buildQueueSynchronization } from "../src/cli/sync-queue.js";
import { probeFailureProvesSharedRecovery } from "../src/cli/probe-outcome.js";
import { applyRetryOperation } from "../src/cli/retry.js";
import { validateStaffScanRequest } from "../src/cli/staff-request.js";
import { reviewConfiguredTarget } from "../src/cli/review-target.js";
import {
  buildTargetedMatrix,
  buildTargetedQueueUpdate,
} from "../src/cli/targeted-scan.js";
import type { TargetManifestV2 } from "../src/contracts/targets.js";
import {
  initialOperationsState,
  pauseSystem,
} from "../src/operations/state.js";
import { recordFailure } from "../src/operations/retry.js";
import { syncScanQueue } from "../src/queue/sync.js";

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
      metadata_only_candidates: 0,
      review_required: 0,
      review_completed: 0,
      javascript_analysis_status: "legacy" as const,
    },
    report_url:
      "https://mentallyquill.github.io/TavernKeeper/reports/github/" +
      `${targetValue.repository_id}/${targetValue.target_sha}/2/${reportId}/`,
    history_url:
      "https://mentallyquill.github.io/TavernKeeper/reports/github/" +
      `${targetValue.repository_id}/history/`,
  };
}

function stateObserving(...targets: ReturnType<typeof target>[]) {
  return {
    ...initialOperationsState(now),
    catalog_observation: {
      initialized_at: now,
      repositories: targets.map(({ repository_id, target_sha }) => ({
        repository_id,
        target_sha,
      })),
    },
  };
}

describe("JSON-only orchestration CLIs", () => {
  test("defaults every coordinator entry point to scanner policy 4", () => {
    const targetValue = target(42);
    const manifest: TargetManifestV2 = {
      schema_version: 2,
      generated_at: now,
      repositories: [
        { ...targetValue, project_kinds: [...targetValue.project_kinds] },
      ],
    };
    const prior = {
      ...indexedReport(targetValue, "2026-07-31T17:55:00.000Z"),
      scanner_policy_version: "3",
      report_url: indexedReport(
        targetValue,
        "2026-07-31T17:55:00.000Z",
      ).report_url.replace("/2/", "/3/"),
    };
    const index = {
      schema_version: 5 as const,
      generated_at: now,
      reports: [prior],
    };
    const synchronized = buildQueueSynchronization({
      manifest,
      index,
      state: {
        ...stateObserving(targetValue),
        policy_campaigns: [
          {
            id: "policy-4-test",
            scanner_policy_version: "4",
            repository_ids: [42],
            created_at: now,
            status: "active",
          },
        ],
      },
      now,
    });

    expect(
      buildReconcileMatrix({
        manifest,
        index,
        state: synchronized.state,
        now,
      }).include[0],
    ).toMatchObject({
      reason: "changed",
      report_version: 1,
      supersedes_report_id: null,
    });
    expect(
      buildTargetedMatrix({
        manifest,
        index,
        state: initialOperationsState(now),
        repositoryId: 42,
        requestCreatedAt: now,
      }).include[0],
    ).toMatchObject({ report_version: 1, supersedes_report_id: null });
  });

  test("only complete target contextual failures prove shared provider recovery", () => {
    expect(
      probeFailureProvesSharedRecovery({
        code: "MODEL_EVIDENCE_INVALID",
        domain: "target",
        component: "contextual-model",
      }),
    ).toBe(true);
    expect(probeFailureProvesSharedRecovery({ domain: "target" })).toBe(false);
    expect(
      probeFailureProvesSharedRecovery({
        code: "MODEL_PROVIDER",
        domain: "target",
        component: "contextual-model",
      }),
    ).toBe(false);
    expect(
      probeFailureProvesSharedRecovery({
        code: "SCANNER_FAILED",
        domain: "target",
        component: "opengrep",
      }),
    ).toBe(false);
  });

  test("reconcile emits no more than five self-contained scan requests", () => {
    const manifest: TargetManifestV2 = {
      schema_version: 2,
      generated_at: now,
      repositories: Array.from({ length: 8 }, (_, index) => {
        const current = target(index + 1);
        return { ...current, project_kinds: [...current.project_kinds] };
      }),
    };
    const index = {
      schema_version: 5 as const,
      generated_at: now,
      reports: [],
    };
    const state = syncScanQueue({
      manifest,
      index,
      state: stateObserving(),
      now,
      scannerPolicyVersion: "2",
    }).state;
    const matrix = buildReconcileMatrix({
      manifest,
      index,
      state,
      now,
      scannerPolicyVersion: "2",
    });

    expect(matrix.include).toHaveLength(5);
    expect(matrix).toMatchObject({
      total_remaining: 3,
      runnable_remaining: 3,
      delayed_entries: 0,
      next_wake_at: null,
      emergency_stopped: false,
    });
    expect(matrix.include[0]).toMatchObject({
      repository_id: 1,
      report_version: 1,
      supersedes_report_id: null,
      reason: "new",
    });
  });

  test("reconcile emits a direct provider probe instead of a repository request", () => {
    const targetValue = target(42);
    const manifest: TargetManifestV2 = {
      schema_version: 2,
      generated_at: now,
      repositories: [
        { ...targetValue, project_kinds: [...targetValue.project_kinds] },
      ],
    };
    const index = {
      schema_version: 5 as const,
      generated_at: now,
      reports: [],
    };
    const queued = syncScanQueue({
      manifest,
      index,
      state: initialOperationsState(now),
      now,
      scannerPolicyVersion: "2",
    }).state;
    const held = recordFailure(queued, {
      target: targetValue,
      failure: {
        code: "MODEL_PROVIDER",
        domain: "shared",
        component: "contextual-model",
      },
      at: now,
    }).state;
    const fingerprint = held.automatic_holds[0]!.error_fingerprint;
    const probeAt = "2026-07-31T18:01:00.000Z";

    expect(
      buildReconcileMatrix({
        manifest,
        index,
        state: held,
        now: probeAt,
        scannerPolicyVersion: "2",
        forceProviderProbe: true,
      }),
    ).toMatchObject({
      include: [],
      recovery_probes: 1,
      provider_probe_fingerprint: fingerprint,
    });
    expect(
      applyRetryOperation(
        held,
        {
          operation: "provider-probe-success",
          error_fingerprint: fingerprint,
          probed_at: probeAt,
        },
        probeAt,
      ).automatic_holds,
    ).toEqual([]);
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
      state: stateObserving(),
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

  test("persists a forced rescan ticket and selects it ahead of ordinary due work", () => {
    const first = target(1);
    const second = target(2);
    const targeted = target(42);
    const prior = indexedReport(targeted, "2026-07-31T17:55:00.000Z");
    const manifest: TargetManifestV2 = {
      schema_version: 2,
      generated_at: now,
      repositories: [first, second, targeted].map((entry) => ({
        ...entry,
        project_kinds: [...entry.project_kinds],
      })),
    };
    const index = {
      schema_version: 5 as const,
      generated_at: now,
      reports: [prior],
    };

    const queued = buildTargetedQueueUpdate({
      manifest,
      index,
      state: stateObserving(),
      repositoryId: 42,
      scannerPolicyVersion: "2",
      requestCreatedAt: now,
      now,
    });

    expect(queued).toMatchObject({
      accepted: true,
      coalesced: false,
      changed: true,
      ticket: 3,
    });
    expect(
      queued.state.scan_queue.entries.map(({ repository_id, ticket }) => [
        repository_id,
        ticket,
      ]),
    ).toEqual([
      [1, 1],
      [2, 2],
      [42, 3],
    ]);

    const later = target(43);
    const synchronized = syncScanQueue({
      manifest: {
        ...manifest,
        repositories: [
          ...manifest.repositories,
          { ...later, project_kinds: [...later.project_kinds] },
        ],
      },
      index,
      state: queued.state,
      now: "2026-07-31T18:01:00.000Z",
      scannerPolicyVersion: "2",
    }).state;
    expect(
      synchronized.scan_queue.entries.map(({ repository_id, ticket }) => [
        repository_id,
        ticket,
      ]),
    ).toEqual([
      [1, 1],
      [2, 2],
      [42, 3],
      [43, 4],
    ]);

    const matrix = buildReconcileMatrix({
      manifest: {
        ...manifest,
        repositories: [
          ...manifest.repositories,
          { ...later, project_kinds: [...later.project_kinds] },
        ],
      },
      index,
      state: synchronized,
      now: "2026-07-31T18:02:00.000Z",
      scannerPolicyVersion: "2",
    });
    expect(matrix.include.map(({ repository_id }) => repository_id)).toEqual([
      42, 1, 2, 43,
    ]);
    expect(matrix.include[0]).toMatchObject({
      repository_id: 42,
      reason: "staff",
      report_version: 2,
      supersedes_report_id: prior.report_id,
    });
  });

  test("clears an automatic rescan cooldown when a targeted scan promotes it to staff work", () => {
    const priorTarget = { ...target(42), target_sha: "a".repeat(40) };
    const currentTarget = { ...priorTarget, target_sha: "b".repeat(40) };
    const index = {
      schema_version: 5 as const,
      generated_at: now,
      reports: [indexedReport(priorTarget, "2026-07-30T18:00:00.000Z")],
    };
    const manifest: TargetManifestV2 = {
      schema_version: 2,
      generated_at: now,
      repositories: [{ ...currentTarget, project_kinds: ["extension"] }],
    };
    const automaticState = syncScanQueue({
      manifest,
      index,
      state: stateObserving(priorTarget),
      now,
      scannerPolicyVersion: "2",
    }).state;

    expect(automaticState.scan_queue.entries[0]).toMatchObject({
      rescan_not_before: "2026-08-01T18:00:00.000Z",
    });

    const queued = buildTargetedQueueUpdate({
      manifest,
      index,
      state: automaticState,
      repositoryId: 42,
      scannerPolicyVersion: "2",
      requestCreatedAt: now,
      now,
    });

    expect(queued.state.scan_queue.entries[0]).toMatchObject({
      staff_requested: true,
    });
    expect(queued.state.scan_queue.entries[0]).not.toHaveProperty(
      "rescan_not_before",
    );
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

  test("targeted wakes respect the explicit staff emergency stop", () => {
    const targetValue = target(42);
    const state = pauseSystem(initialOperationsState(now), {
      kind: "staff",
      reasonCode: "STAFF_PAUSE",
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
  });

  test("a shared diagnostic failure cannot stall a targeted wake", () => {
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
    ).toEqual({
      include: [
        expect.objectContaining({
          repository_id: 42,
          target_sha: targetValue.target_sha,
        }),
      ],
      coalesced: false,
    });
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

  test("reviews a prepared target without a checkout path", async () => {
    const result = await reviewConfiguredTarget(
      {
        TAVERNKEEPER_SESSION_ROOT: "C:/runner/tavernkeeper-session-42",
        TAVERNKEEPER_API_ENDPOINT:
          "https://provider.example/v1/chat/completions",
        TAVERNKEEPER_API_KEY: "test-key",
        TAVERNKEEPER_MODEL: "configured/model",
      },
      {
        loadPolicy: async () => ({
          version: "2",
          promptVersion: "contextual-review-v5",
          schemaVersion: "contextual-assessment-v1",
          maxImmediateAttempts: 3,
          maxOutputTokens: 32_768,
          maxResponseBytes: 5_000_000,
          timeoutMs: 300_000,
        }),
        review: async (spec) => {
          expect(spec.sessionRoot).toBe("C:/runner/tavernkeeper-session-42");
          expect(spec.expandContext).toBeTypeOf("function");
          return { status: "reviewed", review: {} as never };
        },
      },
    );

    expect(result).toEqual({ status: "reviewed" });
    const source = await readFile(
      new URL("../src/cli/review-target.ts", import.meta.url),
      "utf8",
    );
    expect(source).not.toContain("TAVERNKEEPER_CHECKOUT_ROOT");
  });
});
