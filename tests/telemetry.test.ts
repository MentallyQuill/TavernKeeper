import { describe, expect, test } from "vitest";

import { buildTelemetry } from "../src/operations/telemetry.js";

function input() {
  return {
    runId: "run-1",
    startedAt: "2026-08-02T12:00:00.000Z",
    completedAt: "2026-08-02T12:30:00.000Z",
    queue: {
      desired: 12,
      pending: 5,
      active: 2,
      retrying: 1,
      blocked: 0,
      superseded: 1,
      oldestPendingAt: "2026-08-01T12:00:00.000Z",
    },
    scans: [
      {
        repositoryId: 42,
        outcome: "completed" as const,
        packageDigest: "a".repeat(64),
        candidates: 2,
        assessments: 2,
        observations: 1,
        recommendedRisk: { low: 1, material: 1, high: 1 },
        review: {
          provider: "nano-gpt.com",
          model: "deepseek/deepseek-v4-flash-0731:thinking",
          inputTokens: 12_000,
          outputTokens: 1_200,
          cacheReadTokens: 0,
          reasoningTokens: 800,
        },
        inventory: { files: 120, bytes: 48_000 },
        tools: { completed: 5, notApplicable: 2, failed: 0 },
      },
    ],
    scanners: [
      {
        name: "gitleaks",
        version: "8.30.1",
        status: "completed" as const,
        runtimeMs: 12_000,
      },
    ],
    retry: { scope: "system" as const, attempt: 2 },
    publication: {
      reportCommit: "b".repeat(40),
      pagesVerifiedAt: "2026-08-02T12:29:00.000Z",
      tavernaryWakeAt: "2026-08-02T12:30:00.000Z",
    },
    versions: {
      contract: "5" as const,
      scanner: "1.0.0",
      scannerPolicy: "2",
      ruleCatalog: "1",
      packageSchema: 1,
      contextualReviewPolicy: "1",
      ecosystemContext: "sillytavern-community-v1",
      prompt: "contextual-review-v1",
      assessmentSchema: "contextual-assessment-v1",
    },
  };
}

describe("deterministic scan telemetry", () => {
  test("records package, contextual review, inventory, and publication facts", () => {
    const telemetry = buildTelemetry(input());
    expect(telemetry).toMatchObject({
      schemaVersion: 2,
      scans: { completed: 1, repositoryFailed: 0, systemFailed: 0 },
      scanResults: [
        {
          repositoryId: 42,
          packageDigest: "a".repeat(64),
          candidates: 2,
          assessments: 2,
          observations: 1,
          recommendedRisk: { low: 1, material: 1, high: 1 },
          review: {
            provider: "nano-gpt.com",
            model: "deepseek/deepseek-v4-flash-0731:thinking",
            inputTokens: 12_000,
          },
          inventory: { files: 120, bytes: 48_000 },
          tools: { completed: 5, notApplicable: 2, failed: 0 },
        },
      ],
      throughput: { completedPerHour: 2 },
      publication: { reportCommit: "b".repeat(40) },
      versions: {
        contract: "5",
        scannerPolicy: "2",
        contextualReviewPolicy: "1",
        packageSchema: 1,
      },
    });
    expect(JSON.stringify(telemetry)).not.toMatch(
      /api[_-]?key|credential|raw_response/iu,
    );
  });

  test("strictly rejects raw model data and incomplete review coverage", () => {
    expect(() =>
      buildTelemetry({ ...input(), rawResponse: {} } as never),
    ).toThrow();
    expect(() =>
      buildTelemetry({
        ...input(),
        scans: [{ ...input().scans[0]!, assessments: 1 }],
      } as never),
    ).toThrow();
    expect(() =>
      buildTelemetry({
        ...input(),
        versions: { ...input().versions, promptPolicy: "old" },
      } as never),
    ).toThrow();
  });
});
