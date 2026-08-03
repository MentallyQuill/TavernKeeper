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
        result: "red" as const,
        findings: 2,
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
      contract: "4",
      scanner: "1.0.0",
      scannerPolicy: "2",
      ruleCatalog: "1",
      packageSchema: 1,
    },
  };
}

describe("deterministic scan telemetry", () => {
  test("records package, scanner, inventory, result, and publication facts", () => {
    const telemetry = buildTelemetry(input());
    expect(telemetry).toMatchObject({
      schemaVersion: 2,
      scans: { completed: 1, repositoryFailed: 0, systemFailed: 0 },
      scanResults: [
        {
          repositoryId: 42,
          packageDigest: "a".repeat(64),
          result: "red",
          findings: 2,
          inventory: { files: 120, bytes: 48_000 },
          tools: { completed: 5, notApplicable: 2, failed: 0 },
        },
      ],
      throughput: { completedPerHour: 2 },
      publication: { reportCommit: "b".repeat(40) },
      versions: { scannerPolicy: "2", ruleCatalog: "1", packageSchema: 1 },
    });
    expect(JSON.stringify(telemetry)).not.toMatch(
      /model|usage|cache|prompt|chunk|token|api[_-]?key|credential/iu,
    );
  });

  test("strictly rejects former model and cache telemetry", () => {
    expect(() => buildTelemetry({ ...input(), model: {} } as never)).toThrow();
    expect(() => buildTelemetry({ ...input(), cache: {} } as never)).toThrow();
    expect(() =>
      buildTelemetry({
        ...input(),
        versions: { ...input().versions, promptPolicy: "old" },
      } as never),
    ).toThrow();
  });
});
