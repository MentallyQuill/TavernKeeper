import { describe, expect, test } from "vitest";

import {
  allowanceWarnings,
  buildTelemetry,
} from "../src/operations/telemetry.js";

describe("secret-free scan telemetry", () => {
  test("aggregates actual model usage without source or provider payloads", () => {
    const telemetry = buildTelemetry({
      runId: "run-1",
      startedAt: "2026-07-31T12:00:00.000Z",
      completedAt: "2026-07-31T12:30:00.000Z",
      queue: {
        desired: 12,
        pending: 5,
        active: 2,
        retrying: 1,
        blocked: 0,
        superseded: 1,
        oldestPendingAt: "2026-07-30T12:00:00.000Z",
      },
      scans: [
        {
          repositoryId: 42,
          outcome: "completed",
          chunks: 2,
          roles: {
            analyzer: { required: 2, completed: 2 },
            challenger: { required: 2, completed: 2 },
            arbiter: { required: 2, completed: 2 },
          },
          usage: {
            inputTokens: 1_200,
            outputTokens: 300,
            cacheReadTokens: 400,
            reasoningTokens: 90,
          },
        },
      ],
      scanners: [
        {
          name: "gitleaks",
          version: "8.30.1",
          status: "completed",
          runtimeMs: 12_000,
        },
        {
          name: "osv-scanner",
          version: "2.4.0",
          status: "not-applicable",
          runtimeMs: 0,
        },
      ],
      cache: { hits: 1, misses: 2 },
      retry: { scope: "system", attempt: 2 },
      publication: {
        reportCommit: "a".repeat(40),
        pagesVerifiedAt: "2026-07-31T12:29:00.000Z",
        tavernaryWakeAt: "2026-07-31T12:30:00.000Z",
      },
      versions: {
        contract: "1",
        scanner: "1.0.0",
        scannerPolicy: "1",
        promptPolicy: "1",
      },
    });

    expect(telemetry.model.usage).toEqual({
      inputTokens: 1_200,
      outputTokens: 300,
      cacheReadTokens: 400,
      reasoningTokens: 90,
    });
    expect(telemetry.model.chunks).toBe(2);
    expect(telemetry.model.roles).toEqual({
      analyzer: { required: 2, completed: 2 },
      challenger: { required: 2, completed: 2 },
      arbiter: { required: 2, completed: 2 },
    });
    expect(telemetry).toMatchObject({
      queue: {
        desired: 12,
        pending: 5,
        active: 2,
        retrying: 1,
        blocked: 0,
        superseded: 1,
        oldestPendingAgeMs: 88_200_000,
      },
      throughput: { completedPerHour: 2 },
      cache: { hits: 1, misses: 2 },
      retry: { scope: "system", attempt: 2 },
      publication: { reportCommit: "a".repeat(40) },
      versions: { scannerPolicy: "1", promptPolicy: "1" },
    });
    expect(JSON.stringify(telemetry)).not.toMatch(
      /target[_-]?source|prompt[_-]?(?:content|body|text)|api[_-]?key|credential|raw[_-]?response/iu,
    );
  });

  test("reports the highest reached allowance warning without imposing a cutoff", () => {
    expect(
      allowanceWarnings({ used: 45_000_000, allowance: 60_000_000 }),
    ).toEqual([75]);
    expect(
      allowanceWarnings({ used: 60_000_000, allowance: 60_000_000 }),
    ).toEqual([90]);
  });
});
