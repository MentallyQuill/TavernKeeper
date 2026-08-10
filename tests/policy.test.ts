import { describe, expect, test } from "vitest";

import * as policyModule from "../src/config/policy.js";
import {
  ContextualReviewPolicySchema,
  CURRENT_SCANNER_POLICY_PATH,
  CURRENT_SCANNER_POLICY_VERSION,
  loadContextualReviewPolicy,
  loadScannerPins,
  loadScannerPolicy,
  ScannerPinsSchema,
  ScannerPolicyV3Schema,
} from "../src/config/policy.js";

describe("deterministic scanner policy", () => {
  test("names policy 4 as the single current scanner policy", async () => {
    expect(CURRENT_SCANNER_POLICY_VERSION).toBe("4");
    expect(CURRENT_SCANNER_POLICY_PATH).toBe("config/scanner-policy.v4.json");
    expect((await loadScannerPolicy(CURRENT_SCANNER_POLICY_PATH)).version).toBe(
      CURRENT_SCANNER_POLICY_VERSION,
    );
  });

  test("loads exact policy 4 JavaScript limits", async () => {
    expect(
      (policyModule as Record<string, unknown>).ScannerPolicyV4Schema,
    ).toBeDefined();
    const policy = await loadScannerPolicy("config/scanner-policy.v4.json");
    expect(policy).toMatchObject({
      version: "4",
      javascriptAnalysis: {
        maxCandidates: 10_000,
        maxCandidateBytes: 536_870_912,
        maxTransformInputBytes: 16_777_216,
        transformTimeoutMs: 30_000,
        maxWorkerOldGenerationMb: 512,
        maxDerivativeBytes: 16_777_216,
        maxDerivativeBytesPerCandidate: 67_108_864,
        maxTotalDerivativeBytes: 268_435_456,
        maxDerivativesPerCandidate: 64,
        maxRecursionDepth: 3,
        maxDecodedLiteralsPerRepresentation: 256,
        maxEvidenceCharactersPerFinding: 24_000,
        maxPreparedEvidenceBytes: 20_000_000,
        analysisTimeoutMs: 1_200_000,
      },
    });
  });

  test("loads the versioned contextual review policy with bounded batches", async () => {
    expect(
      (policyModule as Record<string, unknown>)
        .CURRENT_CONTEXTUAL_REVIEW_POLICY_VERSION,
    ).toBe("4");
    const policy = await loadContextualReviewPolicy(
      "config/contextual-review.v4.json",
    );
    expect(policy).toMatchObject({
      version: "4",
      promptVersion: "contextual-review-v7",
      schemaVersion: "contextual-assessment-v2",
      maxImmediateAttempts: 3,
      timeoutMs: 300_000,
      maxBatchGroups: 5,
      maxBatchInputTokens: 64_000,
    });
    expect(policy).not.toHaveProperty("tokenBudget");
    expect(
      ContextualReviewPolicySchema.safeParse({ ...policy, tokenBudget: 1 })
        .success,
    ).toBe(false);
  });

  test("loads V3 with bounded batches and no model policy", async () => {
    const policy = await loadScannerPolicy("config/scanner-policy.v3.json");
    expect(policy.version).toBe("3");
    expect(policy.queue).toEqual({ batchSize: 5, maxParallel: 2 });
    expect(policy.history.maxCommits).toBe(20);
    expect(policy.retry).toEqual({
      modelReplyMinutesFromInitialFailure: [5, 10, 15],
      hoursFromInitialFailure: [1, 2, 3],
    });
    expect(policy).not.toHaveProperty("model");
    expect(
      ScannerPolicyV3Schema.safeParse({ ...policy, model: {} }).success,
    ).toBe(false);
  });

  test("loads exact reviewed scanner provenance pins", async () => {
    const pins = await loadScannerPins("config/scanners.v1.json");
    expect(pins.gitleaks).toMatchObject({ version: "8.30.1" });
    expect(pins.opengrep).toMatchObject({ version: "1.26.0" });
    expect(pins.osvScanner).toMatchObject({ version: "2.4.0" });
    expect(pins.zizmor).toMatchObject({ version: "1.28.0" });
    expect(pins.malcontent).toMatchObject({ version: "1.25.7" });
  });

  test("rejects policy drift, unknown fields, and malformed pins", async () => {
    const policy = await loadScannerPolicy("config/scanner-policy.v3.json");
    const pins = await loadScannerPins("config/scanners.v1.json");
    expect(
      ScannerPolicyV3Schema.safeParse({
        ...policy,
        queue: { ...policy.queue, batchSize: 6 },
      }).success,
    ).toBe(false);
    expect(
      ScannerPolicyV3Schema.safeParse({ ...policy, tokenBudget: 1_000 })
        .success,
    ).toBe(false);
    expect(
      ScannerPinsSchema.safeParse({
        ...pins,
        gitleaks: { ...pins.gitleaks, sha256: "abc" },
      }).success,
    ).toBe(false);
  });
});
