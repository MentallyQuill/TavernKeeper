import { describe, expect, test } from "vitest";

import {
  ContextualReviewPolicySchema,
  loadContextualReviewPolicy,
  loadScannerPins,
  loadScannerPolicy,
  ScannerPinsSchema,
  ScannerPolicyV2Schema,
} from "../src/config/policy.js";

describe("deterministic scanner policy", () => {
  test("loads the versioned contextual review policy without a token budget", async () => {
    const policy = await loadContextualReviewPolicy(
      "config/contextual-review.v1.json",
    );
    expect(policy).toMatchObject({
      version: "1",
      promptVersion: "contextual-review-v1",
      schemaVersion: "contextual-assessment-v1",
      maxImmediateAttempts: 3,
    });
    expect(policy).not.toHaveProperty("tokenBudget");
    expect(
      ContextualReviewPolicySchema.safeParse({ ...policy, tokenBudget: 1 })
        .success,
    ).toBe(false);
  });

  test("loads V2 with bounded batches and no model policy", async () => {
    const policy = await loadScannerPolicy("config/scanner-policy.v2.json");
    expect(policy.version).toBe("2");
    expect(policy.queue).toEqual({ batchSize: 5, maxParallel: 2 });
    expect(policy.history.maxCommits).toBe(20);
    expect(policy).not.toHaveProperty("model");
    expect(
      ScannerPolicyV2Schema.safeParse({ ...policy, model: {} }).success,
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
    const policy = await loadScannerPolicy("config/scanner-policy.v2.json");
    const pins = await loadScannerPins("config/scanners.v1.json");
    expect(
      ScannerPolicyV2Schema.safeParse({
        ...policy,
        queue: { ...policy.queue, batchSize: 6 },
      }).success,
    ).toBe(false);
    expect(
      ScannerPolicyV2Schema.safeParse({ ...policy, tokenBudget: 1_000 })
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
