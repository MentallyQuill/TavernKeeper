import { describe, expect, test } from "vitest";

import {
  loadScannerPins,
  loadScannerPolicy,
  ScannerPinsSchema,
  ScannerPolicySchema,
} from "../src/config/policy.js";

describe("versioned scanner policy", () => {
  test("loads V1 with five-target batches and two concurrent scans", async () => {
    const policy = await loadScannerPolicy("config/scanner-policy.v1.json");

    expect(policy.version).toBe("1");
    expect(policy.queue).toEqual({ batchSize: 5, maxParallel: 2 });
    expect(policy.history.maxCommits).toBe(20);
    expect(policy.model.protocol).toBe("openai-compatible-chat-completions");
    expect(policy.model).not.toHaveProperty("provider");
    expect(policy.model).not.toHaveProperty("id");
    expect("aggregateRepositoryTokenCap" in policy.model).toBe(false);
  });

  test("loads exact reviewed scanner provenance pins", async () => {
    const pins = await loadScannerPins("config/scanners.v1.json");

    expect(pins).toEqual({
      gitleaks: {
        version: "8.30.1",
        url: "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz",
        sha256:
          "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb",
      },
      opengrep: {
        version: "1.26.0",
        url: "https://github.com/opengrep/opengrep/releases/download/v1.26.0/opengrep_manylinux_x86",
        sha256:
          "40c21299eeddabf743b856daa843d24f9d4a027130671cd45b3b21776fd9ab26",
      },
      osvScanner: {
        version: "2.4.0",
        url: "https://github.com/google/osv-scanner/releases/download/v2.4.0/osv-scanner_linux_amd64",
        sha256:
          "15314940c10d26af9c6649f150b8a47c1262e8fc7e17b1d1029b0e479e8ed8a0",
      },
      zizmor: {
        version: "1.28.0",
        url: "https://github.com/zizmorcore/zizmor/releases/download/v1.28.0/zizmor-x86_64-unknown-linux-gnu.tar.gz",
        sha256:
          "e87b67160194884e375a46a12c57ccc904f762b53845f254fab7f17d98809c09",
      },
      malcontent: {
        version: "1.25.7",
        image:
          "cgr.dev/chainguard/malcontent@sha256:8c976e9536ded51e277f57946bb11e5ecd16989d1f767c5c2f1423722f5c0138",
      },
    });
  });

  test("rejects policy drift, unknown fields, and malformed pins", async () => {
    const policy = await loadScannerPolicy("config/scanner-policy.v1.json");
    const pins = await loadScannerPins("config/scanners.v1.json");

    expect(
      ScannerPolicySchema.safeParse({
        ...policy,
        queue: { ...policy.queue, batchSize: 6 },
      }).success,
    ).toBe(false);
    expect(
      ScannerPolicySchema.safeParse({ ...policy, tokenBudget: 1_000 }).success,
    ).toBe(false);
    expect(
      ScannerPolicySchema.safeParse({
        ...policy,
        retry: { hoursFromInitialFailure: [1, 2] },
      }).success,
    ).toBe(false);
    expect(
      ScannerPinsSchema.safeParse({
        ...pins,
        gitleaks: { ...pins.gitleaks, sha256: "abc" },
      }).success,
    ).toBe(false);
  });
});
