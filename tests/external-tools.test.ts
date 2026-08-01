import { describe, expect, test, vi } from "vitest";

import type { InventoryClassification } from "../src/inventory/classify.js";
import { runApplicableScanners } from "../src/scanners/run-scanners.js";
import { ScannerError, type ScannerRun } from "../src/scanners/types.js";
import { normalizeFinding } from "../src/scanners/types.js";
import type { CommandRunner } from "../src/process/command-runner.js";

const completed = (name: string): ScannerRun => ({
  name,
  version: "1.0.0",
  status: "completed",
  findings: [],
});
const notApplicable = (name: string): ScannerRun => ({
  name,
  version: "1.0.0",
  status: "not-applicable",
  findings: [],
});

function classification(
  applicability: InventoryClassification["applicability"],
): InventoryClassification {
  return {
    modelEligible: [],
    applicability,
    scannerInputs: { osv: [], zizmor: [], malcontent: [] },
    excluded: {
      dependency_lockfiles: { files: 0, bytes: 0 },
      vendored_dependencies: { files: 0, bytes: 0 },
      generated_bundles: { files: 0, bytes: 0 },
      minified_files: { files: 0, bytes: 0 },
      binaries: { files: 0, bytes: 0 },
      archives: { files: 0, bytes: 0 },
      oversized_files: { files: 0, bytes: 0 },
      unsafe_entries: { files: 0, bytes: 0 },
    },
  };
}

const runner = {} as CommandRunner;
const baseSpec = {
  root: "C:/scan/repository",
  history: {
    baseSha: null,
    targetSha: "a".repeat(40),
    commits: 1,
  },
  classification: classification({
    osv: false,
    zizmor: false,
    malcontent: false,
  }),
  structuralFiles: [],
  runner,
  policy: {
    version: "1" as const,
    queue: { batchSize: 5 as const, maxParallel: 2 as const },
    history: { maxCommits: 20 as const },
    inventory: {
      maxFiles: 500_000 as const,
      maxTotalBytes: 5_368_709_120 as const,
      maxFileBytes: 268_435_456 as const,
      maxArchiveDepth: 4 as const,
      maxExpandedArchiveBytes: 1_073_741_824 as const,
      maxCompressionRatio: 200 as const,
    },
    commands: {
      timeoutMs: 2_700_000 as const,
      maxOutputBytes: 104_857_600 as const,
    },
    model: {
      protocol: "openai-compatible-chat-completions" as const,
      chunkBytes: 524_288 as const,
      chunkOverlapBytes: 8_192 as const,
      maxOutputTokensPerRole: 8_192 as const,
      rolePolicies: {
        analyzer: "analyzer-v1" as const,
        challenger: "challenger-v1" as const,
        arbiter: "arbiter-v1" as const,
      },
    },
    retry: { hoursFromInitialFailure: [1, 2, 3] as [1, 2, 3] },
  },
  pins: {
    gitleaks: { version: "8.30.1" as const },
    opengrep: { version: "1.26.0" as const },
    osvScanner: { version: "2.4.0" as const },
    zizmor: { version: "1.28.0" as const },
    malcontent: { version: "1.25.7" as const },
  },
  rulesRoot: "C:/trusted/rules/opengrep",
};

describe("scanner coordinator", () => {
  test("always runs structural, Gitleaks, and OpenGrep and records conditional absence", async () => {
    const adapters = {
      staticScan: vi.fn(() => []),
      gitleaks: vi.fn(async () => completed("gitleaks")),
      opengrep: vi.fn(async () => completed("opengrep")),
      osv: vi.fn(async () => notApplicable("osv-scanner")),
      zizmor: vi.fn(async () => notApplicable("zizmor")),
      malcontent: vi.fn(async () => notApplicable("malcontent")),
    };

    const runs = await runApplicableScanners(baseSpec, adapters);

    expect(runs.map(({ name, status }) => [name, status])).toEqual([
      ["tavernkeeper-static", "completed"],
      ["gitleaks", "completed"],
      ["opengrep", "completed"],
      ["osv-scanner", "not-applicable"],
      ["zizmor", "not-applicable"],
      ["malcontent", "not-applicable"],
    ]);
    expect(adapters.staticScan).toHaveBeenCalledOnce();
    expect(adapters.gitleaks).toHaveBeenCalledOnce();
    expect(adapters.opengrep).toHaveBeenCalledOnce();
  });

  test("propagates required scanner failures instead of returning partial coverage", async () => {
    const adapters = {
      staticScan: vi.fn(() => []),
      gitleaks: vi.fn(async () => completed("gitleaks")),
      opengrep: vi.fn(async () => {
        throw new ScannerError(
          "SCANNER_UNAVAILABLE",
          "system",
          "OpenGrep could not be started.",
        );
      }),
      osv: vi.fn(async () => notApplicable("osv-scanner")),
      zizmor: vi.fn(async () => notApplicable("zizmor")),
      malcontent: vi.fn(async () => notApplicable("malcontent")),
    };

    await expect(
      runApplicableScanners(baseSpec, adapters),
    ).rejects.toMatchObject({
      code: "SCANNER_UNAVAILABLE",
      scope: "system",
    });
    expect(adapters.osv).not.toHaveBeenCalled();
    expect(adapters.zizmor).not.toHaveBeenCalled();
    expect(adapters.malcontent).not.toHaveBeenCalled();
  });

  test("uses precomputed structural findings without retaining source files", async () => {
    const structuralFinding = normalizeFinding({
      origin: "tavernkeeper",
      ruleId: "unicode-bidi-control",
      category: "obfuscation",
      severity: "medium",
      confidence: "medium",
      path: "src/index.ts",
      lineStart: 1,
      lineEnd: 1,
      evidenceSha: null,
      title: "Bidirectional control",
      explanation: "A bidirectional control requires review.",
    });
    const adapters = {
      staticScan: vi.fn(() => {
        throw new Error("Source-retaining path must not run.");
      }),
      gitleaks: vi.fn(async () => completed("gitleaks")),
      opengrep: vi.fn(async () => completed("opengrep")),
      osv: vi.fn(async () => notApplicable("osv-scanner")),
      zizmor: vi.fn(async () => notApplicable("zizmor")),
      malcontent: vi.fn(async () => notApplicable("malcontent")),
    };

    const runs = await runApplicableScanners(
      { ...baseSpec, structuralFindings: [structuralFinding] },
      adapters,
    );

    expect(runs[0]?.findings).toEqual([structuralFinding]);
    expect(adapters.staticScan).not.toHaveBeenCalled();
  });
});
