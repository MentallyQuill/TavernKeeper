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
const completedOpenGrep = (): ScannerRun => ({
  ...completed("opengrep"),
  pathCoverage: { scanned: [], skipped: [] },
});
const completedJavascriptAnalysis = (): ScannerRun => ({
  ...completed("javascript-analysis"),
  javascriptAnalysis: {
    status: "complete",
    candidates: 0,
    candidate_bytes: 0,
    representations: { raw: 0, decoded: 0, normalized: 0, bundle_modules: 0 },
    stages: {
      raw_signatures: 0,
      raw_ast: 0,
      raw_opengrep: 0,
      derived_signatures: 0,
      derived_ast: 0,
      derived_opengrep: 0,
    },
    unresolved: [],
  },
  evidenceHints: [],
  derivativeAncestry: [],
});

function classification(
  applicability: InventoryClassification["applicability"],
): InventoryClassification {
  return {
    firstPartyText: [],
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
  inventoryFiles: [],
  structuralFiles: [],
  runner,
  policy: {
    version: "4" as const,
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
    javascriptAnalysis: {
      maxCandidates: 10_000 as const,
      maxCandidateBytes: 536_870_912 as const,
      maxTransformInputBytes: 16_777_216 as const,
      transformTimeoutMs: 30_000 as const,
      maxWorkerOldGenerationMb: 512 as const,
      maxDerivativeBytes: 16_777_216 as const,
      maxDerivativeBytesPerCandidate: 67_108_864 as const,
      maxTotalDerivativeBytes: 268_435_456 as const,
      maxDerivativesPerCandidate: 64 as const,
      maxRecursionDepth: 3 as const,
      maxDecodedLiteralsPerRepresentation: 256 as const,
      maxEvidenceCharactersPerFinding: 24_000 as const,
      maxPreparedEvidenceBytes: 20_000_000 as const,
      analysisTimeoutMs: 1_200_000 as const,
    },
    retry: {
      modelReplyMinutesFromInitialFailure: [5, 10, 15] as [5, 10, 15],
      hoursFromInitialFailure: [1, 2, 3] as [1, 2, 3],
    },
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
  test("runs JavaScript analysis after repository OpenGrep and records conditional absence", async () => {
    const adapters = {
      staticScan: vi.fn(() => []),
      gitleaks: vi.fn(async () => completed("gitleaks")),
      opengrep: vi.fn(async () => completedOpenGrep()),
      javascriptAnalysis: vi.fn(async () => completedJavascriptAnalysis()),
      osv: vi.fn(async () => notApplicable("osv-scanner")),
      zizmor: vi.fn(async () => notApplicable("zizmor")),
      malcontent: vi.fn(async () => notApplicable("malcontent")),
    };

    const runs = await runApplicableScanners(baseSpec, adapters);

    expect(runs.map(({ name, status }) => [name, status])).toEqual([
      ["tavernkeeper-static", "completed"],
      ["gitleaks", "completed"],
      ["opengrep", "completed"],
      ["javascript-analysis", "completed"],
      ["osv-scanner", "not-applicable"],
      ["zizmor", "not-applicable"],
      ["malcontent", "not-applicable"],
    ]);
    expect(adapters.staticScan).toHaveBeenCalledOnce();
    expect(adapters.gitleaks).toHaveBeenCalledOnce();
    expect(adapters.opengrep).toHaveBeenCalledOnce();
    expect(adapters.javascriptAnalysis).toHaveBeenCalledOnce();
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
      javascriptAnalysis: vi.fn(async () => completedJavascriptAnalysis()),
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

  test("attributes an untyped adapter failure to the scanner and repository", async () => {
    const adapters = {
      staticScan: vi.fn(() => []),
      gitleaks: vi.fn(async () => completed("gitleaks")),
      opengrep: vi.fn(async () => {
        throw new Error("spawn exploded with an internal path");
      }),
      javascriptAnalysis: vi.fn(async () => completedJavascriptAnalysis()),
      osv: vi.fn(async () => notApplicable("osv-scanner")),
      zizmor: vi.fn(async () => notApplicable("zizmor")),
      malcontent: vi.fn(async () => notApplicable("malcontent")),
    };

    await expect(runApplicableScanners(baseSpec, adapters)).rejects.toEqual(
      expect.objectContaining({
        name: "ScannerError",
        code: "SCANNER_FAILED",
        scope: "repository",
        component: "opengrep",
        message: "OpenGrep failed for this repository.",
      }),
    );
  });

  test("attributes an untyped Gitleaks failure to the scanner and repository", async () => {
    const adapters = {
      staticScan: vi.fn(() => []),
      gitleaks: vi.fn(async () => {
        throw new Error("raw Gitleaks failure");
      }),
      opengrep: vi.fn(async () => completedOpenGrep()),
      javascriptAnalysis: vi.fn(async () => completedJavascriptAnalysis()),
      osv: vi.fn(async () => notApplicable("osv-scanner")),
      zizmor: vi.fn(async () => notApplicable("zizmor")),
      malcontent: vi.fn(async () => notApplicable("malcontent")),
    };

    await expect(
      runApplicableScanners(baseSpec, adapters),
    ).rejects.toMatchObject({
      code: "SCANNER_FAILED",
      scope: "repository",
      component: "gitleaks",
      message: "Gitleaks failed for this repository.",
    });
  });

  test("attributes an untyped OSV failure to the scanner and repository", async () => {
    const adapters = {
      staticScan: vi.fn(() => []),
      gitleaks: vi.fn(async () => completed("gitleaks")),
      opengrep: vi.fn(async () => completedOpenGrep()),
      javascriptAnalysis: vi.fn(async () => completedJavascriptAnalysis()),
      osv: vi.fn(async () => {
        throw new Error("raw OSV failure");
      }),
      zizmor: vi.fn(async () => notApplicable("zizmor")),
      malcontent: vi.fn(async () => notApplicable("malcontent")),
    };

    await expect(
      runApplicableScanners(baseSpec, adapters),
    ).rejects.toMatchObject({
      code: "SCANNER_FAILED",
      scope: "repository",
      component: "osv-scanner",
      message: "OSV-Scanner failed for this repository.",
    });
  });

  test("attributes an untyped zizmor failure to the scanner and repository", async () => {
    const adapters = {
      staticScan: vi.fn(() => []),
      gitleaks: vi.fn(async () => completed("gitleaks")),
      opengrep: vi.fn(async () => completedOpenGrep()),
      javascriptAnalysis: vi.fn(async () => completedJavascriptAnalysis()),
      osv: vi.fn(async () => notApplicable("osv-scanner")),
      zizmor: vi.fn(async () => {
        throw new Error("raw zizmor failure");
      }),
      malcontent: vi.fn(async () => notApplicable("malcontent")),
    };

    await expect(
      runApplicableScanners(baseSpec, adapters),
    ).rejects.toMatchObject({
      code: "SCANNER_FAILED",
      scope: "repository",
      component: "zizmor",
      message: "zizmor failed for this repository.",
    });
  });

  test("attributes an untyped malcontent failure to the scanner and repository", async () => {
    const adapters = {
      staticScan: vi.fn(() => []),
      gitleaks: vi.fn(async () => completed("gitleaks")),
      opengrep: vi.fn(async () => completedOpenGrep()),
      javascriptAnalysis: vi.fn(async () => completedJavascriptAnalysis()),
      osv: vi.fn(async () => notApplicable("osv-scanner")),
      zizmor: vi.fn(async () => notApplicable("zizmor")),
      malcontent: vi.fn(async () => {
        throw new Error("raw malcontent failure");
      }),
    };

    await expect(
      runApplicableScanners(baseSpec, adapters),
    ).rejects.toMatchObject({
      code: "SCANNER_FAILED",
      scope: "repository",
      component: "malcontent",
      message: "malcontent failed for this repository.",
    });
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
      opengrep: vi.fn(async () => completedOpenGrep()),
      javascriptAnalysis: vi.fn(async () => completedJavascriptAnalysis()),
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
