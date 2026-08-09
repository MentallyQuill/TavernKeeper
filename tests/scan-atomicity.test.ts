import { describe, expect, test } from "vitest";

import type { ScannerPolicyV4 } from "../src/config/policy.js";
import { ScanPackageV1Schema } from "../src/contracts/scan-package.js";
import type { Inventory } from "../src/inventory/inventory-handler.js";
import {
  scanRepository,
  type ScanDependencies,
  type ScanRepositorySpec,
} from "../src/orchestrator/scan-handler.js";
import type { CommandRunner } from "../src/process/command-runner.js";
import {
  normalizeFinding,
  ScannerError,
  type ScannerRun,
} from "../src/scanners/types.js";
import { JAVASCRIPT_ANALYSIS_VERSION } from "../src/scanners/javascript-analysis.js";

const targetSha = "a".repeat(40);
const sourceFile = {
  path: "README.md",
  bytes: 6,
  sha256: "b".repeat(64),
  kind: "text" as const,
};
const inventory: Inventory = {
  root: "C:/scan/repository",
  files: [sourceFile],
  totals: { files: 1, bytes: 6 },
  totalBytes: 6,
};
const policy: ScannerPolicyV4 = {
  version: "4",
  queue: { batchSize: 5, maxParallel: 2 },
  history: { maxCommits: 20 },
  inventory: {
    maxFiles: 500_000,
    maxTotalBytes: 5_368_709_120,
    maxFileBytes: 268_435_456,
    maxArchiveDepth: 4,
    maxExpandedArchiveBytes: 1_073_741_824,
    maxCompressionRatio: 200,
  },
  commands: { timeoutMs: 2_700_000, maxOutputBytes: 104_857_600 },
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
  retry: {
    modelReplyMinutesFromInitialFailure: [5, 10, 15],
    hoursFromInitialFailure: [1, 2, 3],
  },
};
const runner: CommandRunner = {
  async run() {
    throw new Error("Unexpected command invocation in isolated unit test.");
  },
};

function finding() {
  return normalizeFinding({
    origin: "tavernkeeper",
    ruleId: "credential-exfiltration",
    category: "credential-theft",
    severity: "high",
    confidence: "high",
    path: sourceFile.path,
    lineStart: 1,
    lineEnd: 1,
    evidenceSha: null,
    title: "Ignored scanner title",
    explanation: "Ignored scanner prose",
  });
}

function scannerRuns(withFinding = false): ScannerRun[] {
  return (
    [
      ["tavernkeeper-static", "4"],
      ["gitleaks", "8.30.1"],
      ["opengrep", "1.26.0"],
      ["javascript-analysis", JAVASCRIPT_ANALYSIS_VERSION],
      ["osv-scanner", "2.4.0"],
      ["zizmor", "1.28.0"],
      ["malcontent", "1.25.7"],
    ] as const
  ).map(([name, version]) => ({
    name,
    version,
    status: ["osv-scanner", "zizmor", "malcontent"].includes(name)
      ? "not-applicable"
      : "completed",
    findings: withFinding && name === "tavernkeeper-static" ? [finding()] : [],
    ...(name === "javascript-analysis"
      ? {
          javascriptAnalysis: {
            status: "complete" as const,
            candidates: 0,
            candidate_bytes: 0,
            representations: {
              raw: 0,
              decoded: 0,
              normalized: 0,
              bundle_modules: 0,
            },
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
        }
      : {}),
  }));
}

function spec(): ScanRepositorySpec {
  return {
    projectKinds: ["extension"],
    target: {
      source_id: "github-42",
      provider: "github",
      repository_id: 42,
      repository: "owner/repo",
      target_sha: targetSha,
      canonical_url: "https://github.com/owner/repo",
    },
    root: inventory.root,
    previousReportShas: [],
    scannerVersion: "1.0.0",
    scannerPolicyVersion: "4",
    ruleCatalogVersion: "1",
    policy,
    pins: {
      gitleaks: { version: "8.30.1" },
      opengrep: { version: "1.26.0" },
      osvScanner: { version: "2.4.0" },
      zizmor: { version: "1.28.0" },
      malcontent: { version: "1.25.7" },
    },
    rulesRoot: "C:/trusted/rules/opengrep",
    runner,
  };
}

function dependencies(withFinding = false): ScanDependencies {
  return {
    inventory: async () => ({ ok: true, value: inventory }),
    classify: () => ({
      firstPartyText: [sourceFile],
      applicability: { osv: false, zizmor: false, malcontent: false },
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
    }),
    history: async () => ({
      ok: true,
      value: { baseSha: null, historyCommits: 1, changedPaths: [] },
    }),
    structuralScan: async () => (withFinding ? [finding()] : []),
    scanners: async () => scannerRuns(withFinding),
    verifyHead: async () => ({ ok: true, value: targetSha }),
  };
}

describe("atomic deterministic repository evidence", () => {
  test("returns one schema-valid scan package after complete scanner coverage", async () => {
    const result = await scanRepository(spec(), dependencies());

    expect(result).toMatchObject({
      ok: true,
      value: {
        scanPackage: {
          schema_version: 1,
          findings: [],
        },
      },
    });
    expect(
      result.ok &&
        ScanPackageV1Schema.safeParse(result.value.scanPackage).success,
    ).toBe(true);
    expect(JSON.stringify(result)).not.toMatch(/model|prompt_policy|mode/iu);
  });

  test("preserves deterministic candidates without assigning public risk", async () => {
    const result = await scanRepository(spec(), dependencies(true));
    expect(result).toMatchObject({
      ok: true,
      value: {
        scanPackage: {
          findings: [{ rule_id: "credential-exfiltration", severity: "high" }],
        },
      },
    });
  });

  test("canonicalizes scanner coverage order", async () => {
    const reversed = dependencies();
    reversed.scanners = async () => scannerRuns().reverse();
    const result = await scanRepository(spec(), reversed);
    expect(
      result.ok
        ? result.value.scanPackage.tools.map(({ name }) => name)
        : result,
    ).toEqual([
      "inventory",
      "tavernkeeper-static",
      "gitleaks",
      "opengrep",
      "javascript-analysis",
      "osv-scanner",
      "zizmor",
      "malcontent",
    ]);
  });

  test.each([
    ["inventory totals", "INVENTORY_INVALID"],
    ["classification partition", "CLASSIFICATION_INVALID"],
    ["required scanner", "SCANNER_FAILED"],
    ["exact checkout head", "HEAD_MISMATCH"],
  ])("publishes no candidate when %s is incomplete", async (kind, code) => {
    const broken = dependencies();
    if (kind === "inventory totals")
      broken.inventory = async () => ({
        ok: true,
        value: { ...inventory, totals: { files: 0, bytes: 0 }, totalBytes: 0 },
      });
    if (kind === "classification partition") {
      const classify = broken.classify;
      broken.classify = (value) => ({
        ...classify(value),
        firstPartyText: [sourceFile, { ...sourceFile, path: "ghost.ts" }],
      });
    }
    if (kind === "required scanner")
      broken.scanners = async () => scannerRuns().slice(0, -1);
    if (kind === "exact checkout head")
      broken.verifyHead = async () => ({
        ok: false,
        error: { code: "HEAD_MISMATCH", message: "Head changed." },
      });

    const result = await scanRepository(spec(), broken);
    expect(result).toMatchObject({ ok: false, error: { code } });
    expect("value" in result).toBe(false);
  });

  test("preserves the failing scanner component for retry isolation", async () => {
    const broken = dependencies();
    broken.scanners = async () => {
      throw new ScannerError(
        "SCANNER_FAILED",
        "system",
        "OpenGrep failed for this repository.",
        "opengrep",
      );
    };

    const result = await scanRepository(spec(), broken);

    expect(result).toMatchObject({
      ok: false,
      error: {
        code: "SCANNER_FAILED",
        scope: "system",
        component: "opengrep",
      },
    });
  });
});
