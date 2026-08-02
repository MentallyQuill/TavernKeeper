import { describe, expect, test } from "vitest";

import type { ScannerPolicy } from "../src/config/policy.js";
import { ScanReportV2Schema } from "../src/contracts/reports.js";
import type { Inventory } from "../src/inventory/inventory-handler.js";
import { InMemoryModelChunkCache } from "../src/model/chunk-cache.js";
import { ModelRequestError } from "../src/model/openai-compatible-client.js";
import {
  scanRepository,
  type ScanDependencies,
  type ScanRepositorySpec,
} from "../src/orchestrator/scan-handler.js";
import type { CommandRunner } from "../src/process/command-runner.js";
import { ScannerError, type ScannerRun } from "../src/scanners/types.js";

const targetSha = "a".repeat(40);
const helloHash =
  "5891b5b522d5df086d0ff0b110fbd9d21bb4fc7163af34d08286a2e846f6be03";
const unselectedHash =
  "033d67aa2f93fa6a46495bf89d759a6721b7ef4f0c8b1aa13212784e357d51a3";
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
const policy: ScannerPolicy = {
  version: "1",
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
  model: {
    protocol: "openai-compatible-chat-completions",
    chunkBytes: 524_288,
    chunkOverlapBytes: 8_192,
    maxOutputTokensPerRole: 8_192,
    rolePolicies: {
      analyzer: "analyzer-v1",
      challenger: "challenger-v1",
      arbiter: "arbiter-v1",
    },
  },
  retry: { hoursFromInitialFailure: [1, 2, 3] },
};
const runner: CommandRunner = {
  async run() {
    throw new Error("Unexpected command invocation in isolated unit test.");
  },
};

const scannerRuns: ScannerRun[] = (
  [
    ["tavernkeeper-static", "1"],
    ["gitleaks", "8.30.1"],
    ["opengrep", "1.26.0"],
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
  findings: [],
}));

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
    completedAt: "2026-07-31T12:05:00.000Z",
    scannerVersion: "1.0.0",
    scannerPolicyVersion: "1",
    promptPolicyVersion: "1",
    reportVersion: 1,
    supersedesReportId: null,
    mode: "standard",
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
    model: {
      endpoint: "https://provider.example/v1/chat/completions",
      apiKey: "test-key",
      identifier: "vendor/model-test",
      cache: new InMemoryModelChunkCache(),
    },
  };
}

function dependencies(): ScanDependencies {
  return {
    inventory: async () => ({ ok: true, value: inventory }),
    classify: () => ({
      modelEligible: [sourceFile],
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
      value: {
        baseSha: null,
        historyCommits: 1,
        changedPaths: [sourceFile.path],
      },
    }),
    structuralScan: async () => [],
    scanners: async () => scannerRuns,
    loadCorpus: async () => [{ ...sourceFile, content: "hello\n" }],
    chunk: () => [
      {
        id: "c".repeat(64),
        bytes: 6,
        content_hashes: [helloHash],
        segments: [
          {
            path: sourceFile.path,
            line_start: 1,
            line_end: 1,
            content: "hello\n",
            bytes: 6,
            overlap_bytes: 0,
            content_hash: helloHash,
            source_sha256: sourceFile.sha256,
          },
        ],
      },
    ],
    verifyHead: async () => ({ ok: true, value: targetSha }),
    review: async () => ({
      endpointOrigin: "https://provider.example",
      provider: "provider.example",
      model: "vendor/model-test",
      findings: [],
      completedChunkIds: ["c".repeat(64)],
      roleCompletion: {
        analyzer: { required: 1, completed: 1 },
        challenger: { required: 1, completed: 1 },
        arbiter: { required: 1, completed: 1 },
      },
      cacheHits: 0,
      cacheMisses: 3,
      usage: {
        inputTokens: 100,
        outputTokens: 20,
        cacheReadTokens: 10,
        reasoningTokens: 5,
      },
    }),
  };
}

describe("atomic repository scan", () => {
  test("returns one schema-valid candidate only after complete coverage", async () => {
    const result = await scanRepository(spec(), dependencies());

    expect(result).toMatchObject({
      ok: true,
      value: {
        report: {
          result: "teal",
          coverage: {
            model: {
              status: "completed",
              input_chunks: 1,
              completed_chunks: 1,
            },
          },
        },
      },
    });
    expect(
      result.ok && ScanReportV2Schema.safeParse(result.value.report).success,
    ).toBe(true);
  });

  test("canonicalizes scanner coverage order", async () => {
    const reversedDependencies = dependencies();
    reversedDependencies.scanners = async () => [...scannerRuns].reverse();

    const result = await scanRepository(spec(), reversedDependencies);

    expect(
      result.ok
        ? result.value.report.coverage.tools.map(({ name }) => name)
        : result,
    ).toEqual([
      "inventory",
      "tavernkeeper-static",
      "gitleaks",
      "opengrep",
      "osv-scanner",
      "zizmor",
      "malcontent",
    ]);
  });

  test("rejects missing model configuration before repository work", async () => {
    const unconfigured = spec();
    unconfigured.model.apiKey = null;
    let inventoryCalled = false;
    const untouchedDependencies = dependencies();
    untouchedDependencies.inventory = async () => {
      inventoryCalled = true;
      return { ok: true, value: inventory };
    };

    const result = await scanRepository(unconfigured, untouchedDependencies);

    expect(result).toMatchObject({
      ok: false,
      error: { code: "INVALID_SCAN_SPEC", scope: "system" },
    });
    expect(inventoryCalled).toBe(false);
  });

  test("publishes no candidate when inventory totals are internally inconsistent", async () => {
    const unsafeDependencies = dependencies();
    unsafeDependencies.inventory = async () => ({
      ok: true,
      value: {
        ...inventory,
        totals: { files: 0, bytes: 0 },
        totalBytes: 0,
      },
    });

    const result = await scanRepository(spec(), unsafeDependencies);

    expect(result).toMatchObject({
      ok: false,
      error: { code: "INVENTORY_INVALID", scope: "system" },
    });
    expect("value" in result).toBe(false);
  });

  test("publishes no candidate when classification does not partition inventory", async () => {
    const unsafeDependencies = dependencies();
    const classify = unsafeDependencies.classify;
    unsafeDependencies.classify = (classifiedInventory) => ({
      ...classify(classifiedInventory),
      modelEligible: [
        sourceFile,
        {
          path: "ghost.ts",
          bytes: 10,
          sha256: "8".repeat(64),
          kind: "text",
        },
      ],
    });

    const result = await scanRepository(spec(), unsafeDependencies);

    expect(result).toMatchObject({
      ok: false,
      error: { code: "CLASSIFICATION_INVALID", scope: "system" },
    });
    expect("value" in result).toBe(false);
  });

  test("publishes no candidate when a chunk contains unselected source", async () => {
    const unsafeDependencies = dependencies();
    unsafeDependencies.chunk = () => [
      {
        id: "c".repeat(64),
        bytes: 18,
        content_hashes: [helloHash, unselectedHash],
        segments: [
          {
            path: sourceFile.path,
            line_start: 1,
            line_end: 1,
            content: "hello\n",
            bytes: 6,
            overlap_bytes: 0,
            content_hash: helloHash,
            source_sha256: sourceFile.sha256,
          },
          {
            path: "vendor/secret.ts",
            line_start: 1,
            line_end: 1,
            content: "unselected\n",
            bytes: 11,
            overlap_bytes: 0,
            content_hash: unselectedHash,
            source_sha256: "f".repeat(64),
          },
        ],
      },
    ];

    const result = await scanRepository(spec(), unsafeDependencies);

    expect(result).toMatchObject({
      ok: false,
      error: { code: "MODEL_INVALID_RESPONSE", scope: "repository" },
    });
    expect("value" in result).toBe(false);
  });

  test("returns no value for scanner, model, or candidate failures", async () => {
    const cases: Array<{
      name: string;
      expectedCode: string;
      expectedScope: "repository" | "system";
      mutate(dependencies: ScanDependencies): void;
    }> = [
      {
        name: "missing required tool",
        expectedCode: "SCANNER_UNAVAILABLE",
        expectedScope: "system",
        mutate(deps) {
          deps.scanners = async () => {
            throw new ScannerError(
              "SCANNER_UNAVAILABLE",
              "system",
              "OpenGrep could not be started.",
            );
          };
        },
      },
      {
        name: "malformed coverage set",
        expectedCode: "SCANNER_FAILED",
        expectedScope: "system",
        mutate(deps) {
          deps.scanners = async () => scannerRuns.slice(0, -1);
        },
      },
      {
        name: "scanner version mismatch",
        expectedCode: "SCANNER_FAILED",
        expectedScope: "system",
        mutate(deps) {
          deps.scanners = async () =>
            scannerRuns.map((run) =>
              run.name === "gitleaks"
                ? { ...run, version: "unexpected-version" }
                : run,
            );
        },
      },
      {
        name: "model quota",
        expectedCode: "MODEL_QUOTA",
        expectedScope: "system",
        mutate(deps) {
          deps.review = async () => {
            throw new ModelRequestError(
              "MODEL_QUOTA",
              "system",
              "Configured model quota is unavailable.",
            );
          };
        },
      },
      {
        name: "incomplete model coverage",
        expectedCode: "MODEL_INVALID_RESPONSE",
        expectedScope: "repository",
        mutate(deps) {
          const complete = deps.review;
          deps.review = async (reviewSpec) => ({
            ...(await complete(reviewSpec)),
            completedChunkIds: [],
          });
        },
      },
      {
        name: "schema-invalid candidate",
        expectedCode: "REPORT_INVALID",
        expectedScope: "system",
        mutate(deps) {
          const complete = deps.review;
          deps.review = async (reviewSpec) => ({
            ...(await complete(reviewSpec)),
            findings: [
              {
                origin: "model:provider-example",
                rule_id: "invalid-path",
                category: "credential-theft",
                severity: "high",
                confidence: "high",
                path: "../outside.ts",
                line_start: 1,
                line_end: 1,
                evidence_sha: null,
                title: "Invalid path",
                explanation: "This finding must fail report validation.",
                fingerprint: "9".repeat(64),
                disposition: "confirmed",
                automated_review: {
                  analyzer_policy: "analyzer-v1",
                  challenger_policy: "challenger-v1",
                  arbiter_policy: "arbiter-v1",
                },
              },
            ],
          });
        },
      },
    ];

    for (const failureCase of cases) {
      const failingDependencies = dependencies();
      failureCase.mutate(failingDependencies);
      const result = await scanRepository(spec(), failingDependencies);
      expect(result, failureCase.name).toMatchObject({
        ok: false,
        error: {
          code: failureCase.expectedCode,
          scope: failureCase.expectedScope,
        },
      });
      expect("value" in result, failureCase.name).toBe(false);
    }
  });
});
