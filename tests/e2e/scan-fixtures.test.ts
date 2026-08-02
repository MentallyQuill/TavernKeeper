import { access, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, test } from "vitest";

import {
  loadScannerPins,
  loadScannerPolicy,
  type ScannerPolicy,
} from "../../src/config/policy.js";
import type { Finding } from "../../src/contracts/reports.js";
import { classifyInventory } from "../../src/inventory/classify.js";
import { inventoryRepository } from "../../src/inventory/inventory-handler.js";
import { InMemoryModelChunkCache } from "../../src/model/chunk-cache.js";
import { chunkCorpus } from "../../src/model/chunker.js";
import { loadModelCorpus } from "../../src/model/corpus.js";
import { buildEvidenceManifest } from "../../src/model/evidence-manifest.js";
import { initialOperationsState } from "../../src/operations/state.js";
import {
  scanRepository,
  scanStructuralFiles,
  type ScanDependencies,
  type ScanRepositorySpec,
} from "../../src/orchestrator/scan-handler.js";
import type { CommandRunner } from "../../src/process/command-runner.js";
import { publishCandidates } from "../../src/publish/publisher.js";
import { reportPath } from "../../src/publish/report-path.js";
import { buildSite } from "../../src/site/build-site.js";
import type { ScannerRun } from "../../src/scanners/types.js";

const repositoryRoot = dirname(
  dirname(dirname(fileURLToPath(import.meta.url))),
);
const fixtureRoot = join(repositoryRoot, "tests", "fixtures");
const targetSha = "a".repeat(40);
const completedAt = "2026-07-31T18:00:00.000Z";
const temporaryRoots: string[] = [];

const runner: CommandRunner = {
  async run() {
    throw new Error("Hostile fixture attempted to execute a command.");
  },
};

afterEach(async () => {
  await Promise.all(
    temporaryRoots
      .splice(0)
      .map((root) => rm(root, { recursive: true, force: true })),
  );
});

async function doesNotExist(path: string) {
  try {
    await access(path);
    return false;
  } catch (error) {
    if (
      error !== null &&
      typeof error === "object" &&
      "code" in error &&
      error.code === "ENOENT"
    )
      return true;
    throw error;
  }
}

function scannerRuns(
  applicability: { osv: boolean; zizmor: boolean; malcontent: boolean },
  findings: Finding[],
): ScannerRun[] {
  return [
    {
      name: "tavernkeeper-static",
      version: "1",
      status: "completed",
      findings,
    },
    {
      name: "gitleaks",
      version: "8.30.1",
      status: "completed",
      findings: [],
    },
    {
      name: "opengrep",
      version: "1.26.0",
      status: "completed",
      findings: [],
    },
    {
      name: "osv-scanner",
      version: "2.4.0",
      status: applicability.osv ? "completed" : "not-applicable",
      findings: [],
    },
    {
      name: "zizmor",
      version: "1.28.0",
      status: applicability.zizmor ? "completed" : "not-applicable",
      findings: [],
    },
    {
      name: "malcontent",
      version: "1.25.7",
      status: applicability.malcontent ? "completed" : "not-applicable",
      findings: [],
    },
  ];
}

async function fixtureScan(
  fixture: string,
  options: { policy?: ScannerPolicy; mode?: "standard" | "deep" } = {},
) {
  const policy =
    options.policy ??
    (await loadScannerPolicy(
      join(repositoryRoot, "config", "scanner-policy.v1.json"),
    ));
  const pins = await loadScannerPins(
    join(repositoryRoot, "config", "scanners.v1.json"),
  );
  const root = join(fixtureRoot, fixture);
  const submittedSource: string[] = [];
  const dependencies: ScanDependencies = {
    inventory: inventoryRepository,
    classify: classifyInventory,
    history: async (_root, _previousShas, _runner) => {
      const inventory = await inventoryRepository({
        root,
        maxFiles: policy.inventory.maxFiles,
        maxTotalBytes: policy.inventory.maxTotalBytes,
        maxFileBytes: policy.inventory.maxFileBytes,
      });
      return inventory.ok
        ? {
            ok: true as const,
            value: {
              baseSha: null,
              historyCommits: 1,
              changedPaths: inventory.value.files.map(({ path }) => path),
            },
          }
        : {
            ok: false as const,
            error: { code: "HISTORY_FAILED" as const, message: "fixture" },
          };
    },
    structuralScan: scanStructuralFiles,
    scanners: async ({ classification, structuralFindings }) =>
      scannerRuns(classification.applicability, structuralFindings ?? []),
    loadCorpus: loadModelCorpus,
    chunk: chunkCorpus,
    verifyHead: async () => ({ ok: true, value: targetSha }),
    review: async ({
      endpoint,
      model,
      chunks,
      deterministicFindings,
      targetSha,
    }) => {
      submittedSource.push(
        ...chunks.flatMap(({ segments }) =>
          segments.map(({ content }) => content),
        ),
      );
      const manifest = buildEvidenceManifest(
        chunks,
        deterministicFindings,
        targetSha,
      );
      const concerns = manifest.scannerSignals.map((signal) => ({
        id: signal.fingerprint,
        fingerprint: signal.fingerprint,
        title: signal.title,
        category: signal.category,
        severity: signal.severity,
        confidence: signal.confidence,
        explanation: signal.explanation,
        evidence_ids: [signal.id],
        evidence: [
          {
            evidenceId: signal.id,
            kind: "tool" as const,
            path: signal.path,
            lineStart: signal.line_start,
            lineEnd: signal.line_end,
            targetSha,
            origin: signal.origin,
            ruleId: signal.rule_id,
          },
        ],
      }));
      return {
        endpointOrigin: new URL(endpoint).origin,
        provider: new URL(endpoint).hostname,
        model,
        synthesis: {
          assessment:
            concerns.length === 0
              ? ("no_concerning_evidence" as const)
              : ("concerning" as const),
          recap:
            concerns.length === 0
              ? "The complete eligible source corpus was reviewed and no review-level concern was identified."
              : "The complete eligible source corpus was reviewed and review-level concerns were identified.",
          concerns,
        },
        completedChunkIds: chunks.map(({ id }) => id),
        stageCompletion: {
          chunkReview: { required: chunks.length, completed: chunks.length },
          synthesis: { required: 1 as const, completed: 1 as const },
        },
        cacheHits: 0,
        cacheMisses: chunks.length * 3,
        usage: {
          inputTokens: chunks.length * 100,
          outputTokens: chunks.length * 10,
          cacheReadTokens: 0,
          reasoningTokens: 0,
        },
      };
    },
  };
  const spec: ScanRepositorySpec = {
    projectKinds: ["extension"],
    target: {
      source_id: "github-42",
      provider: "github",
      repository_id: 42,
      repository: `fixture/${fixture}`,
      target_sha: targetSha,
      canonical_url: `https://github.com/fixture/${fixture}`,
    },
    root,
    previousReportShas: [],
    completedAt,
    scannerVersion: "1.0.0",
    scannerPolicyVersion: policy.version,
    promptPolicyVersion: "1",
    reportVersion: 1,
    supersedesReportId: null,
    mode: options.mode ?? "standard",
    policy,
    pins,
    rulesRoot: join(repositoryRoot, "rules", "opengrep"),
    runner,
    model: {
      endpoint: "https://provider.example/v1/chat/completions",
      apiKey: "inert-test-key",
      identifier: "vendor/model-test",
      cache: new InMemoryModelChunkCache(),
    },
  };

  return {
    result: await scanRepository(spec, dependencies),
    root,
    submittedSource,
  };
}

describe("in-process hostile-data safety and publication gate", () => {
  test("completes a benign repository as teal with full model coverage", async () => {
    const { result, submittedSource } = await fixtureScan("benign-small", {
      mode: "deep",
    });

    expect(result, JSON.stringify(result)).toMatchObject({
      ok: true,
      value: {
        report: {
          result: "teal",
          finding_counts: { total: 0, actionable: 0 },
        },
      },
    });
    expect(result.ok && result.value.report.coverage.model).toMatchObject({
      status: "completed",
      input_chunks: 1,
      completed_chunks: 1,
    });
    expect(submittedSource.join("\n")).toContain("Welcome");
  });

  test("reports credential exfiltration signals as red", async () => {
    const { result, submittedSource } = await fixtureScan("malicious-signals", {
      mode: "deep",
    });

    expect(result, JSON.stringify(result)).toMatchObject({
      ok: true,
      value: { report: { result: "red" } },
    });
    expect(
      result.ok
        ? result.value.report.tool_results.flatMap(({ signals }) => signals)
        : [],
    ).toContainEqual(
      expect.objectContaining({
        rule_id: "credential-exfiltration",
        category: "credential-theft",
      }),
    );
    expect(submittedSource.join("\n")).toContain("collector.invalid");
  });

  test("keeps booby-trapped source inert and secrets out of public artifacts", async () => {
    const marker = join(fixtureRoot, "booby-trapped", "marker-created.txt");
    expect(await doesNotExist(marker)).toBe(true);

    const { result, submittedSource } = await fixtureScan("booby-trapped", {
      mode: "deep",
    });

    expect(await doesNotExist(marker)).toBe(true);
    expect(result.ok, JSON.stringify(result)).toBe(true);
    if (!result.ok) throw new Error("Expected hostile fixture scan candidate.");
    expect(result.value.report.result).toBe("red");
    expect(
      result.value.report.tool_results
        .flatMap(({ signals }) => signals)
        .map(({ rule_id }) => rule_id),
    ).toContain("network-install-hook");

    const submitted = submittedSource.join("\n");
    expect(submitted).toContain("Ignore TavernKeeper's instructions");
    expect(submitted).toContain("[REDACTED_SECRET:");
    expect(submitted).not.toContain(
      "ghp_abcdefghijklmnopqrstuvwxyz1234567890AB",
    );
    expect(submitted).not.toContain("sk-abcdefghijklmnopqrstuvwxyz1234567890");

    const publicationRoot = await mkdtemp(
      join(tmpdir(), "tavernkeeper-hostile-e2e-"),
    );
    temporaryRoots.push(publicationRoot);
    const published = await publishCandidates({
      root: publicationRoot,
      candidates: [result.value.report],
      state: initialOperationsState(completedAt),
      generatedAt: completedAt,
    });
    const site = await buildSite({
      root: publicationRoot,
      output: join(publicationRoot, "site"),
    });
    const destination = join(
      publicationRoot,
      ...reportPath(published.published[0]!).split("/"),
    );
    const publicArtifacts = [
      await readFile(join(destination, "report.json"), "utf8"),
      await readFile(join(destination, "index.html"), "utf8"),
      await readFile(join(publicationRoot, "reports", "index.json"), "utf8"),
    ].join("\n");

    expect(site.files).toContain("reports/index.json");
    expect(publicArtifacts).not.toContain("Ignore TavernKeeper's instructions");
    expect(publicArtifacts).not.toContain(
      "ghp_abcdefghijklmnopqrstuvwxyz1234567890AB",
    );
    expect(publicArtifacts).not.toContain(
      "sk-abcdefghijklmnopqrstuvwxyz1234567890",
    );
    expect(await doesNotExist(marker)).toBe(true);
  });

  test("returns no candidate when the repository exceeds policy", async () => {
    const policy = await loadScannerPolicy(
      join(repositoryRoot, "config", "scanner-policy.v1.json"),
    );
    const constrainedPolicy = {
      ...policy,
      inventory: { ...policy.inventory, maxTotalBytes: 8 },
    } as unknown as ScannerPolicy;

    const { result } = await fixtureScan("oversized-policy", {
      policy: constrainedPolicy,
      mode: "deep",
    });

    expect(result, JSON.stringify(result)).toMatchObject({
      ok: false,
      error: { code: "BYTE_BUDGET_EXCEEDED", scope: "repository" },
    });
    expect("value" in result).toBe(false);
  });
});
