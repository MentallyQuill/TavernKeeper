import { access, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, test } from "vitest";

import {
  loadScannerPins,
  loadScannerPolicy,
  ScannerPolicyV2Schema,
  type ScannerPolicyV2,
} from "../../src/config/policy.js";
import type { Finding } from "../../src/contracts/reports.js";
import { classifyInventory } from "../../src/inventory/classify.js";
import { inventoryRepository } from "../../src/inventory/inventory-handler.js";
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
import { fixtureReportV5 } from "../helpers/v5-report.js";

const repositoryRoot = dirname(
  dirname(dirname(fileURLToPath(import.meta.url))),
);
const fixtureRoot = join(repositoryRoot, "tests", "fixtures");
const targetSha = "a".repeat(40);
const completedAt = "2026-08-02T18:00:00.000Z";
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
      version: "2",
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

async function v2Policy() {
  return ScannerPolicyV2Schema.parse(
    await loadScannerPolicy(
      join(repositoryRoot, "config", "scanner-policy.v2.json"),
    ),
  );
}

async function fixtureScan(fixture: string, policyInput?: ScannerPolicyV2) {
  const policy = policyInput ?? (await v2Policy());
  const pins = await loadScannerPins(
    join(repositoryRoot, "config", "scanners.v1.json"),
  );
  const root = join(fixtureRoot, fixture);
  const dependencies: ScanDependencies = {
    inventory: inventoryRepository,
    classify: classifyInventory,
    history: async () => {
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
    verifyHead: async () => ({ ok: true, value: targetSha }),
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
    scannerPolicyVersion: "2",
    ruleCatalogVersion: "1",
    reportVersion: 1,
    supersedesReportId: null,
    policy,
    pins,
    rulesRoot: join(repositoryRoot, "rules", "opengrep"),
    runner,
  };
  return { result: await scanRepository(spec, dependencies), root };
}

describe("in-process hostile-data safety and deterministic publication gate", () => {
  test("completes a benign repository as teal with complete tool coverage", async () => {
    const { result } = await fixtureScan("benign-small");
    expect(result, JSON.stringify(result)).toMatchObject({
      ok: true,
      value: {
        report: {
          schema_version: 4,
          assessment_method: "deterministic-static-analysis",
          result: "teal",
          finding_counts: { total: 0, reportable: 0 },
        },
      },
    });
    expect(result.ok && result.value.report.coverage.tools).toHaveLength(7);
  });

  test("reports credential exfiltration signals as red", async () => {
    const { result } = await fixtureScan("malicious-signals");
    expect(result, JSON.stringify(result)).toMatchObject({
      ok: true,
      value: { report: { result: "red" } },
    });
    expect(result.ok ? result.value.report.findings : []).toContainEqual(
      expect.objectContaining({
        rule_id: "credential-exfiltration",
        category: "credential-theft",
        policy_status: "reportable",
      }),
    );
  });

  test("keeps booby-trapped source inert and secrets out of public artifacts", async () => {
    const marker = join(fixtureRoot, "booby-trapped", "marker-created.txt");
    expect(await doesNotExist(marker)).toBe(true);
    const { result } = await fixtureScan("booby-trapped");
    expect(await doesNotExist(marker)).toBe(true);
    if (!result.ok) throw new Error(JSON.stringify(result));
    expect(result.value.report.result).toBe("red");
    expect(
      result.value.report.findings.map(({ rule_id }) => rule_id),
    ).toContain("network-install-hook");
    const serialized = JSON.stringify(result.value.report);
    expect(serialized).not.toContain("Ignore TavernKeeper's instructions");
    expect(serialized).not.toContain(
      "ghp_abcdefghijklmnopqrstuvwxyz1234567890AB",
    );
    expect(serialized).not.toContain("sk-abcdefghijklmnopqrstuvwxyz1234567890");

    const publicationRoot = await mkdtemp(
      join(tmpdir(), "tavernkeeper-hostile-e2e-"),
    );
    temporaryRoots.push(publicationRoot);
    const published = await publishCandidates({
      root: publicationRoot,
      candidates: [await fixtureReportV5()],
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
    const policy = await v2Policy();
    const constrained = {
      ...policy,
      inventory: { ...policy.inventory, maxTotalBytes: 8 },
    } as unknown as ScannerPolicyV2;
    const { result } = await fixtureScan("oversized-policy", constrained);
    expect(result, JSON.stringify(result)).toMatchObject({
      ok: false,
      error: { code: "BYTE_BUDGET_EXCEEDED", scope: "repository" },
    });
    expect("value" in result).toBe(false);
  });
});
