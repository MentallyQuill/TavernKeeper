import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, test } from "vitest";

import type { ScanReportV5 } from "../src/contracts/reports-v5.js";
import type { Target } from "../src/contracts/targets.js";
import { initialOperationsState } from "../src/operations/state.js";
import { publishArtifactBatch } from "../src/publish/artifact-batch.js";
import type { ScanTransition } from "../src/cli/transition.js";
import { fixtureReportV5 } from "./helpers/v5-report.js";

const roots: string[] = [];
const initialAt = "2026-08-04T04:00:00.000Z";
const generatedAt = "2026-08-04T04:01:00.000Z";

afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

async function batchRoot() {
  const root = await mkdtemp(join(tmpdir(), "tavernkeeper-artifact-batch-"));
  roots.push(root);
  const artifactsRoot = join(root, "artifacts");
  await Promise.all([
    mkdir(join(root, "operations"), { recursive: true }),
    mkdir(artifactsRoot, { recursive: true }),
  ]);
  await writeFile(
    join(root, "operations", "state.json"),
    `${JSON.stringify(initialOperationsState(initialAt), null, 2)}\n`,
  );
  return { root, artifactsRoot };
}

async function reportFor(repositoryId: number, shaCharacter: string) {
  return fixtureReportV5({
    source_id: `github-${repositoryId}`,
    repository_id: repositoryId,
    repository: `owner/repo-${repositoryId}`,
    canonical_url: `https://github.com/owner/repo-${repositoryId}`,
    target_sha: shaCharacter.repeat(40),
  });
}

function targetOf(report: ScanReportV5): Target {
  return {
    source_id: report.source_id,
    provider: report.provider,
    repository_id: report.repository_id,
    repository: report.repository,
    target_sha: report.target_sha,
    canonical_url: report.canonical_url,
  };
}

function completed(report: ScanReportV5): ScanTransition {
  return {
    schema_version: 1,
    status: "completed",
    target: targetOf(report),
    at: generatedAt,
  };
}

function failed(
  target: Target,
  scope: "repository" | "system",
  code: string,
): ScanTransition {
  return {
    schema_version: 1,
    status: "failure",
    target,
    code,
    scope,
    at: generatedAt,
  };
}

async function writeOutcome(
  artifactsRoot: string,
  position: number,
  transition: ScanTransition,
  report?: ScanReportV5,
) {
  const directory = join(artifactsRoot, `scan-${position}`);
  await mkdir(directory, { recursive: true });
  await writeFile(
    join(directory, "transition.json"),
    `${JSON.stringify(transition, null, 2)}\n`,
  );
  if (report !== undefined)
    await writeFile(
      join(directory, "candidate.json"),
      `${JSON.stringify({ report }, null, 2)}\n`,
    );
}

async function readState(root: string) {
  return JSON.parse(
    await readFile(join(root, "operations", "state.json"), "utf8"),
  );
}

async function readPublishedRepositoryIds(root: string) {
  const index = JSON.parse(
    await readFile(join(root, "reports", "index.json"), "utf8"),
  ) as { reports: Array<{ repository_id: number }> };
  return index.reports
    .map(({ repository_id }) => repository_id)
    .sort((left, right) => left - right);
}

describe("artifact batch publication", () => {
  test("publishes completed reports while recording a system failure", async () => {
    const { root, artifactsRoot } = await batchRoot();
    const [first, second, failedReport] = await Promise.all([
      reportFor(42, "a"),
      reportFor(43, "b"),
      reportFor(44, "c"),
    ]);
    await Promise.all([
      writeOutcome(artifactsRoot, 0, completed(first), first),
      writeOutcome(artifactsRoot, 1, completed(second), second),
      writeOutcome(
        artifactsRoot,
        2,
        failed(targetOf(failedReport), "system", "SCANNER_FAILED"),
      ),
    ]);

    const result = await publishArtifactBatch({
      root,
      artifactsRoot,
      generatedAt,
    });

    expect(result).toEqual({
      status: "partial",
      reports: 2,
      has_failures: true,
      system_failure: true,
      terminal_failures: 0,
    });
    await expect(readPublishedRepositoryIds(root)).resolves.toEqual([42, 43]);
    await expect(readState(root)).resolves.toMatchObject({
      circuit_breaker: { terminal: false },
      retries: [expect.objectContaining({ repository_id: 44 })],
    });
  });

  test("defers a failed-only batch without publishing a report", async () => {
    const { root, artifactsRoot } = await batchRoot();
    const report = await reportFor(45, "d");
    await writeOutcome(
      artifactsRoot,
      0,
      failed(targetOf(report), "system", "MODEL_PROVIDER"),
    );

    const result = await publishArtifactBatch({
      root,
      artifactsRoot,
      generatedAt,
    });

    expect(result).toMatchObject({
      status: "deferred",
      reports: 0,
      has_failures: true,
      system_failure: true,
    });
    await expect(readPublishedRepositoryIds(root)).resolves.toEqual([]);
  });

  test("publishes successes beside repository failures without a breaker", async () => {
    const { root, artifactsRoot } = await batchRoot();
    const [successful, failedReport] = await Promise.all([
      reportFor(46, "e"),
      reportFor(47, "f"),
    ]);
    await Promise.all([
      writeOutcome(artifactsRoot, 0, completed(successful), successful),
      writeOutcome(
        artifactsRoot,
        1,
        failed(targetOf(failedReport), "repository", "MODEL_INVALID_RESPONSE"),
      ),
    ]);

    const result = await publishArtifactBatch({
      root,
      artifactsRoot,
      generatedAt,
    });

    expect(result).toMatchObject({
      status: "partial",
      reports: 1,
      has_failures: true,
      system_failure: false,
    });
    expect((await readState(root)).circuit_breaker).toBeNull();
  });

  test("rejects a completed transition without its candidate", async () => {
    const { root, artifactsRoot } = await batchRoot();
    const report = await reportFor(48, "1");
    await writeOutcome(artifactsRoot, 0, completed(report));

    await expect(
      publishArtifactBatch({ root, artifactsRoot, generatedAt }),
    ).rejects.toThrow("Completed outcome is missing its candidate.");
  });

  test("rejects a failure transition carrying a candidate", async () => {
    const { root, artifactsRoot } = await batchRoot();
    const report = await reportFor(49, "2");
    await writeOutcome(
      artifactsRoot,
      0,
      failed(targetOf(report), "system", "SCANNER_FAILED"),
      report,
    );

    await expect(
      publishArtifactBatch({ root, artifactsRoot, generatedAt }),
    ).rejects.toThrow("Failed outcome must not contain a candidate.");
  });

  test("rejects a candidate that does not match its completed target", async () => {
    const { root, artifactsRoot } = await batchRoot();
    const [transitionReport, candidateReport] = await Promise.all([
      reportFor(50, "3"),
      reportFor(51, "4"),
    ]);
    await writeOutcome(
      artifactsRoot,
      0,
      completed(transitionReport),
      candidateReport,
    );

    await expect(
      publishArtifactBatch({ root, artifactsRoot, generatedAt }),
    ).rejects.toThrow(
      "Completed candidate does not match its transition target.",
    );
  });

  test("rejects duplicate outcomes for one repository target", async () => {
    const { root, artifactsRoot } = await batchRoot();
    const report = await reportFor(52, "5");
    await Promise.all([
      writeOutcome(artifactsRoot, 0, completed(report), report),
      writeOutcome(
        artifactsRoot,
        1,
        failed(targetOf(report), "system", "SCANNER_FAILED"),
      ),
    ]);

    await expect(
      publishArtifactBatch({ root, artifactsRoot, generatedAt }),
    ).rejects.toThrow("Duplicate scan outcome target in publication batch.");
  });
});
