import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, test } from "vitest";

import type { ScanReportV5 } from "../src/contracts/reports-v5.js";
import type { Target } from "../src/contracts/targets.js";
import { initialOperationsState } from "../src/operations/state.js";
import { publishArtifactBatch } from "../src/publish/artifact-batch.js";
import type { ScanTransition } from "../src/cli/transition.js";
import type { FailureDescriptor } from "../src/operations/failure.js";
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
    schema_version: 2,
    status: "completed",
    target: targetOf(report),
    at: generatedAt,
  };
}

function failed(target: Target, failure: FailureDescriptor): ScanTransition {
  return {
    schema_version: 2,
    status: "failure",
    target,
    failure,
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

function publicationInput(
  root: string,
  artifactsRoot: string,
  expectedTargets: Target[],
) {
  return { root, artifactsRoot, generatedAt, expectedTargets };
}

describe("artifact batch publication", () => {
  test("publishes completed reports and continues after a target failure", async () => {
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
        failed(targetOf(failedReport), {
          code: "SCANNER_FAILED",
          domain: "target",
          component: "opengrep",
        }),
      ),
    ]);

    const result = await publishArtifactBatch(
      publicationInput(root, artifactsRoot, [
        targetOf(first),
        targetOf(second),
        targetOf(failedReport),
      ]),
    );

    expect(result).toEqual({
      status: "partial",
      reports: 2,
      target_failures: 1,
      shared_holds: 0,
      security_holds: 0,
      continuation_blocked: false,
      terminal_failures: 0,
    });
    await expect(readPublishedRepositoryIds(root)).resolves.toEqual([42, 43]);
    await expect(readState(root)).resolves.toMatchObject({
      shared_holds: [],
      target_retries: [expect.objectContaining({ repository_id: 44 })],
    });
  });

  test("defers a failed-only batch without publishing a report", async () => {
    const { root, artifactsRoot } = await batchRoot();
    const report = await reportFor(45, "d");
    await writeOutcome(
      artifactsRoot,
      0,
      failed(targetOf(report), {
        code: "MODEL_PROVIDER",
        domain: "shared",
        component: "contextual-model",
      }),
    );

    const result = await publishArtifactBatch(
      publicationInput(root, artifactsRoot, [targetOf(report)]),
    );

    expect(result).toMatchObject({
      status: "deferred",
      reports: 0,
      target_failures: 0,
      shared_holds: 1,
      security_holds: 0,
      continuation_blocked: true,
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
        failed(targetOf(failedReport), {
          code: "MODEL_INVALID_RESPONSE",
          domain: "target",
          component: "contextual-model",
        }),
      ),
    ]);

    const result = await publishArtifactBatch(
      publicationInput(root, artifactsRoot, [
        targetOf(successful),
        targetOf(failedReport),
      ]),
    );

    expect(result).toMatchObject({
      status: "partial",
      reports: 1,
      target_failures: 1,
      shared_holds: 0,
      security_holds: 0,
      continuation_blocked: false,
    });
    expect((await readState(root)).shared_holds).toEqual([]);
  });

  test("rejects a completed transition without its candidate", async () => {
    const { root, artifactsRoot } = await batchRoot();
    const report = await reportFor(48, "1");
    await writeOutcome(artifactsRoot, 0, completed(report));

    await expect(
      publishArtifactBatch(
        publicationInput(root, artifactsRoot, [targetOf(report)]),
      ),
    ).rejects.toThrow("Completed outcome is missing its candidate.");
  });

  test("rejects a failure transition carrying a candidate", async () => {
    const { root, artifactsRoot } = await batchRoot();
    const report = await reportFor(49, "2");
    await writeOutcome(
      artifactsRoot,
      0,
      failed(targetOf(report), {
        code: "SCANNER_FAILED",
        domain: "target",
        component: "opengrep",
      }),
      report,
    );

    await expect(
      publishArtifactBatch(
        publicationInput(root, artifactsRoot, [targetOf(report)]),
      ),
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
      publishArtifactBatch(
        publicationInput(root, artifactsRoot, [targetOf(transitionReport)]),
      ),
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
        failed(targetOf(report), {
          code: "SCANNER_FAILED",
          domain: "target",
          component: "opengrep",
        }),
      ),
    ]);

    await expect(
      publishArtifactBatch(
        publicationInput(root, artifactsRoot, [targetOf(report)]),
      ),
    ).rejects.toThrow("Duplicate scan outcome target in publication batch.");
  });

  test("rejects a batch missing an expected repository outcome", async () => {
    const { root, artifactsRoot } = await batchRoot();
    const [present, missing] = await Promise.all([
      reportFor(53, "6"),
      reportFor(54, "7"),
    ]);
    await writeOutcome(artifactsRoot, 0, completed(present), present);

    await expect(
      publishArtifactBatch(
        publicationInput(root, artifactsRoot, [
          targetOf(present),
          targetOf(missing),
        ]),
      ),
    ).rejects.toThrow("Scan outcome set does not match the requested batch.");
    await expect(readPublishedRepositoryIds(root)).rejects.toThrow();
    await expect(readState(root)).resolves.toEqual(
      initialOperationsState(initialAt),
    );
  });

  test("security failures persist a pause and block continuation", async () => {
    const { root, artifactsRoot } = await batchRoot();
    const report = await reportFor(56, "9");
    await writeOutcome(
      artifactsRoot,
      0,
      failed(targetOf(report), {
        code: "MODEL_AUTHENTICATION",
        domain: "security",
        component: "contextual-model",
      }),
    );

    const result = await publishArtifactBatch(
      publicationInput(root, artifactsRoot, [targetOf(report)]),
    );

    expect(result).toMatchObject({
      security_holds: 1,
      continuation_blocked: true,
    });
    await expect(readState(root)).resolves.toMatchObject({
      pause: { kind: "system", reason_code: "SECURITY_HOLD" },
    });
  });

  test("a successful shared recovery probe clears its hold", async () => {
    const { root, artifactsRoot } = await batchRoot();
    const report = await reportFor(57, "a");
    await writeOutcome(
      artifactsRoot,
      0,
      failed(targetOf(report), {
        code: "MODEL_PROVIDER",
        domain: "shared",
        component: "contextual-model",
      }),
    );
    await publishArtifactBatch(
      publicationInput(root, artifactsRoot, [targetOf(report)]),
    );

    const recoveredArtifacts = join(root, "recovered-artifacts");
    await mkdir(recoveredArtifacts, { recursive: true });
    await writeOutcome(recoveredArtifacts, 0, completed(report), report);
    const recovered = await publishArtifactBatch(
      publicationInput(root, recoveredArtifacts, [targetOf(report)]),
    );

    expect(recovered).toMatchObject({
      status: "published",
      reports: 1,
      shared_holds: 0,
      continuation_blocked: false,
    });
    await expect(readState(root)).resolves.toMatchObject({ shared_holds: [] });
    await expect(readPublishedRepositoryIds(root)).resolves.toEqual([57]);
  });

  test("rejects an outcome whose identity differs from the requested target", async () => {
    const { root, artifactsRoot } = await batchRoot();
    const report = await reportFor(55, "8");
    await writeOutcome(artifactsRoot, 0, completed(report), report);

    await expect(
      publishArtifactBatch(
        publicationInput(root, artifactsRoot, [
          {
            ...targetOf(report),
            repository: "owner/renamed-repo",
            canonical_url: "https://github.com/owner/renamed-repo",
          },
        ]),
      ),
    ).rejects.toThrow("Scan outcome set does not match the requested batch.");
    await expect(readPublishedRepositoryIds(root)).rejects.toThrow();
  });
});
