import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, test } from "vitest";

import type { ScanTransition } from "../src/cli/transition.js";
import type { ScanReportV5 } from "../src/contracts/reports-v5.js";
import type { Target } from "../src/contracts/targets.js";
import type { FailureDescriptor } from "../src/operations/failure.js";
import { initialOperationsState } from "../src/operations/state.js";
import { publishArtifactBatch } from "../src/publish/artifact-batch.js";
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
  test("publishes successes and rotates all failure domains in request order", async () => {
    const { root, artifactsRoot } = await batchRoot();
    const reports = await Promise.all([
      reportFor(42, "a"),
      reportFor(43, "b"),
      reportFor(44, "c"),
      reportFor(45, "d"),
    ]);
    const targets = reports.map(targetOf);
    await Promise.all([
      writeOutcome(artifactsRoot, 9, completed(reports[0]!), reports[0]),
      writeOutcome(
        artifactsRoot,
        2,
        failed(targets[1]!, {
          code: "MODEL_AUTHENTICATION",
          domain: "security",
          component: "contextual-model",
        }),
      ),
      writeOutcome(artifactsRoot, 7, completed(reports[2]!), reports[2]),
      writeOutcome(
        artifactsRoot,
        1,
        failed(targets[3]!, {
          code: "MODEL_PROVIDER",
          domain: "shared",
          component: "contextual-model",
        }),
      ),
    ]);

    const result = await publishArtifactBatch(
      publicationInput(root, artifactsRoot, targets),
    );

    expect(result).toEqual({
      status: "partial",
      reports: 2,
      failures: 2,
      queue_remaining: 2,
      queue_due: 0,
      queue_delayed: 2,
      next_wake_at: "2026-08-04T04:06:00.000Z",
      chronic_failures: 0,
    });
    await expect(readPublishedRepositoryIds(root)).resolves.toEqual([42, 44]);
    await expect(readState(root)).resolves.toMatchObject({
      emergency_stop: null,
      scan_queue: {
        next_ticket: 7,
        entries: [
          { repository_id: 43, ticket: 5 },
          { repository_id: 45, ticket: 6 },
        ],
      },
    });
  });

  test("a failed-only batch remains an automatic queued outcome", async () => {
    const { root, artifactsRoot } = await batchRoot();
    const report = await reportFor(46, "e");
    await writeOutcome(
      artifactsRoot,
      0,
      failed(targetOf(report), {
        code: "SCANNER_FAILED",
        domain: "target",
        component: "opengrep",
      }),
    );

    const result = await publishArtifactBatch(
      publicationInput(root, artifactsRoot, [targetOf(report)]),
    );

    expect(result).toMatchObject({
      status: "deferred",
      reports: 0,
      failures: 1,
      queue_remaining: 1,
      queue_delayed: 1,
      chronic_failures: 0,
    });
    expect(result).not.toHaveProperty("continuation_blocked");
    expect(result).not.toHaveProperty("terminal_failures");
    expect(result).not.toHaveProperty("security_holds");
    expect(result).not.toHaveProperty("shared_holds");
  });

  test("a later success removes a previously failed target", async () => {
    const { root, artifactsRoot } = await batchRoot();
    const report = await reportFor(47, "f");
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
      failures: 0,
      queue_remaining: 0,
    });
    await expect(readState(root)).resolves.toMatchObject({
      scan_queue: { entries: [] },
    });
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

  test("rejects duplicate or missing outcomes before mutating state", async () => {
    const { root, artifactsRoot } = await batchRoot();
    const [present, missing] = await Promise.all([
      reportFor(52, "5"),
      reportFor(53, "6"),
    ]);
    await Promise.all([
      writeOutcome(artifactsRoot, 0, completed(present), present),
      writeOutcome(
        artifactsRoot,
        1,
        failed(targetOf(present), {
          code: "SCANNER_FAILED",
          domain: "target",
          component: "opengrep",
        }),
      ),
    ]);

    await expect(
      publishArtifactBatch(
        publicationInput(root, artifactsRoot, [
          targetOf(present),
          targetOf(missing),
        ]),
      ),
    ).rejects.toThrow("Duplicate scan outcome target in publication batch.");
    await expect(readState(root)).resolves.toEqual(
      initialOperationsState(initialAt),
    );
  });
});
