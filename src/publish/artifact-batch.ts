import { access, readdir } from "node:fs/promises";
import { dirname, join } from "node:path";

import { z } from "zod";

import { readJsonFile } from "../cli/io.js";
import {
  ScanTransitionSchema,
  type ScanTransition,
} from "../cli/transition.js";
import {
  ScanReportV5Schema,
  type ScanReportV5,
} from "../contracts/reports-v5.js";
import type { Target } from "../contracts/targets.js";
import { recordFailure } from "../operations/retry.js";
import { parseOperationsState } from "../operations/state.js";
import { publishCandidates } from "./publisher.js";

const CandidateEnvelopeSchema = z.strictObject({ report: ScanReportV5Schema });

type FailedScanTransition = Extract<ScanTransition, { status: "failure" }>;

export type ArtifactBatchStatus = "published" | "partial" | "deferred";

export interface PublishArtifactBatchInput {
  root: string;
  artifactsRoot: string;
  generatedAt: string;
}

export interface PublishArtifactBatchResult {
  status: ArtifactBatchStatus;
  reports: number;
  has_failures: boolean;
  system_failure: boolean;
  terminal_failures: number;
}

async function exists(path: string) {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

async function findTransitionFiles(root: string): Promise<string[]> {
  const paths: string[] = [];
  for (const entry of await readdir(root, { withFileTypes: true })) {
    const path = join(root, entry.name);
    if (entry.isDirectory()) paths.push(...(await findTransitionFiles(path)));
    else if (entry.isFile() && entry.name === "transition.json")
      paths.push(path);
  }
  return paths;
}

async function outcomeDirectories(artifactsRoot: string) {
  return [
    ...new Set((await findTransitionFiles(artifactsRoot)).map(dirname)),
  ].sort((left, right) => left.localeCompare(right));
}

async function loadPairedOutcome(directory: string) {
  const candidatePath = join(directory, "candidate.json");
  return {
    transition: ScanTransitionSchema.parse(
      await readJsonFile(join(directory, "transition.json")),
    ),
    candidate: (await exists(candidatePath))
      ? await readJsonFile(candidatePath)
      : null,
  };
}

function reportMatchesTarget(report: ScanReportV5, target: Target) {
  return (
    report.source_id === target.source_id &&
    report.provider === target.provider &&
    report.repository_id === target.repository_id &&
    report.repository === target.repository &&
    report.canonical_url === target.canonical_url &&
    report.target_sha === target.target_sha
  );
}

export async function publishArtifactBatch(
  input: PublishArtifactBatchInput,
): Promise<PublishArtifactBatchResult> {
  const outcomes = await Promise.all(
    (await outcomeDirectories(input.artifactsRoot)).map(loadPairedOutcome),
  );
  if (outcomes.length === 0) throw new Error("No scan outcomes were supplied.");

  let state = parseOperationsState(
    await readJsonFile(join(input.root, "operations", "state.json")),
  );
  const reports: ScanReportV5[] = [];
  const failures: FailedScanTransition[] = [];
  const targetKeys = new Set<string>();

  for (const outcome of outcomes) {
    const targetKey = [
      outcome.transition.target.provider,
      outcome.transition.target.repository_id,
      outcome.transition.target.target_sha,
    ].join(":");
    if (targetKeys.has(targetKey))
      throw new Error("Duplicate scan outcome target in publication batch.");
    targetKeys.add(targetKey);

    if (outcome.transition.status === "failure") {
      if (outcome.candidate !== null)
        throw new Error("Failed outcome must not contain a candidate.");
      failures.push(outcome.transition);
      state = recordFailure(state, {
        target: outcome.transition.target,
        code: outcome.transition.code,
        scope: outcome.transition.scope,
        at: outcome.transition.at,
      }).state;
      continue;
    }

    if (outcome.candidate === null)
      throw new Error("Completed outcome is missing its candidate.");
    const report = CandidateEnvelopeSchema.parse(outcome.candidate).report;
    if (!reportMatchesTarget(report, outcome.transition.target))
      throw new Error(
        "Completed candidate does not match its transition target.",
      );
    reports.push(report);
  }

  const published = await publishCandidates({
    root: input.root,
    candidates: reports,
    state,
    generatedAt: input.generatedAt,
  });
  const hasFailures = failures.length > 0;
  return {
    status: hasFailures
      ? published.published.length > 0
        ? "partial"
        : "deferred"
      : "published",
    reports: published.published.length,
    has_failures: hasFailures,
    system_failure: failures.some(({ scope }) => scope === "system"),
    terminal_failures: failures.filter(({ target }) =>
      published.state.retries.some(
        (retry) =>
          retry.repository_id === target.repository_id &&
          retry.target_sha === target.target_sha &&
          retry.exhausted,
      ),
    ).length,
  };
}
