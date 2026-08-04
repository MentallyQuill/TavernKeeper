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
import { recordFailure, recordSuccess } from "../operations/retry.js";
import { parseOperationsState } from "../operations/state.js";
import { appendQueuedTarget } from "../queue/durable-queue.js";
import { publishCandidates } from "./publisher.js";

const CandidateEnvelopeSchema = z.strictObject({ report: ScanReportV5Schema });

type FailedScanTransition = Extract<ScanTransition, { status: "failure" }>;

export type ArtifactBatchStatus = "published" | "partial" | "deferred";

export interface PublishArtifactBatchInput {
  root: string;
  artifactsRoot: string;
  generatedAt: string;
  expectedTargets: Array<
    Target & { recovery_fingerprint?: string | undefined }
  >;
}

export interface PublishArtifactBatchResult {
  status: ArtifactBatchStatus;
  reports: number;
  failures: number;
  queue_remaining: number;
  queue_due: number;
  queue_delayed: number;
  next_wake_at: string | null;
  chronic_failures: number;
  automatic_holds: number;
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

function targetMatches(
  candidate: Pick<
    Target,
    | "source_id"
    | "provider"
    | "repository_id"
    | "repository"
    | "canonical_url"
    | "target_sha"
  >,
  target: Target,
) {
  return (
    candidate.source_id === target.source_id &&
    candidate.provider === target.provider &&
    candidate.repository_id === target.repository_id &&
    candidate.repository === target.repository &&
    candidate.canonical_url === target.canonical_url &&
    candidate.target_sha === target.target_sha
  );
}

function targetKey(target: Target) {
  return [target.provider, target.repository_id, target.target_sha].join(":");
}

function requireCompleteOutcomeSet(
  outcomes: Awaited<ReturnType<typeof loadPairedOutcome>>[],
  expectedTargets: Array<
    Target & { recovery_fingerprint?: string | undefined }
  >,
) {
  const expectedByKey = new Map<
    string,
    Target & { recovery_fingerprint?: string | undefined }
  >();
  for (const target of expectedTargets) {
    const key = targetKey(target);
    if (expectedByKey.has(key))
      throw new Error("Duplicate target in requested publication batch.");
    expectedByKey.set(key, target);
  }

  const outcomeKeys = new Set<string>();
  for (const outcome of outcomes) {
    const key = targetKey(outcome.transition.target);
    if (outcomeKeys.has(key))
      throw new Error("Duplicate scan outcome target in publication batch.");
    outcomeKeys.add(key);
    const expected = expectedByKey.get(key);
    if (
      expected === undefined ||
      !targetMatches(outcome.transition.target, expected)
    )
      throw new Error("Scan outcome set does not match the requested batch.");
  }

  if (outcomeKeys.size !== expectedByKey.size)
    throw new Error("Scan outcome set does not match the requested batch.");
  return expectedByKey;
}

export async function publishArtifactBatch(
  input: PublishArtifactBatchInput,
): Promise<PublishArtifactBatchResult> {
  const outcomes = await Promise.all(
    (await outcomeDirectories(input.artifactsRoot)).map(loadPairedOutcome),
  );
  if (outcomes.length === 0) throw new Error("No scan outcomes were supplied.");
  const expectedByKey = requireCompleteOutcomeSet(
    outcomes,
    input.expectedTargets,
  );
  const outcomeByKey = new Map(
    outcomes.map((outcome) => [targetKey(outcome.transition.target), outcome]),
  );
  const orderedOutcomes = input.expectedTargets.map((target) =>
    outcomeByKey.get(targetKey(target))!,
  );

  let state = parseOperationsState(
    await readJsonFile(join(input.root, "operations", "state.json")),
  );
  for (const target of input.expectedTargets) {
    const existing = state.scan_queue.entries.find(
      ({ repository_id }) => repository_id === target.repository_id,
    );
    if (existing === undefined) {
      state = appendQueuedTarget(state, target);
      continue;
    }
    if (existing.target_sha !== target.target_sha)
      throw new Error("Requested batch target is not the queued target SHA.");
  }
  const reports: ScanReportV5[] = [];
  const failures: FailedScanTransition[] = [];

  for (const outcome of orderedOutcomes) {
    if (outcome.transition.status === "failure") {
      if (outcome.candidate !== null)
        throw new Error("Failed outcome must not contain a candidate.");
      failures.push(outcome.transition);
      state = recordFailure(state, {
        target: outcome.transition.target,
        failure: outcome.transition.failure,
        at: outcome.transition.at,
        recoveryFingerprint: expectedByKey.get(
          targetKey(outcome.transition.target),
        )!.recovery_fingerprint,
      }).state;
      continue;
    }

    if (outcome.candidate === null)
      throw new Error("Completed outcome is missing its candidate.");
    const report = CandidateEnvelopeSchema.parse(outcome.candidate).report;
    if (!targetMatches(report, outcome.transition.target))
      throw new Error(
        "Completed candidate does not match its transition target.",
      );
    state = recordSuccess(
      state,
      outcome.transition.target,
      outcome.transition.at,
      expectedByKey.get(targetKey(outcome.transition.target))!
        .recovery_fingerprint,
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
  const generatedAtMs = Date.parse(input.generatedAt);
  if (!Number.isFinite(generatedAtMs))
    throw new Error("Publication batch time is invalid.");
  const remaining = published.state.scan_queue.entries;
  const delayed = remaining.filter(
    ({ not_before }) =>
      not_before !== null && Date.parse(not_before) > generatedAtMs,
  );
  const due = remaining.filter(
    ({ not_before }) =>
      not_before === null || Date.parse(not_before) <= generatedAtMs,
  );
  const failedRepositoryIds = new Set(
    failures.map(({ target }) => target.repository_id),
  );
  return {
    status: hasFailures
      ? published.published.length > 0
        ? "partial"
        : "deferred"
      : "published",
    reports: published.published.length,
    failures: failures.length,
    queue_remaining: remaining.length,
    queue_due: due.length,
    queue_delayed: delayed.length,
    next_wake_at:
      delayed
        .map(({ not_before }) => not_before!)
        .sort((left, right) => left.localeCompare(right))[0] ?? null,
    chronic_failures: remaining.filter(
      ({ repository_id, chronic }) =>
        chronic && failedRepositoryIds.has(repository_id),
    ).length,
    automatic_holds: published.state.automatic_holds.length,
  };
}
