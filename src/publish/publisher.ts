import { randomUUID } from "node:crypto";
import {
  access,
  mkdir,
  mkdtemp,
  readFile,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { dirname, join, resolve } from "node:path";

import {
  parseReportIndexV5,
  ReportIndexEntryV5Schema,
  ReportIndexV5Schema,
  type ReportIndexEntryV5,
  type ReportIndexV5,
  type ScanReportV5,
} from "../contracts/reports-v5.js";
import {
  OperationsStateSchema,
  serializeOperationsState,
  type OperationsState,
} from "../operations/state.js";
import { recordSuccess } from "../operations/retry.js";
import {
  ReviewCacheManifestSchema,
  reviewCachePath,
  type ReviewCacheManifest,
} from "../model/review-cache.js";
import { renderHistoryHtml } from "./render-history.js";
import { renderReportV5Html } from "./render-report.js";
import {
  historyPath,
  historyUrl,
  reportPath,
  reportUrl,
} from "./report-path.js";
import { sanitizeReportV5 } from "./sanitize.js";
import {
  compareReportPreference,
  nextRepositoryReportLineage,
} from "./report-lineage.js";

export interface PublishCandidatesInput {
  root: string;
  candidates: unknown[];
  reviewCaches: unknown[];
  state: OperationsState;
  generatedAt: string;
}

function cacheMatchesReport(cache: ReviewCacheManifest, report: ScanReportV5) {
  const identity = cache.review_identity;
  const baseMatches =
    cache.repository_id === report.repository_id &&
    cache.repository === report.repository &&
    cache.source_report.report_id === report.report_id &&
    cache.source_report.target_sha === report.target_sha &&
    cache.source_report.scanner_policy_version ===
      report.scanner_policy_version;
  if (identity === undefined)
    return (
      baseMatches &&
      cache.entries.length === 0 &&
      report.review_triage?.candidates.contextual === 0
    );
  const reportTools = report.coverage.tools
    .map(({ name, version }) => ({ name, version }))
    .sort((left, right) =>
      (left.name + ":" + left.version).localeCompare(
        right.name + ":" + right.version,
      ),
    );
  const cacheTools = [...identity.tools].sort((left, right) =>
    (left.name + ":" + left.version).localeCompare(
      right.name + ":" + right.version,
    ),
  );
  const reportCandidateIds = new Set(
    report.candidates.map(({ candidate_id }) => candidate_id),
  );
  let endpointProviderMatches = false;
  try {
    endpointProviderMatches =
      new URL(identity.endpoint_origin).hostname === identity.provider;
  } catch {
    endpointProviderMatches = false;
  }
  return (
    baseMatches &&
    identity.scanner_version === report.scanner_version &&
    identity.scanner_policy_version === report.scanner_policy_version &&
    identity.rule_catalog_version === report.rule_catalog_version &&
    identity.contextual_policy_version ===
      report.contextual_review_policy_version &&
    identity.prompt_version === report.prompt_version &&
    identity.assessment_schema_version === report.assessment_schema_version &&
    report.contextual_reviewer !== undefined &&
    identity.provider === report.contextual_reviewer.provider &&
    endpointProviderMatches &&
    identity.model === report.contextual_reviewer.model &&
    JSON.stringify(cacheTools) === JSON.stringify(reportTools) &&
    cache.entries.every(({ candidate_ids }) =>
      candidate_ids.every((candidateId) => reportCandidateIds.has(candidateId)),
    )
  );
}

function isMissing(error: unknown) {
  return (
    error !== null &&
    typeof error === "object" &&
    "code" in error &&
    error.code === "ENOENT"
  );
}

async function exists(path: string) {
  try {
    await access(path);
    return true;
  } catch (error) {
    if (isMissing(error)) return false;
    throw error;
  }
}

function emptyIndex(generatedAt: string) {
  return ReportIndexV5Schema.parse({
    schema_version: 5,
    generated_at: generatedAt,
    reports: [],
  });
}

async function readExistingIndex(path: string, generatedAt: string) {
  try {
    return parseReportIndexV5(JSON.parse(await readFile(path, "utf8")));
  } catch (error) {
    if (isMissing(error)) return emptyIndex(generatedAt);
    throw error;
  }
}

export function projectReportToIndexV5(
  report: ScanReportV5,
): ReportIndexEntryV5 {
  return ReportIndexEntryV5Schema.parse({
    report_id: report.report_id,
    report_digest: report.report_digest,
    report_version: report.report_version,
    supersedes_report_id: report.supersedes_report_id,
    scanner_version: report.scanner_version,
    scanner_policy_version: report.scanner_policy_version,
    rule_catalog_version: report.rule_catalog_version,
    package_schema_version: report.package_schema_version,
    contextual_review_policy_version: report.contextual_review_policy_version,
    ecosystem_context_version: report.ecosystem_context_version,
    prompt_version: report.prompt_version,
    assessment_schema_version: report.assessment_schema_version,
    source_id: report.source_id,
    provider: report.provider,
    repository_id: report.repository_id,
    repository: report.repository,
    target_sha: report.target_sha,
    completed_at: report.completed_at,
    assessment_method: report.assessment_method,
    counts: report.counts,
    coverage: {
      history_commits: report.history.commits,
      inventory_files: report.coverage.inventory.files,
      inventory_bytes: report.coverage.inventory.bytes,
      tools_completed: report.coverage.tools.filter(
        ({ status }) => status === "completed",
      ).length,
      tools_not_applicable: report.coverage.tools.filter(
        ({ status }) => status === "not-applicable",
      ).length,
      evidence_validated:
        report.coverage.evidence_validation.validated_candidates,
      metadata_only_candidates:
        report.coverage.evidence_validation.status ===
        "completed-with-limitations"
          ? report.coverage.evidence_validation.metadata_only_candidates
          : 0,
      review_required: report.review_coverage.required,
      review_completed: report.review_coverage.completed,
      javascript_analysis_status:
        report.coverage.javascript_analysis?.status ?? "legacy",
    },
    report_url: reportUrl(report),
    history_url: historyUrl(report),
  });
}

function preferredIndex(
  existing: ReportIndexV5,
  reports: ScanReportV5[],
  generatedAt: string,
) {
  const preferred = new Map<string, ReportIndexEntryV5>();
  for (const entry of [
    ...existing.reports,
    ...reports.map(projectReportToIndexV5),
  ]) {
    const key = `${entry.provider}:${entry.repository_id}`;
    const current = preferred.get(key);
    if (current === undefined || compareReportPreference(entry, current) > 0)
      preferred.set(key, entry);
  }
  return ReportIndexV5Schema.parse({
    schema_version: 5,
    generated_at: generatedAt,
    reports: [...preferred.values()].sort(
      (left, right) => left.repository_id - right.repository_id,
    ),
  });
}

function completedState(
  input: OperationsState,
  reports: ScanReportV5[],
  generatedAt: string,
) {
  let state = OperationsStateSchema.parse(input);
  for (const report of reports)
    state = recordSuccess(
      state,
      {
        source_id: report.source_id,
        provider: report.provider,
        repository_id: report.repository_id,
        repository: report.repository,
        canonical_url: report.canonical_url,
        target_sha: report.target_sha,
      },
      generatedAt,
    );
  return state;
}

async function atomicReplace(path: string, contents: string | Buffer) {
  await mkdir(dirname(path), { recursive: true });
  const temporary = `${path}.${randomUUID()}.tmp`;
  try {
    await writeFile(temporary, contents);
    await rename(temporary, path);
  } finally {
    await rm(temporary, { force: true });
  }
}

async function restore(path: string, contents: Buffer | null) {
  if (contents === null) {
    await rm(path, { force: true });
    return;
  }
  await atomicReplace(path, contents);
}

async function readOptional(path: string) {
  try {
    return await readFile(path);
  } catch (error) {
    if (isMissing(error)) return null;
    throw error;
  }
}

async function readHistoryEntries(path: string) {
  try {
    const input = JSON.parse(await readFile(path, "utf8"));
    if (!Array.isArray(input))
      throw new Error("Report history must be an array.");
    return input.map((entry) => ReportIndexEntryV5Schema.parse(entry));
  } catch (error) {
    if (isMissing(error)) return [];
    throw error;
  }
}

function mergeHistory(
  existing: ReportIndexEntryV5[],
  additions: ReportIndexEntryV5[],
) {
  const reports = new Map(existing.map((entry) => [entry.report_id, entry]));
  for (const entry of additions) reports.set(entry.report_id, entry);
  return [...reports.values()].sort((left, right) => {
    const time = Date.parse(left.completed_at) - Date.parse(right.completed_at);
    return time || left.report_id.localeCompare(right.report_id);
  });
}

export async function publishCandidates({
  root: rootInput,
  candidates,
  reviewCaches: reviewCachesInput,
  state: stateInput,
  generatedAt,
}: PublishCandidatesInput) {
  const root = resolve(rootInput);
  const reports = candidates.map(sanitizeReportV5);
  const reviewCaches = reviewCachesInput.map((cache) =>
    ReviewCacheManifestSchema.parse(cache),
  );
  if (reviewCaches.length !== reports.length)
    throw new Error("Every report must have exactly one review cache.");
  const cacheByRepositoryId = new Map(
    reviewCaches.map((cache) => [cache.repository_id, cache]),
  );
  if (cacheByRepositoryId.size !== reviewCaches.length)
    throw new Error("Duplicate review cache repository in publication batch.");
  const orderedCaches = reports.map((report) => {
    const cache = cacheByRepositoryId.get(report.repository_id);
    if (cache === undefined || !cacheMatchesReport(cache, report))
      throw new Error("Review cache does not match its report.");
    return cache;
  });
  const relativePaths = reports.map(reportPath);
  if (new Set(relativePaths).size !== relativePaths.length)
    throw new Error("Duplicate immutable report path in publication batch.");

  const destinations = relativePaths.map((path) =>
    join(root, ...path.split("/")),
  );
  const cacheDestinations = orderedCaches.map((cache) =>
    join(root, ...reviewCachePath(cache.repository_id).split("/")),
  );
  for (const destination of destinations)
    if (await exists(destination))
      throw new Error(`Immutable report path already exists: ${destination}`);

  const indexPath = join(root, "reports", "index.json");
  const statePath = join(root, "operations", "state.json");
  const existingIndex = await readExistingIndex(indexPath, generatedAt);
  for (const report of reports) {
    const expected = nextRepositoryReportLineage(existingIndex, report);
    if (
      report.report_version !== expected.report_version ||
      report.supersedes_report_id !== expected.supersedes_report_id
    )
      throw new Error(
        `Report lineage does not advance the preferred repository report: ${report.provider}:${report.repository_id}.`,
      );
  }
  const index = preferredIndex(existingIndex, reports, generatedAt);
  const state = completedState(stateInput, reports, generatedAt);
  const indexContents = `${JSON.stringify(index, null, 2)}\n`;
  const stateContents = serializeOperationsState(state);
  const projected = reports.map(projectReportToIndexV5);
  const repositoryIds = [
    ...new Set(reports.map(({ repository_id }) => repository_id)),
  ];
  const histories = await Promise.all(
    repositoryIds.map(async (repositoryId) => {
      const representative = reports.find(
        (report) => report.repository_id === repositoryId,
      )!;
      const directory = join(root, ...historyPath(representative).split("/"));
      const jsonPath = join(directory, "history.json");
      const previous = await readHistoryEntries(jsonPath);
      const fallback = existingIndex.reports.filter(
        (entry) => entry.repository_id === repositoryId,
      );
      const entries = mergeHistory(
        previous.length === 0 ? fallback : previous,
        projected.filter((entry) => entry.repository_id === repositoryId),
      );
      return {
        htmlPath: join(directory, "index.html"),
        jsonPath,
        html: renderHistoryHtml(entries),
        json: `${JSON.stringify(entries, null, 2)}\n`,
      };
    }),
  );

  await mkdir(root, { recursive: true });
  const stagingRoot = await mkdtemp(join(root, ".tavernkeeper-publish-"));
  const moved: string[] = [];
  const originalIndex = await readOptional(indexPath);
  const originalState = await readOptional(statePath);
  const historyOriginals = await Promise.all(
    histories.flatMap((history) =>
      [history.htmlPath, history.jsonPath].map(async (path) => ({
        path,
        contents: await readOptional(path),
      })),
    ),
  );
  const cacheOriginals = await Promise.all(
    cacheDestinations.map(async (path) => ({
      path,
      contents: await readOptional(path),
    })),
  );
  const replaced: string[] = [];
  try {
    for (const [position, report] of reports.entries()) {
      const staged = join(stagingRoot, ...relativePaths[position]!.split("/"));
      await mkdir(staged, { recursive: true });
      await writeFile(
        join(staged, "report.json"),
        `${JSON.stringify(report, null, 2)}\n`,
      );
      await writeFile(join(staged, "index.html"), renderReportV5Html(report));
    }
    for (const [position, destination] of destinations.entries()) {
      await mkdir(dirname(destination), { recursive: true });
      await rename(
        join(stagingRoot, ...relativePaths[position]!.split("/")),
        destination,
      );
      moved.push(destination);
    }
    for (const history of histories) {
      await atomicReplace(history.htmlPath, history.html);
      replaced.push(history.htmlPath);
      await atomicReplace(history.jsonPath, history.json);
      replaced.push(history.jsonPath);
    }
    for (const [position, path] of cacheDestinations.entries()) {
      await atomicReplace(
        path,
        `${JSON.stringify(orderedCaches[position], null, 2)}\n`,
      );
      replaced.push(path);
    }
    await atomicReplace(statePath, stateContents);
    replaced.push(statePath);
    await atomicReplace(indexPath, indexContents);
    replaced.push(indexPath);
  } catch (error) {
    for (const path of replaced.reverse()) {
      const historyOriginal = historyOriginals.find(
        (item) => item.path === path,
      );
      const original =
        path === indexPath
          ? originalIndex
          : path === statePath
            ? originalState
            : historyOriginal !== undefined
              ? historyOriginal.contents
              : cacheOriginals.find((item) => item.path === path)!.contents;
      await restore(path, original);
    }
    await Promise.all(
      moved.map((destination) =>
        rm(destination, { recursive: true, force: true }),
      ),
    );
    throw error;
  } finally {
    await rm(stagingRoot, { recursive: true, force: true });
  }

  return { published: reports, index, state };
}
