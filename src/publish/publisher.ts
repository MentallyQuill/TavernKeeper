import {
  access,
  mkdir,
  mkdtemp,
  readFile,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { randomUUID } from "node:crypto";
import { dirname, join, resolve } from "node:path";

import {
  ReportIndexEntrySchema,
  ReportIndexSchema,
  type ReportIndex,
  type ReportIndexEntry,
  type ScanReport,
} from "../contracts/reports.js";
import {
  OperationsStateSchema,
  serializeOperationsState,
  type OperationsState,
} from "../operations/state.js";
import { recordSuccess } from "../operations/retry.js";
import { renderReportHtml } from "./render-report.js";
import { reportPath, reportUrl } from "./report-path.js";
import { sanitizeReport } from "./sanitize.js";

export interface PublishCandidatesInput {
  root: string;
  candidates: unknown[];
  state: OperationsState;
  generatedAt: string;
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

async function readExistingIndex(path: string, generatedAt: string) {
  try {
    return ReportIndexSchema.parse(JSON.parse(await readFile(path, "utf8")));
  } catch (error) {
    if (isMissing(error))
      return ReportIndexSchema.parse({
        schema_version: 1,
        generated_at: generatedAt,
        reports: [],
      });
    throw error;
  }
}

function indexEntry(report: ScanReport): ReportIndexEntry {
  return ReportIndexEntrySchema.parse({
    report_id: report.report_id,
    report_version: report.report_version,
    supersedes_report_id: report.supersedes_report_id,
    scanner_version: report.scanner_version,
    scanner_policy_version: report.scanner_policy_version,
    prompt_policy_version: report.prompt_policy_version,
    source_id: report.source_id,
    provider: report.provider,
    repository_id: report.repository_id,
    repository: report.repository,
    target_sha: report.target_sha,
    completed_at: report.completed_at,
    mode: report.mode,
    result: report.result,
    finding_counts: report.finding_counts,
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
      model_chunks: report.coverage.model.completed_chunks,
    },
    report_url: reportUrl(report),
  });
}

function preference(left: ReportIndexEntry, right: ReportIndexEntry) {
  if (left.report_version !== right.report_version)
    return left.report_version - right.report_version;
  if (left.mode !== right.mode) return left.mode === "deep" ? 1 : -1;
  const time = Date.parse(left.completed_at) - Date.parse(right.completed_at);
  return time === 0 ? left.report_id.localeCompare(right.report_id) : time;
}

function preferredIndex(
  existing: ReportIndex,
  reports: ScanReport[],
  generatedAt: string,
) {
  const preferred = new Map<string, ReportIndexEntry>();
  for (const entry of [
    ...existing.reports,
    ...reports.map((report) => indexEntry(report)),
  ]) {
    const key = [
      entry.provider,
      entry.repository_id,
      entry.target_sha,
      entry.scanner_policy_version,
    ].join(":");
    const current = preferred.get(key);
    if (current === undefined || preference(entry, current) > 0)
      preferred.set(key, entry);
  }
  return ReportIndexSchema.parse({
    schema_version: 1,
    generated_at: generatedAt,
    reports: [...preferred.values()].sort((left, right) =>
      [
        left.repository_id.toString().padStart(20, "0"),
        left.target_sha,
        left.scanner_policy_version,
      ]
        .join(":")
        .localeCompare(
          [
            right.repository_id.toString().padStart(20, "0"),
            right.target_sha,
            right.scanner_policy_version,
          ].join(":"),
        ),
    ),
  });
}

function completedState(
  input: OperationsState,
  reports: ScanReport[],
  generatedAt: string,
) {
  let state = OperationsStateSchema.parse(input);
  for (const report of reports) {
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
    state = OperationsStateSchema.parse({
      ...state,
      updated_at: generatedAt,
      active_scans: state.active_scans.filter(
        (active) =>
          active.repository_id !== report.repository_id ||
          active.target_sha !== report.target_sha,
      ),
    });
  }
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

export async function publishCandidates({
  root: rootInput,
  candidates,
  state: stateInput,
  generatedAt,
}: PublishCandidatesInput) {
  const root = resolve(rootInput);
  const reports = candidates.map((candidate) => sanitizeReport(candidate));
  const relativePaths = reports.map((report) => reportPath(report));
  if (new Set(relativePaths).size !== relativePaths.length)
    throw new Error("Duplicate immutable report path in publication batch.");

  const destinations = relativePaths.map((path) =>
    join(root, ...path.split("/")),
  );
  for (const destination of destinations) {
    if (await exists(destination))
      throw new Error(`Immutable report path already exists: ${destination}`);
  }

  const indexPath = join(root, "reports", "index.json");
  const statePath = join(root, "operations", "state.json");
  const existingIndex = await readExistingIndex(indexPath, generatedAt);
  const index = preferredIndex(existingIndex, reports, generatedAt);
  const state = completedState(stateInput, reports, generatedAt);
  const indexContents = `${JSON.stringify(index, null, 2)}\n`;
  const stateContents = serializeOperationsState(state);

  await mkdir(root, { recursive: true });
  const stagingRoot = await mkdtemp(join(root, ".tavernkeeper-publish-"));
  const moved: string[] = [];
  const originalIndex = await readOptional(indexPath);
  const originalState = await readOptional(statePath);
  let indexReplaced = false;
  let stateReplaced = false;
  try {
    for (const [position, report] of reports.entries()) {
      const staged = join(stagingRoot, ...relativePaths[position]!.split("/"));
      await mkdir(staged, { recursive: true });
      await writeFile(
        join(staged, "report.json"),
        `${JSON.stringify(report, null, 2)}\n`,
      );
      await writeFile(join(staged, "index.html"), renderReportHtml(report));
    }
    await mkdir(join(stagingRoot, "reports"), { recursive: true });
    await mkdir(join(stagingRoot, "operations"), { recursive: true });
    await writeFile(join(stagingRoot, "reports", "index.json"), indexContents);
    await writeFile(
      join(stagingRoot, "operations", "state.json"),
      stateContents,
    );

    for (const [position, destination] of destinations.entries()) {
      await mkdir(dirname(destination), { recursive: true });
      const staged = join(stagingRoot, ...relativePaths[position]!.split("/"));
      await rename(staged, destination);
      moved.push(destination);
    }
    await atomicReplace(statePath, stateContents);
    stateReplaced = true;
    await atomicReplace(indexPath, indexContents);
    indexReplaced = true;
  } catch (error) {
    if (indexReplaced) await restore(indexPath, originalIndex);
    if (stateReplaced) await restore(statePath, originalState);
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
