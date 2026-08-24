import { parseReportIndexV5 } from "../contracts/reports-v5.js";
import { CURRENT_SCANNER_POLICY_VERSION } from "../config/policy.js";
import {
  parseTargetManifest,
  requireTargetManifestV2,
} from "../contracts/targets.js";
import { parseOperationsState } from "../operations/state.js";
import {
  fetchFixedJson,
  isDirectExecution,
  readJsonFile,
  requiredEnvironment,
  runJsonCli,
  writeJsonFile,
} from "./io.js";
import { TARGET_MANIFEST_URL } from "./reconcile.js";
import { OperationsStateSchema } from "../operations/state.js";
import { appendQueuedTarget } from "../queue/durable-queue.js";
import { syncScanQueue } from "../queue/sync.js";
import {
  ScanRequestSchema,
  validateTargetedScanHint,
} from "./staff-request.js";
import { nextRepositoryReportLineage } from "../publish/report-lineage.js";

export function buildTargetedMatrix({
  manifest: manifestInput,
  index: indexInput,
  state: stateInput,
  repositoryId,
  scannerPolicyVersion = CURRENT_SCANNER_POLICY_VERSION,
  requestCreatedAt,
}: {
  manifest: unknown;
  index: unknown;
  state: unknown;
  repositoryId: number;
  scannerPolicyVersion?: string;
  requestCreatedAt: string;
}) {
  const manifest = requireTargetManifestV2(parseTargetManifest(manifestInput));
  const index = parseReportIndexV5(indexInput);
  const state = parseOperationsState(stateInput);
  const target = manifest.repositories.find(
    ({ repository_id }) => repository_id === repositoryId,
  );
  if (target === undefined)
    throw new Error(
      "Targeted repository ID is not in Tavernary's current target manifest.",
    );
  const requestCreatedAtMs = Date.parse(requestCreatedAt);
  if (!Number.isFinite(requestCreatedAtMs))
    throw new Error("Targeted workflow creation time is invalid.");
  const previous = index.reports.filter(
    ({ repository_id }) => repository_id === target.repository_id,
  );
  if (state.emergency_stop !== null) return { include: [], coalesced: true };
  const matchingReports = previous.filter(
    ({ target_sha, scanner_policy_version }) =>
      target_sha === target.target_sha &&
      scanner_policy_version === scannerPolicyVersion,
  );
  if (
    state.active_scans.some(
      (active) =>
        active.repository_id === target.repository_id &&
        active.target_sha === target.target_sha,
    ) ||
    matchingReports.some(
      ({ completed_at }) => Date.parse(completed_at) >= requestCreatedAtMs,
    )
  )
    return { include: [], coalesced: true };

  const lineage = nextRepositoryReportLineage(index, target);
  const request = ScanRequestSchema.parse({
    ...target,
    reason: "staff",
    ...lineage,
    previous_report_shas: [
      ...new Set(previous.map(({ target_sha }) => target_sha)),
    ].slice(0, 20),
  });
  return { include: [request], coalesced: false };
}

export function buildTargetedQueueUpdate({
  manifest: manifestInput,
  index: indexInput,
  state: stateInput,
  repositoryId,
  scannerPolicyVersion = CURRENT_SCANNER_POLICY_VERSION,
  requestCreatedAt,
  now,
}: {
  manifest: unknown;
  index: unknown;
  state: unknown;
  repositoryId: number;
  scannerPolicyVersion?: string;
  requestCreatedAt: string;
  now: string;
}) {
  const manifest = requireTargetManifestV2(parseTargetManifest(manifestInput));
  const index = parseReportIndexV5(indexInput);
  const synchronized = syncScanQueue({
    manifest,
    index,
    state: stateInput,
    now,
    scannerPolicyVersion,
  });
  const target = manifest.repositories.find(
    ({ repository_id }) => repository_id === repositoryId,
  );
  if (target === undefined)
    throw new Error(
      "Targeted repository ID is not in Tavernary's current target manifest.",
    );
  const requestCreatedAtMs = Date.parse(requestCreatedAt);
  if (!Number.isFinite(requestCreatedAtMs))
    throw new Error("Targeted workflow creation time is invalid.");
  if (!Number.isFinite(Date.parse(now)))
    throw new Error("Targeted queue time is invalid.");

  const completedAfterRequest = index.reports.some(
    ({ repository_id, target_sha, scanner_policy_version, completed_at }) =>
      repository_id === target.repository_id &&
      target_sha === target.target_sha &&
      scanner_policy_version === scannerPolicyVersion &&
      Date.parse(completed_at) >= requestCreatedAtMs,
  );
  const alreadyActive = synchronized.state.active_scans.some(
    ({ repository_id, target_sha }) =>
      repository_id === target.repository_id &&
      target_sha === target.target_sha,
  );
  if (completedAfterRequest || alreadyActive)
    return {
      state: synchronized.state,
      accepted: false,
      coalesced: true,
      changed: synchronized.changed,
      ticket: null,
    };

  const existing = synchronized.state.scan_queue.entries.find(
    ({ repository_id }) => repository_id === target.repository_id,
  );
  const targetedEntryChanged = existing?.staff_requested !== true;
  const appended = appendQueuedTarget(synchronized.state, target, {
    staffRequested: true,
  });
  const changed = synchronized.changed || targetedEntryChanged;
  const state = changed
    ? OperationsStateSchema.parse({ ...appended, updated_at: now })
    : appended;
  const ticket = state.scan_queue.entries.find(
    ({ repository_id }) => repository_id === target.repository_id,
  )!.ticket;
  return {
    state,
    accepted: true,
    coalesced: false,
    changed,
    ticket,
  };
}

async function main() {
  const hint = validateTargetedScanHint(
    JSON.parse(requiredEnvironment(process.env, "TAVERNKEEPER_TARGETED_SCAN")),
  );
  const [manifest, index, state] = await Promise.all([
    fetchFixedJson(TARGET_MANIFEST_URL),
    readJsonFile("reports/index.json"),
    readJsonFile("operations/state.json"),
  ]);
  const queued = buildTargetedQueueUpdate({
    manifest,
    index,
    state,
    repositoryId: hint.repository_id,
    requestCreatedAt: requiredEnvironment(
      process.env,
      "TAVERNKEEPER_REQUEST_CREATED_AT",
    ),
    now: new Date().toISOString(),
  });
  if (queued.changed)
    await writeJsonFile("operations/state.json", queued.state);
  return {
    accepted: queued.accepted,
    coalesced: queued.coalesced,
    changed: queued.changed,
    ticket: queued.ticket,
    queue_entries: queued.state.scan_queue.entries.length,
  };
}

if (isDirectExecution(import.meta.url)) runJsonCli(main);
