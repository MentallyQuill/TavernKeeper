import {
  ReportIndexV5Schema,
  type ReportIndexV5,
} from "../contracts/reports-v5.js";
import {
  TargetManifestV2Schema,
  TargetManifestV3Schema,
  type CurrentTarget,
  type CurrentTargetManifest,
} from "../contracts/targets.js";
import {
  OperationsStateSchema,
  type OperationsState,
  type ScanQueueEntry,
} from "../operations/state.js";

export interface QueueSyncSummary {
  seeded: number;
  retained: number;
  replaced: number;
  removed: number;
  migrated_from: 1 | 2 | null;
  automatic_stops_cleared: number;
  automatic_holds_preserved: number;
  legacy_retries_preserved: number;
}

function parseCurrentManifest(input: CurrentTargetManifest) {
  return input.schema_version === 3
    ? TargetManifestV3Schema.parse(input)
    : TargetManifestV2Schema.parse(input);
}

function targetOrder(left: CurrentTarget, right: CurrentTarget) {
  if (
    "popularity_rank" in left.catalog_priority &&
    "popularity_rank" in right.catalog_priority
  )
    return (
      left.catalog_priority.popularity_rank -
        right.catalog_priority.popularity_rank ||
      left.repository_id - right.repository_id
    );
  if (left.catalog_priority.top_30 !== right.catalog_priority.top_30)
    return left.catalog_priority.top_30 ? -1 : 1;
  return (
    Date.parse(left.catalog_priority.first_cataloged_at) -
      Date.parse(right.catalog_priority.first_cataloged_at) ||
    left.repository_id - right.repository_id
  );
}

function blankEntry(
  target: CurrentTarget,
  ticket: number,
  rescanNotBefore?: string,
): ScanQueueEntry {
  return {
    source_id: target.source_id,
    repository_id: target.repository_id,
    repository: target.repository,
    target_sha: target.target_sha,
    ticket,
    consecutive_failures: 0,
    total_failures: 0,
    not_before: null,
    last_failure: null,
    last_failed_at: null,
    ...(rescanNotBefore === undefined
      ? {}
      : { rescan_not_before: rescanNotBefore }),
    chronic: false,
  };
}

function hasActivePolicyCampaign(
  target: CurrentTarget,
  state: OperationsState,
  scannerPolicyVersion: string,
) {
  return state.policy_campaigns.some(
    (item) =>
      item.status === "active" &&
      item.scanner_policy_version === scannerPolicyVersion &&
      item.repository_ids.includes(target.repository_id),
  );
}

function targetNeedsScan(
  target: CurrentTarget,
  index: ReportIndexV5,
  state: OperationsState,
  scannerPolicyVersion: string,
) {
  const campaign = hasActivePolicyCampaign(target, state, scannerPolicyVersion);
  if (campaign) return true;
  return !index.reports.some(
    (report) =>
      report.repository_id === target.repository_id &&
      report.target_sha === target.target_sha &&
      report.scanner_policy_version === scannerPolicyVersion,
  );
}

function advancePolicyCampaigns(
  state: OperationsState,
  manifest: CurrentTargetManifest,
  index: ReportIndexV5,
) {
  const targetByRepositoryId = new Map(
    manifest.repositories.map((target) => [target.repository_id, target]),
  );
  return state.policy_campaigns.map((campaign) => {
    if (campaign.status === "completed") return campaign;
    const remaining = campaign.repository_ids.filter((repositoryId) => {
      const target = targetByRepositoryId.get(repositoryId);
      if (target === undefined) return false;
      return !index.reports.some(
        (report) =>
          report.repository_id === repositoryId &&
          report.target_sha === target.target_sha &&
          report.scanner_policy_version === campaign.scanner_policy_version,
      );
    });
    return {
      ...campaign,
      repository_ids: remaining,
      status: remaining.length === 0 ? ("completed" as const) : campaign.status,
    };
  });
}

function automaticRescanNotBefore(input: {
  target: CurrentTarget;
  report: ReportIndexV5["reports"][number] | undefined;
  state: OperationsState;
  scannerPolicyVersion: string;
  staffRequested: boolean;
}) {
  const { target, report, state, scannerPolicyVersion, staffRequested } = input;
  if (
    staffRequested ||
    hasActivePolicyCampaign(target, state, scannerPolicyVersion) ||
    report === undefined ||
    report.target_sha === target.target_sha
  )
    return undefined;
  return new Date(
    Date.parse(report.completed_at) + 48 * 60 * 60 * 1_000,
  ).toISOString();
}

export function reconcileCurrentScanQueue(input: {
  manifest: CurrentTargetManifest;
  index: ReportIndexV5;
  state: OperationsState;
  now: string;
  scannerPolicyVersion: string;
}) {
  const manifest = parseCurrentManifest(input.manifest);
  const index = ReportIndexV5Schema.parse(input.index);
  const state = OperationsStateSchema.parse(input.state);
  if (!Number.isFinite(Date.parse(input.now)))
    throw new Error("Queue synchronization time is invalid.");

  const policyCampaigns = advancePolicyCampaigns(state, manifest, index);
  const campaignState = OperationsStateSchema.parse({
    ...state,
    policy_campaigns: policyCampaigns,
  });
  const campaignsChanged =
    JSON.stringify(policyCampaigns) !== JSON.stringify(state.policy_campaigns);
  const targetByRepositoryId = new Map(
    manifest.repositories.map((target) => [target.repository_id, target]),
  );
  const preferredReportByRepositoryId = new Map(
    index.reports.map((report) => [report.repository_id, report]),
  );
  const eligibleTargets = manifest.repositories
    .filter((target) =>
      targetNeedsScan(target, index, campaignState, input.scannerPolicyVersion),
    )
    .sort(targetOrder);
  const eligibleRepositoryIds = new Set(
    eligibleTargets.map(({ repository_id }) => repository_id),
  );
  const existingRepositoryIds = new Set<number>();
  const entries: ScanQueueEntry[] = [];
  let retained = 0;
  let replaced = 0;
  let removed = 0;

  for (const entry of [...campaignState.scan_queue.entries].sort(
    (left, right) => left.ticket - right.ticket,
  )) {
    const target = targetByRepositoryId.get(entry.repository_id);
    if (
      target === undefined ||
      (!eligibleRepositoryIds.has(entry.repository_id) &&
        entry.staff_requested !== true)
    ) {
      removed += 1;
      continue;
    }
    existingRepositoryIds.add(entry.repository_id);
    const rescanNotBefore = automaticRescanNotBefore({
      target,
      report: preferredReportByRepositoryId.get(target.repository_id),
      state: campaignState,
      scannerPolicyVersion: input.scannerPolicyVersion,
      staffRequested: entry.staff_requested === true,
    });
    if (entry.target_sha !== target.target_sha) {
      entries.push({
        ...blankEntry(target, entry.ticket, rescanNotBefore),
        total_failures: entry.total_failures,
        ...(entry.staff_requested === true ? { staff_requested: true } : {}),
      });
      replaced += 1;
      continue;
    }
    const normalizedEntry = {
      ...entry,
      source_id: target.source_id,
      repository: target.repository,
    };
    if (rescanNotBefore === undefined) {
      const { rescan_not_before: _ignored, ...entryWithoutRescanDeadline } =
        normalizedEntry;
      entries.push(entryWithoutRescanDeadline);
    } else
      entries.push({
        ...normalizedEntry,
        rescan_not_before: rescanNotBefore,
      });
    retained += 1;
  }

  let nextTicket = campaignState.scan_queue.next_ticket;
  let seeded = 0;
  for (const target of eligibleTargets) {
    if (existingRepositoryIds.has(target.repository_id)) continue;
    if (nextTicket >= Number.MAX_SAFE_INTEGER)
      throw new Error("Scan queue ticket space is exhausted.");
    entries.push(
      blankEntry(
        target,
        nextTicket,
        automaticRescanNotBefore({
          target,
          report: preferredReportByRepositoryId.get(target.repository_id),
          state: campaignState,
          scannerPolicyVersion: input.scannerPolicyVersion,
          staffRequested: false,
        }),
      ),
    );
    nextTicket += 1;
    seeded += 1;
  }

  entries.sort((left, right) => left.ticket - right.ticket);
  const changed =
    campaignsChanged ||
    seeded > 0 ||
    replaced > 0 ||
    removed > 0 ||
    entries.some(
      (entry, indexValue) =>
        JSON.stringify(entry) !==
        JSON.stringify(
          [...campaignState.scan_queue.entries].sort(
            (left, right) => left.ticket - right.ticket,
          )[indexValue],
        ),
    ) ||
    (campaignState.coverage_started_at === null && entries.length > 0);
  const nextState = OperationsStateSchema.parse({
    ...campaignState,
    updated_at: changed ? input.now : campaignState.updated_at,
    coverage_started_at:
      campaignState.coverage_started_at ??
      (entries.length > 0 ? input.now : null),
    scan_queue: { next_ticket: nextTicket, entries },
  });
  return {
    state: nextState,
    changed,
    summary: {
      seeded,
      retained,
      replaced,
      removed,
      migrated_from: null,
      automatic_stops_cleared: 0,
      automatic_holds_preserved: 0,
      legacy_retries_preserved: 0,
    } satisfies QueueSyncSummary,
  };
}
