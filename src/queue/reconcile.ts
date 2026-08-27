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
  type UnscannableTarget,
} from "../operations/state.js";
import { failureFingerprint } from "../operations/failure.js";
import { targetRetryNotBefore } from "../operations/retry-schedule.js";

export interface QueueSyncSummary {
  seeded: number;
  retained: number;
  replaced: number;
  removed: number;
  migrated_from: 1 | 2 | null;
  automatic_stops_cleared: number;
  automatic_holds_preserved: number;
  legacy_retries_preserved: number;
  terminalized: number;
}

export function normalizeRetryPolicyEntries(
  state: OperationsState,
  at: string,
) {
  let retryPolicyNormalized = 0;
  const retryEntries = state.scan_queue.entries.map((entry) => {
    if (entry.consecutive_failures < 1 || entry.consecutive_failures > 2)
      return entry;
    const notBefore = targetRetryNotBefore(
      entry.last_failed_at!,
      entry.consecutive_failures,
    );
    const chronic = entry.consecutive_failures >= 2;
    if (entry.not_before === notBefore && entry.chronic === chronic)
      return entry;
    retryPolicyNormalized += 1;
    return { ...entry, not_before: notBefore, chronic };
  });
  const retryState =
    retryPolicyNormalized === 0
      ? state
      : OperationsStateSchema.parse({
          ...state,
          updated_at: at,
          scan_queue: { ...state.scan_queue, entries: retryEntries },
        });
  const terminalEntries = retryState.scan_queue.entries.filter(
    ({ consecutive_failures }) => consecutive_failures >= 3,
  );
  if (terminalEntries.length === 0)
    return { state: retryState, retryPolicyNormalized, terminalized: 0 };
  const terminalRepositoryIds = new Set(
    terminalEntries.map(({ repository_id }) => repository_id),
  );
  const unscannableTargets: UnscannableTarget[] = terminalEntries.map(
    (entry) => {
      const lastFailure = entry.last_failure!;
      const lastFailedAt = entry.last_failed_at!;
      return {
        source_id: entry.source_id,
        repository_id: entry.repository_id,
        repository: entry.repository,
        target_sha: entry.target_sha,
        unscannable_at: at,
        consecutive_failures: entry.consecutive_failures,
        total_failures: entry.total_failures,
        last_failure: lastFailure,
        last_failed_at: lastFailedAt,
        failure_history: entry.failure_history ?? [
          {
            failed_at: lastFailedAt,
            failure: lastFailure,
            error_fingerprint: failureFingerprint(lastFailure),
          },
        ],
      };
    },
  );
  return {
    state: OperationsStateSchema.parse({
      ...retryState,
      updated_at: at,
      unscannable_targets: [
        ...retryState.unscannable_targets,
        ...unscannableTargets,
      ],
      scan_queue: {
        ...retryState.scan_queue,
        entries: retryState.scan_queue.entries.filter(
          ({ repository_id }) => !terminalRepositoryIds.has(repository_id),
        ),
      },
      active_scans: retryState.active_scans.filter(
        ({ repository_id }) => !terminalRepositoryIds.has(repository_id),
      ),
    }),
    retryPolicyNormalized,
    terminalized: terminalEntries.length,
  };
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
  catalogChange?: "new" | "updated",
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
    ...(catalogChange === undefined ? {} : { catalog_change: catalogChange }),
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

function hasActiveCoverageCampaign(
  target: CurrentTarget,
  state: OperationsState,
  scannerPolicyVersion: string,
) {
  return state.coverage_campaigns.some(
    (item) =>
      item.status === "active" &&
      item.scanner_policy_version === scannerPolicyVersion &&
      item.remaining_repository_ids.includes(target.repository_id),
  );
}

function advancePolicyCampaigns(
  state: OperationsState,
  manifest: CurrentTargetManifest,
  index: ReportIndexV5,
) {
  const unscannableRepositoryIds = new Set(
    state.unscannable_targets.map(({ repository_id }) => repository_id),
  );
  const targetByRepositoryId = new Map(
    manifest.repositories.map((target) => [target.repository_id, target]),
  );
  return state.policy_campaigns.map((campaign) => {
    if (campaign.status === "completed") return campaign;
    const remaining = campaign.repository_ids.filter((repositoryId) => {
      if (unscannableRepositoryIds.has(repositoryId)) return false;
      const target = targetByRepositoryId.get(repositoryId);
      if (target === undefined) return false;
      return !index.reports.some(
        (report) =>
          report.repository_id === repositoryId &&
          report.target_sha === target.target_sha &&
          report.scanner_policy_version === campaign.scanner_policy_version &&
          Date.parse(report.completed_at) >= Date.parse(campaign.created_at),
      );
    });
    return {
      ...campaign,
      repository_ids: remaining,
      status: remaining.length === 0 ? ("completed" as const) : campaign.status,
    };
  });
}

function advanceCoverageCampaigns(
  state: OperationsState,
  manifest: CurrentTargetManifest,
  index: ReportIndexV5,
  contextualReviewPolicyVersion: string,
) {
  const unscannableRepositoryIds = new Set(
    state.unscannable_targets.map(({ repository_id }) => repository_id),
  );
  const targetByRepositoryId = new Map(
    manifest.repositories.map((target) => [target.repository_id, target]),
  );
  return state.coverage_campaigns.map((campaign) => {
    if (campaign.status === "completed") return campaign;
    const remainingRepositoryIds = campaign.remaining_repository_ids.filter(
      (repositoryId) => {
        if (unscannableRepositoryIds.has(repositoryId)) return false;
        const target = targetByRepositoryId.get(repositoryId);
        if (target === undefined) return false;
        return !index.reports.some(
          (report) =>
            report.repository_id === repositoryId &&
            report.target_sha === target.target_sha &&
            report.scanner_policy_version === campaign.scanner_policy_version &&
            report.contextual_review_policy_version ===
              contextualReviewPolicyVersion &&
            Date.parse(report.completed_at) >= Date.parse(campaign.created_at),
        );
      },
    );
    return {
      ...campaign,
      remaining_repository_ids: remainingRepositoryIds,
      status:
        remainingRepositoryIds.length === 0
          ? ("completed" as const)
          : campaign.status,
    };
  });
}

function automaticRescanNotBefore(input: {
  target: CurrentTarget;
  report: ReportIndexV5["reports"][number] | undefined;
  state: OperationsState;
  scannerPolicyVersion: string;
  staffRequested: boolean;
  coverageRequested: boolean;
}) {
  const {
    target,
    report,
    state,
    scannerPolicyVersion,
    staffRequested,
    coverageRequested,
  } = input;
  if (
    staffRequested ||
    hasActivePolicyCampaign(target, state, scannerPolicyVersion) ||
    report === undefined ||
    (!coverageRequested && report.target_sha === target.target_sha)
  )
    return undefined;
  return new Date(
    Date.parse(report.completed_at) + 7 * 24 * 60 * 60 * 1_000,
  ).toISOString();
}

function hasExactCurrentReport(input: {
  target: CurrentTarget;
  report: ReportIndexV5["reports"][number] | undefined;
  scannerPolicyVersion: string;
  contextualReviewPolicyVersion: string;
}) {
  const {
    target,
    report,
    scannerPolicyVersion,
    contextualReviewPolicyVersion,
  } = input;
  return (
    report !== undefined &&
    report.target_sha === target.target_sha &&
    report.scanner_policy_version === scannerPolicyVersion &&
    report.contextual_review_policy_version === contextualReviewPolicyVersion
  );
}

export function reconcileCurrentScanQueue(input: {
  manifest: CurrentTargetManifest;
  index: ReportIndexV5;
  state: OperationsState;
  now: string;
  scannerPolicyVersion: string;
  contextualReviewPolicyVersion: string;
}) {
  const manifest = parseCurrentManifest(input.manifest);
  const index = ReportIndexV5Schema.parse(input.index);
  const parsedState = OperationsStateSchema.parse(input.state);
  if (!Number.isFinite(Date.parse(input.now)))
    throw new Error("Queue synchronization time is invalid.");
  const normalizedTerminal = normalizeRetryPolicyEntries(
    parsedState,
    input.now,
  );
  const state = normalizedTerminal.state;

  const policyCampaigns = advancePolicyCampaigns(state, manifest, index);
  const coverageCampaigns = advanceCoverageCampaigns(
    state,
    manifest,
    index,
    input.contextualReviewPolicyVersion,
  );
  const campaignState = OperationsStateSchema.parse({
    ...state,
    policy_campaigns: policyCampaigns,
    coverage_campaigns: coverageCampaigns,
  });
  const campaignsChanged =
    JSON.stringify(policyCampaigns) !==
      JSON.stringify(state.policy_campaigns) ||
    JSON.stringify(coverageCampaigns) !==
      JSON.stringify(state.coverage_campaigns);
  const targetByRepositoryId = new Map(
    manifest.repositories.map((target) => [target.repository_id, target]),
  );
  const preferredReportByRepositoryId = new Map(
    index.reports.map((report) => [report.repository_id, report]),
  );
  const observationInitialized = campaignState.catalog_observation != null;
  const observedShaByRepositoryId = new Map(
    campaignState.catalog_observation?.repositories.map((entry) => [
      entry.repository_id,
      entry.target_sha,
    ]) ?? [],
  );
  const detectedCatalogChange = new Map<number, "new" | "updated">();
  if (observationInitialized) {
    for (const target of manifest.repositories) {
      const observedSha = observedShaByRepositoryId.get(target.repository_id);
      if (observedSha === undefined)
        detectedCatalogChange.set(target.repository_id, "new");
      else if (observedSha !== target.target_sha)
        detectedCatalogChange.set(target.repository_id, "updated");
    }
  }
  const existingEntryByRepositoryId = new Map(
    campaignState.scan_queue.entries.map((entry) => [
      entry.repository_id,
      entry,
    ]),
  );
  const unscannableRepositoryIds = new Set(
    campaignState.unscannable_targets.map(({ repository_id }) => repository_id),
  );
  const eligibleTargets = manifest.repositories
    .filter(({ repository_id }) => !unscannableRepositoryIds.has(repository_id))
    .filter((target) => {
      const entry = existingEntryByRepositoryId.get(target.repository_id);
      const report = preferredReportByRepositoryId.get(target.repository_id);
      return (
        hasActivePolicyCampaign(
          target,
          campaignState,
          input.scannerPolicyVersion,
        ) ||
        hasActiveCoverageCampaign(
          target,
          campaignState,
          input.scannerPolicyVersion,
        ) ||
        (observationInitialized && entry?.staff_requested === true) ||
        entry?.catalog_change !== undefined ||
        detectedCatalogChange.has(target.repository_id) ||
        !hasExactCurrentReport({
          target,
          report,
          scannerPolicyVersion: input.scannerPolicyVersion,
          contextualReviewPolicyVersion: input.contextualReviewPolicyVersion,
        })
      );
    })
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
      !eligibleRepositoryIds.has(entry.repository_id)
    ) {
      removed += 1;
      continue;
    }
    existingRepositoryIds.add(entry.repository_id);
    const staffRequested =
      observationInitialized && entry.staff_requested === true;
    const campaignRequested = hasActivePolicyCampaign(
      target,
      campaignState,
      input.scannerPolicyVersion,
    );
    const coverageRequested = hasActiveCoverageCampaign(
      target,
      campaignState,
      input.scannerPolicyVersion,
    );
    const report = preferredReportByRepositoryId.get(target.repository_id);
    const catalogChange =
      entry.catalog_change ??
      detectedCatalogChange.get(entry.repository_id) ??
      (!coverageRequested &&
      report !== undefined &&
      report.target_sha !== target.target_sha
        ? "updated"
        : undefined);
    const clearsRescanDeadline = staffRequested || campaignRequested;
    const durableRescanDeadline =
      catalogChange === undefined && !coverageRequested
        ? undefined
        : entry.rescan_not_before;
    const reportRescanDeadline = automaticRescanNotBefore({
      target,
      report,
      state: campaignState,
      scannerPolicyVersion: input.scannerPolicyVersion,
      staffRequested,
      coverageRequested,
    });
    const rescanNotBefore = clearsRescanDeadline
      ? undefined
      : durableRescanDeadline === undefined
        ? reportRescanDeadline
        : reportRescanDeadline === undefined ||
            Date.parse(durableRescanDeadline) >=
              Date.parse(reportRescanDeadline)
          ? durableRescanDeadline
          : reportRescanDeadline;
    if (entry.target_sha !== target.target_sha) {
      const {
        rescan_not_before: _ignoredRescanDeadline,
        catalog_change: _ignoredCatalogChange,
        staff_requested: _ignoredStaffRequest,
        ...durableFailureEntry
      } = entry;
      entries.push({
        ...durableFailureEntry,
        source_id: target.source_id,
        repository: target.repository,
        target_sha: target.target_sha,
        ...(rescanNotBefore === undefined
          ? {}
          : { rescan_not_before: rescanNotBefore }),
        ...(catalogChange === undefined
          ? {}
          : { catalog_change: catalogChange }),
        ...(staffRequested ? { staff_requested: true } : {}),
      });
      replaced += 1;
      continue;
    }
    const { staff_requested: _ignoredStaffRequest, ...entryWithoutStaff } =
      entry;
    const normalizedEntry = {
      ...entryWithoutStaff,
      source_id: target.source_id,
      repository: target.repository,
      ...(staffRequested ? { staff_requested: true as const } : {}),
      ...(catalogChange === undefined ? {} : { catalog_change: catalogChange }),
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
    const report = preferredReportByRepositoryId.get(target.repository_id);
    const coverageRequested = hasActiveCoverageCampaign(
      target,
      campaignState,
      input.scannerPolicyVersion,
    );
    const catalogChange =
      detectedCatalogChange.get(target.repository_id) ??
      (!coverageRequested &&
      report !== undefined &&
      report.target_sha !== target.target_sha
        ? "updated"
        : undefined);
    entries.push(
      blankEntry(
        target,
        nextTicket,
        automaticRescanNotBefore({
          target,
          report,
          state: campaignState,
          scannerPolicyVersion: input.scannerPolicyVersion,
          staffRequested: false,
          coverageRequested,
        }),
        catalogChange,
      ),
    );
    nextTicket += 1;
    seeded += 1;
  }

  entries.sort((left, right) => left.ticket - right.ticket);
  const catalogObservation = {
    initialized_at:
      campaignState.catalog_observation?.initialized_at ?? input.now,
    repositories: manifest.repositories.map(
      ({ repository_id, target_sha }) => ({ repository_id, target_sha }),
    ),
  };
  const observationChanged =
    JSON.stringify(catalogObservation) !==
    JSON.stringify(campaignState.catalog_observation);
  const changed =
    normalizedTerminal.retryPolicyNormalized > 0 ||
    normalizedTerminal.terminalized > 0 ||
    campaignsChanged ||
    observationChanged ||
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
    catalog_observation: catalogObservation,
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
      terminalized: normalizedTerminal.terminalized,
    } satisfies QueueSyncSummary,
  };
}
