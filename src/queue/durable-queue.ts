import { TargetSchema, type Target } from "../contracts/targets.js";
import { CURRENT_SCANNER_POLICY_VERSION } from "../config/policy.js";
import {
  FailureDescriptorSchema,
  failureFingerprint,
  type FailureDescriptor,
} from "../operations/failure.js";
import { targetRetryNotBefore } from "../operations/retry-schedule.js";
import {
  OperationsStateSchema,
  type OperationsState,
  type ScanQueueEntry,
  type UnscannableTarget,
} from "../operations/state.js";

function targetMatches(
  entry: Pick<ScanQueueEntry, "repository_id" | "target_sha">,
  target: Pick<Target, "repository_id" | "target_sha">,
) {
  return (
    entry.repository_id === target.repository_id &&
    entry.target_sha === target.target_sha
  );
}

function entryForTarget(target: Target, ticket: number): ScanQueueEntry {
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
    chronic: false,
  };
}

function parseTargetIdentity(target: Target) {
  return TargetSchema.parse({
    source_id: target.source_id,
    provider: target.provider,
    repository_id: target.repository_id,
    repository: target.repository,
    target_sha: target.target_sha,
    canonical_url: target.canonical_url,
  });
}

export function effectiveQueueEntryNotBefore(
  entry: ScanQueueEntry,
  state: OperationsState,
  scannerPolicyVersion: string = CURRENT_SCANNER_POLICY_VERSION,
) {
  const activePolicyTarget = state.policy_campaigns.some(
    (campaign) =>
      campaign.status === "active" &&
      campaign.scanner_policy_version === scannerPolicyVersion &&
      campaign.repository_ids.includes(entry.repository_id),
  );
  const automaticRescanNotBefore =
    entry.rescan_not_before === undefined ||
    entry.staff_requested === true ||
    entry.consecutive_failures > 0 ||
    activePolicyTarget
      ? null
      : entry.rescan_not_before;
  return (
    [entry.not_before, automaticRescanNotBefore]
      .filter((value): value is string => value !== null)
      .sort((left, right) => right.localeCompare(left))[0] ?? null
  );
}

export function appendQueuedTarget(
  stateInput: OperationsState,
  targetInput: Target,
  options: {
    staffRequested?: boolean;
    catalogChange?: "new" | "updated";
  } = {},
) {
  const state = OperationsStateSchema.parse(stateInput);
  const target = parseTargetIdentity(targetInput);
  if (
    state.unscannable_targets.some(
      ({ repository_id }) => repository_id === target.repository_id,
    )
  )
    throw new Error("Unscannable repository requires protected add-back.");
  const existing = state.scan_queue.entries.find(
    ({ repository_id }) => repository_id === target.repository_id,
  );
  if (existing !== undefined) {
    if (existing.target_sha === target.target_sha) {
      const promoteToStaff =
        options.staffRequested === true && existing.staff_requested !== true;
      const addCatalogChange =
        options.catalogChange !== undefined &&
        existing.catalog_change === undefined;
      if (!promoteToStaff && !addCatalogChange) return state;
      return OperationsStateSchema.parse({
        ...state,
        scan_queue: {
          ...state.scan_queue,
          entries: state.scan_queue.entries.map((entry) => {
            if (entry.repository_id !== target.repository_id) return entry;
            const enrichedEntry = {
              ...entry,
              ...(addCatalogChange
                ? { catalog_change: options.catalogChange }
                : {}),
            };
            if (!promoteToStaff) return enrichedEntry;
            const { rescan_not_before: _ignored, ...staffEntry } =
              enrichedEntry;
            return { ...staffEntry, staff_requested: true };
          }),
        },
      });
    }
    throw new Error("Repository already has a different queued target SHA.");
  }
  if (state.scan_queue.next_ticket >= Number.MAX_SAFE_INTEGER)
    throw new Error("Scan queue ticket space is exhausted.");

  return OperationsStateSchema.parse({
    ...state,
    scan_queue: {
      next_ticket: state.scan_queue.next_ticket + 1,
      entries: [
        ...state.scan_queue.entries,
        {
          ...entryForTarget(target, state.scan_queue.next_ticket),
          ...(options.staffRequested === true ? { staff_requested: true } : {}),
          ...(options.catalogChange !== undefined
            ? { catalog_change: options.catalogChange }
            : {}),
        },
      ],
    },
  });
}

export function dueQueueEntries(
  stateInput: OperationsState,
  now: string,
  limit = 5,
  scannerPolicyVersion: string = CURRENT_SCANNER_POLICY_VERSION,
) {
  const state = OperationsStateSchema.parse(stateInput);
  const nowMs = Date.parse(now);
  if (!Number.isFinite(nowMs)) throw new Error("Queue time is invalid.");
  if (!Number.isSafeInteger(limit) || limit < 0)
    throw new Error("Queue selection limit is invalid.");
  if (state.emergency_stop !== null) return [];
  return [...state.scan_queue.entries]
    .filter((entry) => {
      const notBefore = effectiveQueueEntryNotBefore(
        entry,
        state,
        scannerPolicyVersion,
      );
      return notBefore === null || Date.parse(notBefore) <= nowMs;
    })
    .sort((left, right) => left.ticket - right.ticket)
    .slice(0, limit);
}

export function addBackUnscannableTarget(
  stateInput: OperationsState,
  repositoryId: number,
) {
  const state = OperationsStateSchema.parse(stateInput);
  if (!Number.isSafeInteger(repositoryId) || repositoryId < 1)
    throw new Error("Staff add-back repository ID is invalid.");
  if (
    !state.unscannable_targets.some(
      ({ repository_id }) => repository_id === repositoryId,
    )
  )
    throw new Error("Staff add-back repository is not unscannable.");
  return OperationsStateSchema.parse({
    ...state,
    unscannable_targets: state.unscannable_targets.filter(
      ({ repository_id }) => repository_id !== repositoryId,
    ),
  });
}

export function prioritizeQueuedTargetRetry(
  stateInput: OperationsState,
  repositoryId: number,
) {
  const state = OperationsStateSchema.parse(stateInput);
  if (!Number.isSafeInteger(repositoryId) || repositoryId < 1)
    throw new Error("Staff retry repository ID is invalid.");
  if (
    !state.scan_queue.entries.some(
      ({ repository_id }) => repository_id === repositoryId,
    )
  )
    throw new Error("Staff retry repository is not queued.");
  return OperationsStateSchema.parse({
    ...state,
    scan_queue: {
      ...state.scan_queue,
      entries: state.scan_queue.entries.map((entry) =>
        entry.repository_id === repositoryId
          ? { ...entry, not_before: null, staff_requested: true }
          : entry,
      ),
    },
  });
}

export function revokeQueuedTargetStaffRequest(
  stateInput: OperationsState,
  repositoryId: number,
) {
  const state = OperationsStateSchema.parse(stateInput);
  if (!Number.isSafeInteger(repositoryId) || repositoryId < 1)
    throw new Error("Staff revoke repository ID is invalid.");
  const queued = state.scan_queue.entries.find(
    ({ repository_id }) => repository_id === repositoryId,
  );
  if (queued === undefined)
    throw new Error("Staff revoke repository is not queued.");
  if (queued.staff_requested !== true) return state;
  return OperationsStateSchema.parse({
    ...state,
    scan_queue: {
      ...state.scan_queue,
      entries: state.scan_queue.entries.map((entry) => {
        if (entry.repository_id !== repositoryId) return entry;
        const { staff_requested: _revoked, ...revoked } = entry;
        return revoked;
      }),
    },
  });
}

export function rotateFailedTarget(
  stateInput: OperationsState,
  input: { target: Target; failure: FailureDescriptor; at: string },
) {
  let state = OperationsStateSchema.parse(stateInput);
  const target = parseTargetIdentity(input.target);
  const failure = FailureDescriptorSchema.parse(input.failure);
  if (!Number.isFinite(Date.parse(input.at)))
    throw new Error("Queue failure time is invalid.");

  let current = state.scan_queue.entries.find((entry) =>
    targetMatches(entry, target),
  );
  if (current === undefined) {
    state = appendQueuedTarget(state, target);
    current = state.scan_queue.entries.find((entry) =>
      targetMatches(entry, target),
    )!;
  }
  if (state.scan_queue.next_ticket >= Number.MAX_SAFE_INTEGER)
    throw new Error("Scan queue ticket space is exhausted.");

  const consecutiveFailures = current.consecutive_failures + 1;
  const entry: ScanQueueEntry = {
    ...current,
    source_id: target.source_id,
    repository: target.repository,
    ticket:
      consecutiveFailures >= 3
        ? current.ticket
        : state.scan_queue.next_ticket,
    consecutive_failures: consecutiveFailures,
    total_failures: current.total_failures + 1,
    not_before:
      consecutiveFailures >= 3
        ? null
        : targetRetryNotBefore(input.at, consecutiveFailures),
    last_failure: failure,
    last_failed_at: input.at,
    chronic: consecutiveFailures >= 2,
    failure_history: [
      ...(current.failure_history ?? []),
      {
        failed_at: input.at,
        failure,
        error_fingerprint: failureFingerprint(failure),
      },
    ].slice(-4),
  };
  if (consecutiveFailures >= 3) {
    const unscannable: UnscannableTarget = {
      source_id: entry.source_id,
      repository_id: entry.repository_id,
      repository: entry.repository,
      target_sha: entry.target_sha,
      unscannable_at: input.at,
      consecutive_failures: entry.consecutive_failures,
      total_failures: entry.total_failures,
      last_failure: failure,
      last_failed_at: input.at,
      failure_history: entry.failure_history!,
    };
    const terminalState = OperationsStateSchema.parse({
      ...state,
      updated_at: input.at,
      unscannable_targets: [
        ...state.unscannable_targets.filter(
          ({ repository_id }) => repository_id !== target.repository_id,
        ),
        unscannable,
      ],
      scan_queue: {
        ...state.scan_queue,
        entries: state.scan_queue.entries.filter(
          ({ repository_id }) => repository_id !== target.repository_id,
        ),
      },
      active_scans: state.active_scans.filter(
        ({ repository_id }) => repository_id !== target.repository_id,
      ),
    });
    return {
      state: terminalState,
      entry,
      becameChronic: false,
      terminal: true,
      unscannable,
    } as const;
  }
  const nextState = OperationsStateSchema.parse({
    ...state,
    updated_at: input.at,
    scan_queue: {
      next_ticket: state.scan_queue.next_ticket + 1,
      entries: [
        ...state.scan_queue.entries.filter(
          ({ repository_id }) => repository_id !== target.repository_id,
        ),
        entry,
      ],
    },
    active_scans: state.active_scans.filter(
      (active) => !targetMatches(active, target),
    ),
  });
  return {
    state: nextState,
    entry,
    becameChronic: consecutiveFailures === 2,
    terminal: false,
  } as const;
}

export function replaceQueuedTargetSha(
  stateInput: OperationsState,
  targetInput: Target,
  at: string,
) {
  const state = OperationsStateSchema.parse(stateInput);
  const target = parseTargetIdentity(targetInput);
  if (!Number.isFinite(Date.parse(at)))
    throw new Error("Queue replacement time is invalid.");
  const current = state.scan_queue.entries.find(
    ({ repository_id }) => repository_id === target.repository_id,
  );
  if (current === undefined) return appendQueuedTarget(state, target);
  if (current.target_sha === target.target_sha) return state;

  return OperationsStateSchema.parse({
    ...state,
    updated_at: at,
    scan_queue: {
      ...state.scan_queue,
      entries: state.scan_queue.entries.map((entry) =>
        entry.repository_id === target.repository_id
          ? {
              ...entry,
              source_id: target.source_id,
              repository: target.repository,
              target_sha: target.target_sha,
            }
          : entry,
      ),
    },
    active_scans: state.active_scans.filter(
      ({ repository_id }) => repository_id !== target.repository_id,
    ),
  });
}

export function removeSuccessfulTarget(
  stateInput: OperationsState,
  targetInput: Target,
  at: string,
) {
  const state = OperationsStateSchema.parse(stateInput);
  const target = parseTargetIdentity(targetInput);
  if (!Number.isFinite(Date.parse(at)))
    throw new Error("Queue success time is invalid.");
  return OperationsStateSchema.parse({
    ...state,
    updated_at: at,
    scan_queue: {
      ...state.scan_queue,
      entries: state.scan_queue.entries.filter(
        (entry) => !targetMatches(entry, target),
      ),
    },
    active_scans: state.active_scans.filter(
      (active) => !targetMatches(active, target),
    ),
  });
}
