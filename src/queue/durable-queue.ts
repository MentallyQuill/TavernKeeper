import { TargetSchema, type Target } from "../contracts/targets.js";
import {
  FailureDescriptorSchema,
  failureFingerprint,
  type FailureDescriptor,
} from "../operations/failure.js";
import { scanRetryAt } from "../operations/retry-schedule.js";
import {
  OperationsStateSchema,
  type OperationsState,
  type ScanQueueEntry,
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
  scannerPolicyVersion = "3",
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
  options: { staffRequested?: boolean } = {},
) {
  const state = OperationsStateSchema.parse(stateInput);
  const target = parseTargetIdentity(targetInput);
  const existing = state.scan_queue.entries.find(
    ({ repository_id }) => repository_id === target.repository_id,
  );
  if (existing !== undefined) {
    if (existing.target_sha === target.target_sha) {
      if (options.staffRequested !== true || existing.staff_requested === true)
        return state;
      return OperationsStateSchema.parse({
        ...state,
        scan_queue: {
          ...state.scan_queue,
          entries: state.scan_queue.entries.map((entry) => {
            if (entry.repository_id !== target.repository_id) return entry;
            const { rescan_not_before: _ignored, ...staffEntry } = entry;
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
        },
      ],
    },
  });
}

export function dueQueueEntries(
  stateInput: OperationsState,
  now: string,
  limit = 5,
  scannerPolicyVersion = "3",
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
    ticket: state.scan_queue.next_ticket,
    consecutive_failures: consecutiveFailures,
    total_failures: current.total_failures + 1,
    not_before: scanRetryAt(input.at, consecutiveFailures),
    last_failure: failure,
    last_failed_at: input.at,
    chronic: consecutiveFailures >= 5,
    failure_history: [
      ...(current.failure_history ?? []),
      {
        failed_at: input.at,
        failure,
        error_fingerprint: failureFingerprint(failure),
      },
    ].slice(-4),
  };
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
    becameChronic: consecutiveFailures === 5,
  };
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
              ...entryForTarget(target, entry.ticket),
              total_failures: entry.total_failures,
              ...(entry.staff_requested === true
                ? { staff_requested: true }
                : {}),
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
