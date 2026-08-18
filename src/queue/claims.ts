import {
  OperationsStateSchema,
  type OperationsState,
} from "../operations/state.js";
import type { PlannedTarget } from "./backlog.js";

export const ACTIVE_SCAN_CAPACITY = 2;
export const ACTIVE_SCAN_LEASE_MS = 2 * 60 * 60 * 1_000;

export function expireStaleScanClaims(
  stateInput: OperationsState,
  now: string,
) {
  const state = OperationsStateSchema.parse(stateInput);
  const nowMs = Date.parse(now);
  if (!Number.isFinite(nowMs)) throw new Error("Scan claim time is invalid.");
  const activeScans = state.active_scans.filter(
    ({ started_at }) => Date.parse(started_at) + ACTIVE_SCAN_LEASE_MS > nowMs,
  );
  const expired = state.active_scans.length - activeScans.length;
  return {
    state: OperationsStateSchema.parse({
      ...state,
      updated_at: expired > 0 ? now : state.updated_at,
      active_scans: activeScans,
    }),
    expired,
    changed: expired > 0,
  };
}

export function claimScanSlots(input: {
  state: OperationsState;
  plannedTargets: PlannedTarget[];
  now: string;
  runId: string;
}) {
  const expiredClaims = expireStaleScanClaims(input.state, input.now);
  const state = expiredClaims.state;
  if (!/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/u.test(input.runId))
    throw new Error("Scan claim run ID is invalid.");

  const activeScans = state.active_scans;
  const activeRepositoryIds = new Set(
    activeScans.map(({ repository_id }) => repository_id),
  );
  const capacity = Math.max(0, ACTIVE_SCAN_CAPACITY - activeScans.length);
  const claimed = input.plannedTargets
    .filter(({ target }) => !activeRepositoryIds.has(target.repository_id))
    .slice(0, capacity);
  const additions = claimed.map(({ target }) => ({
    source_id: target.source_id,
    repository_id: target.repository_id,
    target_sha: target.target_sha,
    started_at: input.now,
    run_id: `${input.runId}-${target.repository_id}`,
  }));
  const claimedRepositoryIds = new Set(
    claimed.map(({ target }) => target.repository_id),
  );
  const queueEntries = state.scan_queue.entries.map((entry) => {
    if (!claimedRepositoryIds.has(entry.repository_id)) return entry;
    const { staff_requested: _consumed, ...consumed } = entry;
    return consumed;
  });
  const changed = expiredClaims.changed || additions.length > 0;
  const nextState = OperationsStateSchema.parse({
    ...state,
    updated_at: changed ? input.now : state.updated_at,
    scan_queue: { ...state.scan_queue, entries: queueEntries },
    active_scans: [...activeScans, ...additions],
  });
  return {
    state: nextState,
    claimed,
    expired: expiredClaims.expired,
    capacity: Math.max(0, ACTIVE_SCAN_CAPACITY - nextState.active_scans.length),
    changed,
  };
}
