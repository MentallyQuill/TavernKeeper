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

export type BacklogReason = "new" | "changed" | "retry" | "policy" | "staff";

export interface PlannedTarget {
  target: CurrentTarget;
  reason: BacklogReason;
  queueEntry: ScanQueueEntry;
  recoveryFingerprint?: string | undefined;
}

export interface BatchPlan {
  targets: PlannedTarget[];
  totalRemaining: number;
  runnableRemaining: number;
  delayedEntries: number;
  nextWakeAt: string | null;
  emergencyStopped: boolean;
  automaticHolds: number;
  recoveryProbes: number;
}

function parseCurrentManifest(input: CurrentTargetManifest) {
  return input.schema_version === 3
    ? TargetManifestV3Schema.parse(input)
    : TargetManifestV2Schema.parse(input);
}

function reasonFor(
  entry: ScanQueueEntry,
  target: CurrentTarget,
  index: ReportIndexV5,
  state: OperationsState,
  scannerPolicyVersion: string,
): BacklogReason {
  if (entry.consecutive_failures > 0) return "retry";
  if (entry.staff_requested === true) return "staff";
  const reports = index.reports.filter(
    ({ repository_id }) => repository_id === target.repository_id,
  );
  if (reports.length === 0) return "new";
  const covered = reports.some(
    (report) =>
      report.target_sha === target.target_sha &&
      report.scanner_policy_version === scannerPolicyVersion,
  );
  if (
    covered &&
    state.policy_campaigns.some(
      (campaign) =>
        campaign.status === "active" &&
        campaign.scanner_policy_version === scannerPolicyVersion &&
        campaign.repository_ids.includes(target.repository_id),
    )
  )
    return "policy";
  if (covered) return "staff";
  return "changed";
}

export function planBatch(
  manifestInput: CurrentTargetManifest,
  indexInput: ReportIndexV5,
  stateInput: OperationsState,
  now: string,
  scannerPolicyVersion = "3",
): BatchPlan {
  const manifest = parseCurrentManifest(manifestInput);
  const index = ReportIndexV5Schema.parse(indexInput);
  const state = OperationsStateSchema.parse(stateInput);
  const nowMs = Date.parse(now);
  if (!Number.isFinite(nowMs)) throw new Error("Backlog time is invalid.");

  const targetByRepositoryId = new Map(
    manifest.repositories.map((target) => [target.repository_id, target]),
  );
  const activeRepositoryIds = new Set(
    state.active_scans.map(({ repository_id }) => repository_id),
  );
  const available = [...state.scan_queue.entries]
    .filter(({ repository_id }) => !activeRepositoryIds.has(repository_id))
    .sort((left, right) => left.ticket - right.ticket);
  const delayed = available.filter(
    ({ not_before }) => not_before !== null && Date.parse(not_before) > nowMs,
  );
  const nextWakeAt =
    delayed
      .map(({ not_before }) => not_before!)
      .sort((left, right) => left.localeCompare(right))[0] ?? null;

  if (state.emergency_stop !== null)
    return {
      targets: [],
      totalRemaining: available.length,
      runnableRemaining: 0,
      delayedEntries: delayed.length,
      nextWakeAt: null,
      emergencyStopped: true,
      automaticHolds: state.automatic_holds.length,
      recoveryProbes: 0,
    };

  if (state.automatic_holds.length > 0) {
    const dueHold = [...state.automatic_holds]
      .filter(({ next_probe_at }) => Date.parse(next_probe_at) <= nowMs)
      .sort((left, right) =>
        [left.next_probe_at, left.error_fingerprint]
          .join(":")
          .localeCompare(
            [right.next_probe_at, right.error_fingerprint].join(":"),
          ),
      )[0];
    const probeEntry =
      dueHold === undefined
        ? undefined
        : available.find(
            ({ not_before }) =>
              not_before === null || Date.parse(not_before) <= nowMs,
          );
    const targets: PlannedTarget[] = [];
    if (dueHold !== undefined && probeEntry !== undefined) {
      const target = targetByRepositoryId.get(probeEntry.repository_id);
      if (target === undefined || target.target_sha !== probeEntry.target_sha)
        throw new Error(
          "Committed scan queue is not synchronized with the target manifest.",
        );
      targets.push({
        target,
        reason: reasonFor(
          probeEntry,
          target,
          index,
          state,
          scannerPolicyVersion,
        ),
        queueEntry: probeEntry,
        recoveryFingerprint: dueHold.error_fingerprint,
      });
    }
    const futureHoldWake = state.automatic_holds
      .filter(({ next_probe_at }) => Date.parse(next_probe_at) > nowMs)
      .map(({ next_probe_at }) => next_probe_at)
      .sort((left, right) => left.localeCompare(right))[0];
    const queueWake = delayed
      .map(({ not_before }) => not_before!)
      .sort((left, right) => left.localeCompare(right))[0];
    return {
      targets,
      totalRemaining: Math.max(0, available.length - targets.length),
      runnableRemaining: 0,
      delayedEntries: delayed.length,
      nextWakeAt:
        targets.length > 0
          ? null
          : ([futureHoldWake, queueWake]
              .filter((value): value is string => value !== undefined)
              .sort((left, right) => left.localeCompare(right))[0] ?? null),
      emergencyStopped: false,
      automaticHolds: state.automatic_holds.length,
      recoveryProbes: targets.length,
    };
  }

  const runnable = available
    .filter(
      ({ not_before }) =>
        not_before === null || Date.parse(not_before) <= nowMs,
    )
    .map((entry): PlannedTarget => {
      const target = targetByRepositoryId.get(entry.repository_id);
      if (target === undefined || target.target_sha !== entry.target_sha)
        throw new Error(
          "Committed scan queue is not synchronized with the target manifest.",
        );
      return {
        target,
        reason: reasonFor(entry, target, index, state, scannerPolicyVersion),
        queueEntry: entry,
      };
    });
  const targets = runnable.slice(0, 5);
  return {
    targets,
    totalRemaining: Math.max(0, available.length - targets.length),
    runnableRemaining: Math.max(0, runnable.length - targets.length),
    delayedEntries: delayed.length,
    nextWakeAt,
    emergencyStopped: false,
    automaticHolds: 0,
    recoveryProbes: 0,
  };
}
