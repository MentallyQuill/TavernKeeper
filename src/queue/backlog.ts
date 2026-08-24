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
  CURRENT_CONTEXTUAL_REVIEW_POLICY_VERSION,
  CURRENT_SCANNER_POLICY_VERSION,
} from "../config/policy.js";
import {
  OperationsStateSchema,
  type OperationsState,
  type ScanQueueEntry,
} from "../operations/state.js";
import { failureFingerprint } from "../operations/failure.js";
import { effectiveQueueEntryNotBefore } from "./durable-queue.js";

export type BacklogReason =
  "new" | "changed" | "retry" | "policy" | "coverage" | "staff";

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
  providerProbeFingerprint: string | null;
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
  contextualReviewPolicyVersion: string,
): BacklogReason {
  if (entry.consecutive_failures > 0) return "retry";
  if (entry.staff_requested === true) return "staff";
  if (
    state.policy_campaigns.some(
      (campaign) =>
        campaign.status === "active" &&
        campaign.scanner_policy_version === scannerPolicyVersion &&
        campaign.repository_ids.includes(target.repository_id),
    )
  )
    return "policy";
  if (entry.catalog_change === "new") return "new";
  if (entry.catalog_change === "updated") return "changed";
  const reports = index.reports.filter(
    ({ repository_id }) => repository_id === target.repository_id,
  );
  const hasCurrentTarget = reports.some(
    (report) =>
      report.target_sha === target.target_sha &&
      report.scanner_policy_version === scannerPolicyVersion &&
      report.contextual_review_policy_version === contextualReviewPolicyVersion,
  );
  if (!hasCurrentTarget && reports.length > 0) return "changed";
  if (
    state.coverage_campaigns.some(
      (campaign) =>
        campaign.status === "active" &&
        campaign.scanner_policy_version === scannerPolicyVersion &&
        campaign.remaining_repository_ids.includes(target.repository_id),
    )
  )
    return "coverage";
  return "changed";
}

function queuePriority(
  entry: ScanQueueEntry,
  state: OperationsState,
  scannerPolicyVersion: string,
) {
  if (entry.staff_requested === true) return 0;
  if (
    state.policy_campaigns.some(
      (campaign) =>
        campaign.status === "active" &&
        campaign.scanner_policy_version === scannerPolicyVersion &&
        campaign.repository_ids.includes(entry.repository_id),
    )
  )
    return 1;
  if (entry.catalog_change === "new") return 2;
  if (entry.catalog_change === "updated") return 3;
  if (
    state.coverage_campaigns.some(
      (campaign) =>
        campaign.status === "active" &&
        campaign.scanner_policy_version === scannerPolicyVersion &&
        campaign.remaining_repository_ids.includes(entry.repository_id),
    )
  )
    return 4;
  return 5;
}

export function planBatch(
  manifestInput: CurrentTargetManifest,
  indexInput: ReportIndexV5,
  stateInput: OperationsState,
  now: string,
  scannerPolicyVersion: string = CURRENT_SCANNER_POLICY_VERSION,
  contextualReviewPolicyVersion: string = CURRENT_CONTEXTUAL_REVIEW_POLICY_VERSION,
  forceProviderProbe = false,
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
  const allAvailable = [...state.scan_queue.entries]
    .filter(({ repository_id }) => !activeRepositoryIds.has(repository_id))
    .sort(
      (left, right) =>
        queuePriority(left, state, scannerPolicyVersion) -
          queuePriority(right, state, scannerPolicyVersion) ||
        Number(left.consecutive_failures > 0) -
          Number(right.consecutive_failures > 0) ||
        left.ticket - right.ticket,
    );
  const policyCanaryGate =
    state.emergency_stop !== null &&
    state.emergency_stop.reason_code ===
      `POLICY_V${scannerPolicyVersion}_CANARY_GATE`;
  const available = policyCanaryGate
    ? allAvailable.filter(({ staff_requested }) => staff_requested === true)
    : allAvailable;
  const delayed = available.filter((entry) => {
    const notBefore = effectiveQueueEntryNotBefore(
      entry,
      state,
      scannerPolicyVersion,
    );
    return notBefore !== null && Date.parse(notBefore) > nowMs;
  });
  const nextWakeAt =
    delayed
      .map((entry) =>
        effectiveQueueEntryNotBefore(entry, state, scannerPolicyVersion),
      )
      .filter((value): value is string => value !== null)
      .sort((left, right) => left.localeCompare(right))[0] ?? null;

  if (state.emergency_stop !== null && !policyCanaryGate)
    return {
      targets: [],
      totalRemaining: allAvailable.length,
      runnableRemaining: 0,
      delayedEntries: delayed.length,
      nextWakeAt: null,
      emergencyStopped: true,
      automaticHolds: state.automatic_holds.length,
      recoveryProbes: 0,
      providerProbeFingerprint: null,
    };

  if (policyCanaryGate && available.length === 0)
    return {
      targets: [],
      totalRemaining: 0,
      runnableRemaining: 0,
      delayedEntries: 0,
      nextWakeAt: null,
      emergencyStopped: true,
      automaticHolds: state.automatic_holds.length,
      recoveryProbes: 0,
      providerProbeFingerprint: null,
    };

  if (state.automatic_holds.length > 0) {
    const dueHold = [...state.automatic_holds]
      .filter(
        ({ error_fingerprint, last_failed_at, next_probe_at }) =>
          forceProviderProbe ||
          Date.parse(next_probe_at) <= nowMs ||
          state.scan_queue.entries.some(
            (entry) =>
              entry.last_failure !== null &&
              entry.last_failure.domain !== "target" &&
              entry.last_failed_at === last_failed_at &&
              failureFingerprint(entry.last_failure) === error_fingerprint,
          ),
      )
      .sort((left, right) =>
        [left.next_probe_at, left.error_fingerprint]
          .join(":")
          .localeCompare(
            [right.next_probe_at, right.error_fingerprint].join(":"),
          ),
      )[0];
    const targets: PlannedTarget[] = [];
    const futureHoldWake = state.automatic_holds
      .filter(({ next_probe_at }) => Date.parse(next_probe_at) > nowMs)
      .map(({ next_probe_at }) => next_probe_at)
      .sort((left, right) => left.localeCompare(right))[0];
    const queueWake = delayed
      .map((entry) =>
        effectiveQueueEntryNotBefore(entry, state, scannerPolicyVersion),
      )
      .filter((value): value is string => value !== null)
      .sort((left, right) => left.localeCompare(right))[0];
    return {
      targets,
      totalRemaining: available.length,
      runnableRemaining: 0,
      delayedEntries: delayed.length,
      nextWakeAt:
        dueHold !== undefined
          ? null
          : ([futureHoldWake, queueWake]
              .filter((value): value is string => value !== undefined)
              .sort((left, right) => left.localeCompare(right))[0] ?? null),
      emergencyStopped: state.emergency_stop !== null,
      automaticHolds: state.automatic_holds.length,
      recoveryProbes: dueHold === undefined ? 0 : 1,
      providerProbeFingerprint: dueHold?.error_fingerprint ?? null,
    };
  }

  const runnable = available
    .filter((entry) => {
      const notBefore = effectiveQueueEntryNotBefore(
        entry,
        state,
        scannerPolicyVersion,
      );
      return notBefore === null || Date.parse(notBefore) <= nowMs;
    })
    .map((entry): PlannedTarget => {
      const target = targetByRepositoryId.get(entry.repository_id);
      if (target === undefined || target.target_sha !== entry.target_sha)
        throw new Error(
          "Committed scan queue is not synchronized with the target manifest.",
        );
      return {
        target,
        reason: reasonFor(
          entry,
          target,
          index,
          state,
          scannerPolicyVersion,
          contextualReviewPolicyVersion,
        ),
        queueEntry: entry,
      };
    });
  const targets = runnable.slice(0, policyCanaryGate ? 1 : 5);
  return {
    targets,
    totalRemaining: Math.max(0, available.length - targets.length),
    runnableRemaining: Math.max(0, runnable.length - targets.length),
    delayedEntries: delayed.length,
    nextWakeAt,
    emergencyStopped: state.emergency_stop !== null,
    automaticHolds: 0,
    recoveryProbes: 0,
    providerProbeFingerprint: null,
  };
}
