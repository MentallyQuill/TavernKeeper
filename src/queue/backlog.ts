import { ReportIndexSchema, type ReportIndex } from "../contracts/reports.js";
import {
  TargetManifestSchema,
  type Target,
  type TargetManifest,
} from "../contracts/targets.js";
import {
  OperationsStateSchema,
  type OperationsState,
} from "../operations/state.js";

export type BacklogReason = "new" | "changed" | "retry" | "policy";

export interface PlannedTarget {
  target: Target;
  reason: BacklogReason;
  ageFrom: string;
}

export interface BatchPlan {
  targets: PlannedTarget[];
  remaining: number;
  blocked: boolean;
}

function reasonPriority(reason: BacklogReason) {
  return { new: 0, changed: 1, retry: 2, policy: 3 }[reason];
}

export function planBatch(
  manifestInput: TargetManifest,
  indexInput: ReportIndex,
  stateInput: OperationsState,
  now: string,
  scannerPolicyVersion = "1",
): BatchPlan {
  const manifest = TargetManifestSchema.parse(manifestInput);
  const index = ReportIndexSchema.parse(indexInput);
  const state = OperationsStateSchema.parse(stateInput);
  const nowMs = Date.parse(now);
  if (!Number.isFinite(nowMs)) throw new Error("Backlog time is invalid.");

  const activeRepositoryIds = new Set(
    state.active_scans.map(({ repository_id }) => repository_id),
  );
  const planned: PlannedTarget[] = [];
  for (const target of manifest.repositories) {
    if (activeRepositoryIds.has(target.repository_id)) continue;
    const reports = index.reports.filter(
      ({ repository_id }) => repository_id === target.repository_id,
    );
    const covered = reports.some(
      (report) =>
        report.target_sha === target.target_sha &&
        report.scanner_policy_version === scannerPolicyVersion,
    );
    const retry = state.retries.find(
      (entry) =>
        entry.repository_id === target.repository_id &&
        entry.target_sha === target.target_sha &&
        !entry.exhausted,
    );
    if (
      retry !== undefined &&
      (retry.next_retry_at === null || Date.parse(retry.next_retry_at) > nowMs)
    )
      continue;
    const campaign = state.policy_campaigns.find(
      (item) =>
        item.status === "active" &&
        item.scanner_policy_version === scannerPolicyVersion &&
        item.repository_ids.includes(target.repository_id),
    );
    let reason: BacklogReason | null = null;
    let ageFrom = manifest.generated_at;
    if (retry !== undefined) {
      reason = "retry";
      ageFrom = retry.initial_failed_at;
    } else if (reports.length === 0) {
      reason = "new";
    } else if (!covered) {
      reason = "changed";
      ageFrom = reports.map(({ completed_at }) => completed_at).sort()[0]!;
    } else if (campaign !== undefined) {
      reason = "policy";
      ageFrom = campaign.created_at;
    }
    if (reason !== null) planned.push({ target, reason, ageFrom });
  }

  planned.sort((left, right) => {
    const priority = reasonPriority(left.reason) - reasonPriority(right.reason);
    if (priority !== 0) return priority;
    const age = Date.parse(left.ageFrom) - Date.parse(right.ageFrom);
    return age !== 0
      ? age
      : left.target.repository_id - right.target.repository_id;
  });
  const breaker = state.circuit_breaker;
  const breakerRecovery =
    breaker === null
      ? planned
      : planned.filter(({ target, reason }) => {
          if (reason !== "retry") return false;
          const retry = state.retries.find(
            (entry) =>
              entry.repository_id === target.repository_id &&
              entry.target_sha === target.target_sha,
          );
          return (
            retry?.scope === "system" &&
            retry.error_fingerprint === breaker.error_fingerprint
          );
        });
  const available =
    breaker === null ? breakerRecovery : breakerRecovery.slice(0, 1);
  const targets = state.pause === null ? available.slice(0, 5) : [];
  const blocked =
    state.pause !== null || (breaker !== null && targets.length === 0);
  return {
    targets,
    remaining: planned.length - targets.length,
    blocked,
  };
}
