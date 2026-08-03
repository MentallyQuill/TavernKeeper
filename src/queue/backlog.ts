import {
  ReportIndexV4Schema,
  type ReportIndexV4,
} from "../contracts/reports.js";
import {
  TargetManifestV2Schema,
  type TargetManifestV2,
  type TargetV2,
} from "../contracts/targets.js";
import {
  OperationsStateSchema,
  type OperationsState,
} from "../operations/state.js";

export type BacklogReason = "new" | "changed" | "retry" | "policy";
export type BacklogLane = "top-30" | "new-submission" | "old-project";

export interface PlannedTarget {
  target: TargetV2;
  reason: BacklogReason;
  lane: BacklogLane;
  ageFrom: string;
}

export interface BatchPlan {
  targets: PlannedTarget[];
  remaining: number;
  blocked: boolean;
}

const LANE_RANK: Record<BacklogLane, number> = {
  "top-30": 0,
  "new-submission": 1,
  "old-project": 2,
};
const AGE_BOOST_MS = 30 * 24 * 60 * 60 * 1_000;

function laneFor(target: TargetV2, coverageStartedAt: string | null) {
  if (target.catalog_priority.top_30) return "top-30" as const;
  if (
    coverageStartedAt !== null &&
    Date.parse(target.catalog_priority.first_cataloged_at) >=
      Date.parse(coverageStartedAt)
  )
    return "new-submission" as const;
  return "old-project" as const;
}

function waitStartedAt(item: PlannedTarget, coverageStartedAt: string | null) {
  if (item.lane === "old-project")
    return coverageStartedAt ?? item.target.catalog_priority.first_cataloged_at;
  if (item.lane === "new-submission")
    return item.target.catalog_priority.first_cataloged_at;
  return item.ageFrom;
}

function effectiveRank(
  item: PlannedTarget,
  coverageStartedAt: string | null,
  nowMs: number,
) {
  const waited = Math.max(
    0,
    nowMs - Date.parse(waitStartedAt(item, coverageStartedAt)),
  );
  return Math.max(0, LANE_RANK[item.lane] - Math.floor(waited / AGE_BOOST_MS));
}

export function planBatch(
  manifestInput: TargetManifestV2,
  indexInput: ReportIndexV4,
  stateInput: OperationsState,
  now: string,
  scannerPolicyVersion = "2",
): BatchPlan {
  const manifest = TargetManifestV2Schema.parse(manifestInput);
  const index = ReportIndexV4Schema.parse(indexInput);
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
      ageFrom = target.catalog_priority.first_cataloged_at;
    } else if (!covered) {
      reason = "changed";
      ageFrom = reports.map(({ completed_at }) => completed_at).sort()[0]!;
    } else if (campaign !== undefined) {
      reason = "policy";
      ageFrom = campaign.created_at;
    }
    if (reason !== null)
      planned.push({
        target,
        reason,
        lane: laneFor(target, state.coverage_started_at),
        ageFrom,
      });
  }

  planned.sort((left, right) => {
    const priority =
      effectiveRank(left, state.coverage_started_at, nowMs) -
      effectiveRank(right, state.coverage_started_at, nowMs);
    if (priority !== 0) return priority;
    const wait =
      Date.parse(waitStartedAt(left, state.coverage_started_at)) -
      Date.parse(waitStartedAt(right, state.coverage_started_at));
    if (wait !== 0) return wait;
    const lane = LANE_RANK[left.lane] - LANE_RANK[right.lane];
    if (lane !== 0) return lane;
    const catalogAge =
      Date.parse(left.target.catalog_priority.first_cataloged_at) -
      Date.parse(right.target.catalog_priority.first_cataloged_at);
    return catalogAge !== 0
      ? catalogAge
      : left.target.repository_id - right.target.repository_id;
  });
  const breaker = state.circuit_breaker;
  const available =
    breaker === null
      ? planned
      : planned
          .filter(({ target, reason }) => {
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
          })
          .slice(0, 1);
  const targets = state.pause === null ? available.slice(0, 5) : [];
  const blocked =
    state.pause !== null || (breaker !== null && targets.length === 0);
  return {
    targets,
    remaining: planned.length - targets.length,
    blocked,
  };
}
