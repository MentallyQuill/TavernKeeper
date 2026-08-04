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
  type TargetRetryEntry,
} from "../operations/state.js";

export type BacklogReason = "new" | "changed" | "retry" | "policy";
export type BacklogLane = "top-30" | "new-submission" | "old-project";

export interface PlannedTarget {
  target: CurrentTarget;
  reason: BacklogReason;
  lane: BacklogLane;
  ageFrom: string;
  recoveryFingerprint?: string;
}

export interface BatchPlan {
  targets: PlannedTarget[];
  totalRemaining: number;
  runnableRemaining: number;
  delayedRetries: number;
  sharedHolds: number;
  nextWakeAt: string | null;
  blocked: boolean;
}

const LANE_RANK: Record<BacklogLane, number> = {
  "top-30": 0,
  "new-submission": 1,
  "old-project": 2,
};
const AGE_BOOST_MS = 30 * 24 * 60 * 60 * 1_000;

function parseCurrentManifest(input: CurrentTargetManifest) {
  return input.schema_version === 3
    ? TargetManifestV3Schema.parse(input)
    : TargetManifestV2Schema.parse(input);
}

function laneFor(target: CurrentTarget, coverageStartedAt: string | null) {
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

function targetIdentity(target: CurrentTarget) {
  return `${target.repository_id}:${target.target_sha}`;
}

function retryIdentity(retry: TargetRetryEntry) {
  return `${retry.repository_id}:${retry.target_sha}`;
}

function futureTimes(values: Array<string | null>, nowMs: number) {
  return values
    .filter((value): value is string =>
      value === null ? false : Date.parse(value) > nowMs,
    )
    .sort();
}

function v2FallbackComparator(
  left: PlannedTarget,
  right: PlannedTarget,
  coverageStartedAt: string | null,
  nowMs: number,
) {
  const priority =
    effectiveRank(left, coverageStartedAt, nowMs) -
    effectiveRank(right, coverageStartedAt, nowMs);
  if (priority !== 0) return priority;
  const wait =
    Date.parse(waitStartedAt(left, coverageStartedAt)) -
    Date.parse(waitStartedAt(right, coverageStartedAt));
  if (wait !== 0) return wait;
  const lane = LANE_RANK[left.lane] - LANE_RANK[right.lane];
  if (lane !== 0) return lane;
  const catalogAge =
    Date.parse(left.target.catalog_priority.first_cataloged_at) -
    Date.parse(right.target.catalog_priority.first_cataloged_at);
  return catalogAge !== 0
    ? catalogAge
    : left.target.repository_id - right.target.repository_id;
}

function sortedRunnable(
  planned: PlannedTarget[],
  manifest: CurrentTargetManifest,
  state: OperationsState,
  nowMs: number,
) {
  const retryByIdentity = new Map(
    state.target_retries.map((retry) => [retryIdentity(retry), retry]),
  );
  return [...planned].sort((left, right) => {
    if (left.reason === "retry" && right.reason !== "retry") return -1;
    if (right.reason === "retry" && left.reason !== "retry") return 1;
    if (left.reason === "retry" && right.reason === "retry") {
      const leftRetry = retryByIdentity.get(targetIdentity(left.target))!;
      const rightRetry = retryByIdentity.get(targetIdentity(right.target))!;
      return [leftRetry.next_retry_at, leftRetry.initial_failed_at]
        .join(":")
        .localeCompare(
          [rightRetry.next_retry_at, rightRetry.initial_failed_at].join(":"),
        );
    }
    if (manifest.schema_version === 3) {
      if (
        !("popularity_rank" in left.target.catalog_priority) ||
        !("popularity_rank" in right.target.catalog_priority)
      )
        throw new Error("Ranked target manifest lost popularity metadata.");
      const rank =
        left.target.catalog_priority.popularity_rank -
        right.target.catalog_priority.popularity_rank;
      if (rank !== 0) return rank;
      const catalogAge =
        Date.parse(left.target.catalog_priority.first_cataloged_at) -
        Date.parse(right.target.catalog_priority.first_cataloged_at);
      return catalogAge !== 0
        ? catalogAge
        : left.target.repository_id - right.target.repository_id;
    }
    return v2FallbackComparator(left, right, state.coverage_started_at, nowMs);
  });
}

export function planBatch(
  manifestInput: CurrentTargetManifest,
  indexInput: ReportIndexV5,
  stateInput: OperationsState,
  now: string,
  scannerPolicyVersion = "2",
): BatchPlan {
  const manifest = parseCurrentManifest(manifestInput);
  const index = ReportIndexV5Schema.parse(indexInput);
  const state = OperationsStateSchema.parse(stateInput);
  const nowMs = Date.parse(now);
  if (!Number.isFinite(nowMs)) throw new Error("Backlog time is invalid.");

  const activeRepositoryIds = new Set(
    state.active_scans.map(({ repository_id }) => repository_id),
  );
  const retryByIdentity = new Map(
    state.target_retries.map((retry) => [retryIdentity(retry), retry]),
  );
  const targetByRepositoryId = new Map(
    manifest.repositories.map((target) => [target.repository_id, target]),
  );
  const planned: PlannedTarget[] = [];
  let outstanding = 0;
  let delayedRetries = 0;
  const delayedTimes: string[] = [];

  for (const target of manifest.repositories) {
    if (activeRepositoryIds.has(target.repository_id)) continue;
    const retry = retryByIdentity.get(targetIdentity(target));
    const reports = index.reports.filter(
      ({ repository_id }) => repository_id === target.repository_id,
    );
    const covered = reports.some(
      (report) =>
        report.target_sha === target.target_sha &&
        report.scanner_policy_version === scannerPolicyVersion,
    );
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
    if (reason === null) continue;
    outstanding += 1;

    if (retry?.exhausted === true) continue;
    if (
      retry !== undefined &&
      retry.next_retry_at !== null &&
      Date.parse(retry.next_retry_at) > nowMs
    ) {
      delayedRetries += 1;
      delayedTimes.push(retry.next_retry_at);
      continue;
    }
    planned.push({
      target,
      reason,
      lane: laneFor(target, state.coverage_started_at),
      ageFrom,
    });
  }

  if (state.pause !== null)
    return {
      targets: [],
      totalRemaining: outstanding,
      runnableRemaining: 0,
      delayedRetries,
      sharedHolds: state.shared_holds.length,
      nextWakeAt: null,
      blocked: true,
    };

  if (state.shared_holds.length > 0) {
    const holdFutureTimes = futureTimes(
      state.shared_holds.map(({ next_probe_at }) => next_probe_at),
      nowMs,
    );
    const dueHolds = state.shared_holds
      .filter(({ next_probe_at }) => Date.parse(next_probe_at) <= nowMs)
      .sort((left, right) =>
        [left.next_probe_at, left.error_fingerprint]
          .join(":")
          .localeCompare(
            [right.next_probe_at, right.error_fingerprint].join(":"),
          ),
      );
    const compareRecoveryTargets = (
      left: CurrentTarget,
      right: CurrentTarget,
    ) => {
      if (
        manifest.schema_version === 3 &&
        "popularity_rank" in left.catalog_priority &&
        "popularity_rank" in right.catalog_priority
      )
        return (
          left.catalog_priority.popularity_rank -
            right.catalog_priority.popularity_rank ||
          left.repository_id - right.repository_id
        );
      return left.repository_id - right.repository_id;
    };
    const availableRecoveryTargets = manifest.repositories.filter(
      (target) => !activeRepositoryIds.has(target.repository_id),
    );
    const recoveryTargets = [
      ...availableRecoveryTargets
        .filter((target) => !retryByIdentity.has(targetIdentity(target)))
        .sort(compareRecoveryTargets),
      ...availableRecoveryTargets
        .filter((target) => {
          const retry = retryByIdentity.get(targetIdentity(target));
          return (
            retry?.failure.domain === "target" &&
            !retry.exhausted &&
            retry.next_retry_at !== null &&
            Date.parse(retry.next_retry_at) <= nowMs
          );
        })
        .sort(compareRecoveryTargets),
    ];
    const usedRepositoryIds = new Set<number>();
    const eligible: PlannedTarget[] = [];
    for (const hold of dueHolds) {
      const retries = state.target_retries
        .filter(
          (entry) =>
            !entry.exhausted &&
            entry.error_fingerprint === hold.error_fingerprint,
        )
        .sort((left, right) =>
          [left.initial_failed_at, left.repository_id]
            .join(":")
            .localeCompare(
              [right.initial_failed_at, right.repository_id].join(":"),
            ),
        );
      const retry = retries[0];
      if (retry === undefined) continue;
      const target =
        retries
          .map(({ repository_id }) => targetByRepositoryId.get(repository_id))
          .find(
            (candidate) =>
              candidate !== undefined &&
              !activeRepositoryIds.has(candidate.repository_id) &&
              !usedRepositoryIds.has(candidate.repository_id),
          ) ??
        recoveryTargets.find(
          (candidate) => !usedRepositoryIds.has(candidate.repository_id),
        );
      if (target === undefined) continue;
      usedRepositoryIds.add(target.repository_id);
      eligible.push({
        target,
        reason: "retry",
        lane: laneFor(target, state.coverage_started_at),
        ageFrom: retry.initial_failed_at,
        recoveryFingerprint: hold.error_fingerprint,
      });
    }
    const targets = eligible.slice(0, 2);
    return {
      targets,
      totalRemaining: Math.max(0, outstanding - targets.length),
      runnableRemaining: Math.max(0, eligible.length - targets.length),
      delayedRetries: state.shared_holds.filter(
        ({ next_probe_at }) => Date.parse(next_probe_at) > nowMs,
      ).length,
      sharedHolds: state.shared_holds.length,
      nextWakeAt: holdFutureTimes[0] ?? null,
      blocked: targets.length === 0,
    };
  }

  const runnable = sortedRunnable(planned, manifest, state, nowMs);
  const targets = runnable.slice(0, 5);
  return {
    targets,
    totalRemaining: Math.max(0, outstanding - targets.length),
    runnableRemaining: Math.max(0, runnable.length - targets.length),
    delayedRetries,
    sharedHolds: 0,
    nextWakeAt: delayedTimes.sort()[0] ?? null,
    blocked: false,
  };
}
