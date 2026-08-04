import { TargetSchema, type Target } from "../contracts/targets.js";
import {
  FailureDescriptorSchema,
  failureFingerprint,
  retryModeForFailure,
  type FailureDescriptor,
} from "./failure.js";
import {
  OperationsStateSchema,
  type OperationsState,
  type SharedRecoveryHold,
  type TargetRetryEntry,
} from "./state.js";
import { sharedProbeAt, targetRetryAt } from "./retry-schedule.js";

export interface FailureTransition {
  state: OperationsState;
  entry: TargetRetryEntry;
  notification: "none" | "staff";
  terminal: boolean;
}

function retryIdentity(
  entry: Pick<TargetRetryEntry, "repository_id" | "target_sha">,
  target: Target,
) {
  return (
    entry.repository_id === target.repository_id &&
    entry.target_sha === target.target_sha
  );
}

function sortedRetries(retries: TargetRetryEntry[]) {
  return [...retries].sort((left, right) =>
    [left.initial_failed_at, left.repository_id, left.target_sha]
      .join(":")
      .localeCompare(
        [right.initial_failed_at, right.repository_id, right.target_sha].join(
          ":",
        ),
      ),
  );
}

function updatedSharedHold(
  current: SharedRecoveryHold | undefined,
  failure: FailureDescriptor,
  errorFingerprint: string,
  at: string,
): SharedRecoveryHold {
  const isNewFailureTime =
    current === undefined ||
    Date.parse(at) > Date.parse(current.last_failed_at);
  const consecutiveFailures =
    current === undefined
      ? 1
      : current.consecutive_failures + (isNewFailureTime ? 1 : 0);
  const lastFailedAt = isNewFailureTime ? at : current!.last_failed_at;
  return {
    error_fingerprint: errorFingerprint,
    failure,
    first_failed_at: current?.first_failed_at ?? at,
    last_failed_at: lastFailedAt,
    consecutive_failures: consecutiveFailures,
    next_probe_at: sharedProbeAt(lastFailedAt, consecutiveFailures),
    notified: consecutiveFailures >= 4,
  };
}

function targetRetryEntry(input: {
  target: Target;
  failure: FailureDescriptor;
  fingerprint: string;
  existing?: TargetRetryEntry;
  at: string;
  sharedNextProbeAt?: string;
}): TargetRetryEntry {
  const initialFailedAt = input.existing?.initial_failed_at ?? input.at;
  if (Date.parse(input.at) < Date.parse(initialFailedAt))
    throw new Error("Retry failure precedes its initial failure.");

  if (input.failure.domain === "target") {
    const attempt = Math.min((input.existing?.attempt ?? 0) + 1, 4);
    const exhausted = attempt === 4;
    const retryMode = retryModeForFailure(input.failure);
    const failureHistory = [
      ...(input.existing?.failure_history ?? []),
      {
        failed_at: input.at,
        failure: input.failure,
        error_fingerprint: input.fingerprint,
      },
    ].slice(-4);
    return {
      source_id: input.target.source_id,
      repository_id: input.target.repository_id,
      repository: input.target.repository,
      target_sha: input.target.target_sha,
      failure: input.failure,
      error_fingerprint: input.fingerprint,
      initial_failed_at: initialFailedAt,
      last_failed_at: input.at,
      attempt,
      next_retry_at:
        exhausted || retryMode === "manual"
          ? null
          : targetRetryAt(input.at, attempt),
      exhausted,
      retry_mode: retryMode,
      failure_history: failureHistory,
    };
  }

  if (input.failure.domain === "shared") {
    if (input.sharedNextProbeAt === undefined)
      throw new Error("Shared retry requires a recovery probe time.");
    return {
      source_id: input.target.source_id,
      repository_id: input.target.repository_id,
      repository: input.target.repository,
      target_sha: input.target.target_sha,
      failure: input.failure,
      error_fingerprint: input.fingerprint,
      initial_failed_at: initialFailedAt,
      last_failed_at: input.at,
      attempt: Math.min((input.existing?.attempt ?? 0) + 1, 4),
      next_retry_at: input.sharedNextProbeAt,
      exhausted: false,
    };
  }

  return {
    source_id: input.target.source_id,
    repository_id: input.target.repository_id,
    repository: input.target.repository,
    target_sha: input.target.target_sha,
    failure: input.failure,
    error_fingerprint: input.fingerprint,
    initial_failed_at: initialFailedAt,
    last_failed_at: input.at,
    attempt: Math.min((input.existing?.attempt ?? 0) + 1, 4),
    next_retry_at: null,
    exhausted: true,
  };
}

export function recordFailure(
  stateInput: OperationsState,
  input: {
    target: Target;
    failure: FailureDescriptor;
    at: string;
  },
): FailureTransition {
  const state = OperationsStateSchema.parse(stateInput);
  const target = TargetSchema.parse(input.target);
  const failure = FailureDescriptorSchema.parse(input.failure);
  const errorFingerprint = failureFingerprint(failure);
  const priorForTarget = state.target_retries.find((entry) =>
    retryIdentity(entry, target),
  );
  const existing =
    priorForTarget !== undefined &&
    (priorForTarget.error_fingerprint === errorFingerprint ||
      (priorForTarget.failure.domain === "target" &&
        failure.domain === "target"))
      ? priorForTarget
      : undefined;
  const retriesWithoutTarget = state.target_retries.filter(
    (entry) => !retryIdentity(entry, target),
  );

  let sharedHolds = state.shared_holds.filter((hold) => {
    if (
      priorForTarget === undefined ||
      priorForTarget.error_fingerprint === errorFingerprint ||
      hold.error_fingerprint !== priorForTarget.error_fingerprint
    )
      return true;
    return retriesWithoutTarget.some(
      (entry) => entry.error_fingerprint === hold.error_fingerprint,
    );
  });

  let sharedHold: SharedRecoveryHold | undefined;
  if (failure.domain === "shared") {
    const current = sharedHolds.find(
      ({ error_fingerprint }) => error_fingerprint === errorFingerprint,
    );
    sharedHold = updatedSharedHold(
      current,
      failure,
      errorFingerprint,
      input.at,
    );
    sharedHolds = [
      ...sharedHolds.filter(
        ({ error_fingerprint }) => error_fingerprint !== errorFingerprint,
      ),
      sharedHold,
    ];
  }

  const entry = targetRetryEntry({
    target,
    failure,
    fingerprint: errorFingerprint,
    ...(existing === undefined ? {} : { existing }),
    at: input.at,
    ...(sharedHold === undefined
      ? {}
      : { sharedNextProbeAt: sharedHold.next_probe_at }),
  });
  const terminal =
    failure.domain === "security" ||
    (failure.domain === "target" && entry.exhausted);
  const notification =
    terminal || (sharedHold?.notified ?? false) ? "staff" : "none";

  const nextState = OperationsStateSchema.parse({
    ...state,
    updated_at: input.at,
    pause:
      failure.domain === "security"
        ? {
            kind: "system",
            reason_code: "SECURITY_HOLD",
            paused_at: input.at,
          }
        : state.pause,
    target_retries: sortedRetries([...retriesWithoutTarget, entry]),
    shared_holds: sharedHolds.sort((left, right) =>
      left.error_fingerprint.localeCompare(right.error_fingerprint),
    ),
    active_scans: state.active_scans.filter(
      (active) =>
        active.repository_id !== target.repository_id ||
        active.target_sha !== target.target_sha,
    ),
  });
  return { state: nextState, entry, notification, terminal };
}

export function dueRetries(stateInput: OperationsState, now: string) {
  const state = OperationsStateSchema.parse(stateInput);
  const nowMs = Date.parse(now);
  if (!Number.isFinite(nowMs)) throw new Error("Retry time is invalid.");
  if (state.pause !== null) return [];

  if (state.shared_holds.length > 0)
    return state.shared_holds
      .filter(({ next_probe_at }) => Date.parse(next_probe_at) <= nowMs)
      .sort((left, right) =>
        [left.next_probe_at, left.error_fingerprint]
          .join(":")
          .localeCompare(
            [right.next_probe_at, right.error_fingerprint].join(":"),
          ),
      )
      .flatMap((hold) => {
        const candidate = sortedRetries(
          state.target_retries.filter(
            (entry) =>
              !entry.exhausted &&
              entry.error_fingerprint === hold.error_fingerprint,
          ),
        )[0];
        return candidate === undefined ? [] : [candidate];
      })
      .slice(0, 2);

  return state.target_retries
    .filter(
      (entry) =>
        entry.failure.domain !== "security" &&
        !entry.exhausted &&
        entry.next_retry_at !== null &&
        Date.parse(entry.next_retry_at) <= nowMs,
    )
    .sort((left, right) =>
      [left.next_retry_at, left.repository_id, left.target_sha]
        .join(":")
        .localeCompare(
          [right.next_retry_at, right.repository_id, right.target_sha].join(
            ":",
          ),
        ),
    );
}

export function recordSuccess(
  stateInput: OperationsState,
  targetInput: Target,
  at: string,
  recoveryFingerprint?: string,
) {
  const state = OperationsStateSchema.parse(stateInput);
  const target = TargetSchema.parse(targetInput);
  if (
    recoveryFingerprint !== undefined &&
    !/^[0-9a-f]{64}$/u.test(recoveryFingerprint)
  )
    throw new Error("Recovery fingerprint is invalid.");
  const removed = state.target_retries.filter(
    (entry) =>
      retryIdentity(entry, target) ||
      (recoveryFingerprint !== undefined &&
        entry.repository_id === target.repository_id &&
        entry.error_fingerprint === recoveryFingerprint),
  );
  const resolvedSharedFingerprints = new Set(
    removed
      .filter(({ failure }) => failure.domain === "shared")
      .map(({ error_fingerprint }) => error_fingerprint),
  );
  if (recoveryFingerprint !== undefined)
    resolvedSharedFingerprints.add(recoveryFingerprint);
  return OperationsStateSchema.parse({
    ...state,
    updated_at: at,
    target_retries: state.target_retries.filter(
      (entry) => !removed.includes(entry),
    ),
    shared_holds: state.shared_holds.filter(
      (hold) => !resolvedSharedFingerprints.has(hold.error_fingerprint),
    ),
    active_scans: state.active_scans.filter(
      (active) =>
        active.repository_id !== target.repository_id ||
        active.target_sha !== target.target_sha,
    ),
  });
}
