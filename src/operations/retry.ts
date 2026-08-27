import type { Target } from "../contracts/targets.js";
import {
  appendQueuedTarget,
  dueQueueEntries,
  removeSuccessfulTarget,
  rotateFailedTarget,
} from "../queue/durable-queue.js";
import { failureFingerprint, type FailureDescriptor } from "./failure.js";
import { scanRetryAt } from "./retry-schedule.js";
import {
  OperationsStateSchema,
  type AutomaticRecoveryHold,
  type OperationsState,
  type ScanQueueEntry,
} from "./state.js";

export interface FailureTransition {
  state: OperationsState;
  entry: ScanQueueEntry;
  notification: "none" | "chronic" | "unscannable";
  terminal: boolean;
}

export function recordFailure(
  state: OperationsState,
  input: {
    target: Target;
    failure: FailureDescriptor;
    at: string;
    recoveryFingerprint?: string | undefined;
  },
): FailureTransition {
  const targetFailure = input.failure.domain === "target";
  const transitioned = targetFailure
    ? rotateFailedTarget(state, input)
    : (() => {
        const queued = appendQueuedTarget(state, input.target);
        const entry = queued.scan_queue.entries.find(
          ({ repository_id, target_sha }) =>
            repository_id === input.target.repository_id &&
            target_sha === input.target.target_sha,
        );
        if (entry === undefined)
          throw new Error("Shared scan failure target is not queued.");
        return {
          state: OperationsStateSchema.parse({
            ...queued,
            updated_at: input.at,
            active_scans: queued.active_scans.filter(
              ({ repository_id, target_sha }) =>
                repository_id !== input.target.repository_id ||
                target_sha !== input.target.target_sha,
            ),
          }),
          entry,
          terminal: false as const,
        };
      })();
  let automaticHolds = [...transitioned.state.automatic_holds];
  let automaticChronic = false;

  if (input.failure.domain !== "target") {
    const errorFingerprint = failureFingerprint(input.failure);
    if (
      input.recoveryFingerprint !== undefined &&
      input.recoveryFingerprint !== errorFingerprint
    )
      automaticHolds = automaticHolds.map((hold) =>
        hold.error_fingerprint === input.recoveryFingerprint
          ? {
              ...hold,
              next_probe_at: scanRetryAt(input.at, hold.consecutive_failures),
            }
          : hold,
      );
    const current = automaticHolds.find(
      ({ error_fingerprint }) => error_fingerprint === errorFingerprint,
    );
    const consecutiveFailures = (current?.consecutive_failures ?? 0) + 1;
    const firstFailedAt =
      current === undefined ||
      Date.parse(input.at) < Date.parse(current.first_failed_at)
        ? input.at
        : current.first_failed_at;
    const lastFailedAt =
      current === undefined ||
      Date.parse(input.at) > Date.parse(current.last_failed_at)
        ? input.at
        : current.last_failed_at;
    const hold: AutomaticRecoveryHold = {
      error_fingerprint: errorFingerprint,
      failure: input.failure,
      first_failed_at: firstFailedAt,
      last_failed_at: lastFailedAt,
      consecutive_failures: consecutiveFailures,
      next_probe_at: scanRetryAt(lastFailedAt, consecutiveFailures),
      chronic: consecutiveFailures >= 5,
    };
    automaticHolds = [
      ...automaticHolds.filter(
        ({ error_fingerprint }) => error_fingerprint !== errorFingerprint,
      ),
      hold,
    ];
    automaticChronic = hold.chronic;
  }

  const nextState = OperationsStateSchema.parse({
    ...transitioned.state,
    automatic_holds: automaticHolds,
  });
  return {
    state: nextState,
    entry: transitioned.entry,
    notification:
      targetFailure && transitioned.terminal
        ? "unscannable"
        : (targetFailure && transitioned.entry.chronic) || automaticChronic
          ? "chronic"
          : "none",
    terminal: transitioned.terminal,
  };
}

export function dueRetries(state: OperationsState, now: string) {
  const due = dueQueueEntries(state, now, Number.MAX_SAFE_INTEGER);
  if (state.automatic_holds.length === 0)
    return due.filter(({ consecutive_failures }) => consecutive_failures > 0);
  return [];
}

function automaticHoldFor(state: OperationsState, errorFingerprint: string) {
  const hold = state.automatic_holds.find(
    ({ error_fingerprint }) => error_fingerprint === errorFingerprint,
  );
  if (hold === undefined)
    throw new Error("Matching automatic recovery hold was not found.");
  return hold;
}

export function recordAutomaticProbeSuccess(
  stateInput: OperationsState,
  errorFingerprint: string,
  at: string,
) {
  const state = OperationsStateSchema.parse(stateInput);
  automaticHoldFor(state, errorFingerprint);
  if (!Number.isFinite(Date.parse(at)))
    throw new Error("Automatic recovery probe time is invalid.");
  return OperationsStateSchema.parse({
    ...state,
    updated_at: at,
    automatic_holds: state.automatic_holds.filter(
      ({ error_fingerprint }) => error_fingerprint !== errorFingerprint,
    ),
  });
}

export function recordAutomaticProbeFailure(
  stateInput: OperationsState,
  errorFingerprint: string,
  at: string,
) {
  const state = OperationsStateSchema.parse(stateInput);
  const hold = automaticHoldFor(state, errorFingerprint);
  const atMs = Date.parse(at);
  if (!Number.isFinite(atMs))
    throw new Error("Automatic recovery probe time is invalid.");
  if (atMs <= Date.parse(hold.last_failed_at)) return state;
  const lastFailedAt =
    atMs > Date.parse(hold.last_failed_at) ? at : hold.last_failed_at;
  const consecutiveFailures = hold.consecutive_failures + 1;
  return OperationsStateSchema.parse({
    ...state,
    updated_at: at,
    automatic_holds: state.automatic_holds.map((candidate) =>
      candidate.error_fingerprint === errorFingerprint
        ? {
            ...candidate,
            last_failed_at: lastFailedAt,
            consecutive_failures: consecutiveFailures,
            next_probe_at: scanRetryAt(lastFailedAt, consecutiveFailures),
            chronic: consecutiveFailures >= 5,
          }
        : candidate,
    ),
  });
}

export function recordSuccess(
  state: OperationsState,
  target: Target,
  at: string,
  recoveryFingerprint?: string,
) {
  const removed = removeSuccessfulTarget(state, target, at);
  return OperationsStateSchema.parse({
    ...removed,
    automatic_holds:
      recoveryFingerprint === undefined
        ? removed.automatic_holds
        : removed.automatic_holds.filter(
            ({ error_fingerprint }) =>
              error_fingerprint !== recoveryFingerprint,
          ),
  });
}
