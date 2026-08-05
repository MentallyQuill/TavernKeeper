import type { Target } from "../contracts/targets.js";
import {
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
  notification: "none" | "chronic";
  terminal: false;
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
  const rotated = rotateFailedTarget(state, input);
  let automaticHolds = [...rotated.state.automatic_holds];
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
    ...rotated.state,
    automatic_holds: automaticHolds,
  });
  return {
    state: nextState,
    entry: rotated.entry,
    notification:
      rotated.entry.chronic || automaticChronic ? "chronic" : "none",
    terminal: false,
  };
}

export function dueRetries(state: OperationsState, now: string) {
  const due = dueQueueEntries(state, now, Number.MAX_SAFE_INTEGER);
  if (state.automatic_holds.length === 0)
    return due.filter(({ consecutive_failures }) => consecutive_failures > 0);
  const holdDue = state.automatic_holds.some(
    ({ next_probe_at }) => Date.parse(next_probe_at) <= Date.parse(now),
  );
  return holdDue ? due.slice(0, 1) : [];
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
