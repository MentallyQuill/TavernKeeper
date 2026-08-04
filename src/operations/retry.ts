import type { Target } from "../contracts/targets.js";
import {
  dueQueueEntries,
  removeSuccessfulTarget,
  rotateFailedTarget,
} from "../queue/durable-queue.js";
import type { FailureDescriptor } from "./failure.js";
import type { OperationsState, ScanQueueEntry } from "./state.js";

export interface FailureTransition {
  state: OperationsState;
  entry: ScanQueueEntry;
  notification: "none" | "chronic";
  terminal: false;
}

export function recordFailure(
  state: OperationsState,
  input: { target: Target; failure: FailureDescriptor; at: string },
): FailureTransition {
  const rotated = rotateFailedTarget(state, input);
  return {
    state: rotated.state,
    entry: rotated.entry,
    notification: rotated.entry.chronic ? "chronic" : "none",
    terminal: false,
  };
}

export function dueRetries(state: OperationsState, now: string) {
  return dueQueueEntries(state, now, Number.MAX_SAFE_INTEGER).filter(
    ({ consecutive_failures }) => consecutive_failures > 0,
  );
}

export function recordSuccess(
  state: OperationsState,
  target: Target,
  at: string,
  _recoveryFingerprint?: string,
) {
  return removeSuccessfulTarget(state, target, at);
}
