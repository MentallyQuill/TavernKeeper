import { createHash } from "node:crypto";

import { TargetSchema, type Target } from "../contracts/targets.js";
import {
  OperationsStateSchema,
  type OperationsState,
  type RetryEntry,
} from "./state.js";
import { scheduledRetryAt } from "./retry-schedule.js";

export interface FailureTransition {
  state: OperationsState;
  entry: RetryEntry;
  notification: "none" | "staff";
  terminal: boolean;
}

function fingerprint(scope: "repository" | "system", code: string) {
  return createHash("sha256")
    .update(JSON.stringify([scope, code]))
    .digest("hex");
}

function replaceTargetRetry(
  retries: RetryEntry[],
  entry: RetryEntry,
): RetryEntry[] {
  return [
    ...retries.filter(
      (candidate) =>
        candidate.repository_id !== entry.repository_id ||
        candidate.target_sha !== entry.target_sha,
    ),
    entry,
  ].sort((left, right) =>
    [left.initial_failed_at, left.repository_id, left.target_sha]
      .join(":")
      .localeCompare(
        [right.initial_failed_at, right.repository_id, right.target_sha].join(
          ":",
        ),
      ),
  );
}

export function recordFailure(
  stateInput: OperationsState,
  input: {
    target: Target;
    code: string;
    scope: "repository" | "system";
    at: string;
    credentialCompromise?: boolean;
  },
): FailureTransition {
  const state = OperationsStateSchema.parse(stateInput);
  const target = TargetSchema.parse(input.target);
  if (!/^[A-Z][A-Z0-9_]{0,79}$/u.test(input.code))
    throw new Error("Retry error code is invalid.");
  const errorFingerprint = fingerprint(input.scope, input.code);
  const existing = state.retries.find(
    (entry) =>
      entry.repository_id === target.repository_id &&
      entry.target_sha === target.target_sha &&
      entry.error_fingerprint === errorFingerprint,
  );

  const initialFailedAt = existing?.initial_failed_at ?? input.at;
  if (Date.parse(input.at) < Date.parse(initialFailedAt))
    throw new Error("Retry failure precedes its initial failure.");
  const terminal =
    input.credentialCompromise === true || existing?.attempt === 3;
  const attempt = terminal
    ? 3
    : existing === undefined
      ? 1
      : existing.attempt + 1;
  const entry: RetryEntry = {
    source_id: target.source_id,
    repository_id: target.repository_id,
    repository: target.repository,
    target_sha: target.target_sha,
    error_fingerprint: errorFingerprint,
    error_code: input.code,
    scope: input.scope,
    initial_failed_at: initialFailedAt,
    last_failed_at: input.at,
    attempt,
    next_retry_at: terminal
      ? null
      : scheduledRetryAt({
          initialFailedAt,
          attempt,
          scope: input.scope,
          code: input.code,
        }),
    exhausted: terminal,
  };
  const circuitBreaker =
    input.scope === "system"
      ? {
          error_fingerprint: errorFingerprint,
          engaged_at: state.circuit_breaker?.engaged_at ?? initialFailedAt,
          terminal,
        }
      : state.circuit_breaker;
  const nextState = OperationsStateSchema.parse({
    ...state,
    updated_at: input.at,
    retries: replaceTargetRetry(state.retries, entry),
    circuit_breaker: circuitBreaker,
    active_scans: state.active_scans.filter(
      (active) =>
        active.repository_id !== target.repository_id ||
        active.target_sha !== target.target_sha,
    ),
  });
  return {
    state: nextState,
    entry,
    notification: terminal ? "staff" : "none",
    terminal,
  };
}

export function dueRetries(stateInput: OperationsState, now: string) {
  const state = OperationsStateSchema.parse(stateInput);
  const nowMs = Date.parse(now);
  if (!Number.isFinite(nowMs)) throw new Error("Retry time is invalid.");
  if (state.pause !== null) return [];
  const breakerFingerprint = state.circuit_breaker?.error_fingerprint;
  return state.retries
    .filter(
      (entry) =>
        !entry.exhausted &&
        entry.next_retry_at !== null &&
        Date.parse(entry.next_retry_at) <= nowMs &&
        (breakerFingerprint === undefined ||
          (entry.scope === "system" &&
            entry.error_fingerprint === breakerFingerprint)),
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
) {
  const state = OperationsStateSchema.parse(stateInput);
  const target = TargetSchema.parse(targetInput);
  const removed = state.retries.filter(
    (entry) =>
      entry.repository_id === target.repository_id &&
      entry.target_sha === target.target_sha,
  );
  const retries = state.retries.filter(
    (entry) =>
      entry.repository_id !== target.repository_id ||
      entry.target_sha !== target.target_sha,
  );
  const breaker = state.circuit_breaker;
  const releaseTransientBreaker =
    breaker !== null &&
    !breaker.terminal &&
    removed.some(
      (entry) =>
        entry.scope === "system" &&
        entry.error_fingerprint === breaker.error_fingerprint,
    ) &&
    !retries.some(
      (entry) =>
        entry.scope === "system" &&
        entry.error_fingerprint === breaker.error_fingerprint,
    );
  return OperationsStateSchema.parse({
    ...state,
    updated_at: at,
    retries,
    circuit_breaker: releaseTransientBreaker ? null : breaker,
    active_scans: state.active_scans.filter(
      (active) =>
        active.repository_id !== target.repository_id ||
        active.target_sha !== target.target_sha,
    ),
  });
}
