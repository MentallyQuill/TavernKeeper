import { z } from "zod";

import { FullShaSchema } from "../contracts/targets.js";
import {
  classifyFailure,
  failureFingerprint,
  type FailureDescriptor,
} from "./failure.js";
import { sharedProbeAt, targetRetryAt } from "./retry-schedule.js";
import {
  ActiveScanSchema,
  OperationsStateSchema,
  PauseSchema,
  PolicyCampaignSchema,
  type OperationsState,
  type SharedRecoveryHold,
  type TargetRetryEntry,
} from "./state.js";

const LegacyRetrySchema = z.strictObject({
  source_id: z.string().regex(/^github-[1-9][0-9]*$/u),
  repository_id: z.number().int().positive(),
  repository: z.string().regex(/^[^/\s]+\/[^/\s]+$/u),
  target_sha: FullShaSchema,
  error_fingerprint: z.string().regex(/^[0-9a-f]{64}$/u),
  error_code: z.string().regex(/^[A-Z][A-Z0-9_]{0,79}$/u),
  scope: z.enum(["repository", "system"]),
  initial_failed_at: z.iso.datetime(),
  last_failed_at: z.iso.datetime(),
  attempt: z.number().int().min(1).max(3),
  next_retry_at: z.iso.datetime().nullable(),
  exhausted: z.boolean(),
});

const LegacyOperationsStateSchema = z.strictObject({
  schema_version: z.literal(1),
  updated_at: z.iso.datetime(),
  coverage_started_at: z.iso.datetime().nullable(),
  pause: PauseSchema.nullable(),
  circuit_breaker: z
    .strictObject({
      error_fingerprint: z.string().regex(/^[0-9a-f]{64}$/u),
      engaged_at: z.iso.datetime(),
      terminal: z.boolean(),
    })
    .nullable(),
  retries: z.array(LegacyRetrySchema),
  active_scans: z.array(ActiveScanSchema),
  policy_campaigns: z.array(PolicyCampaignSchema),
});

export interface StateMigrationResult {
  state: OperationsState;
  summary: { target: number; shared: number; security: number };
}

function legacyFailure(code: string, scope: "repository" | "system") {
  return classifyFailure({ code, scope });
}

function sharedHoldFor(
  entries: Array<{
    failure: FailureDescriptor;
    initial_failed_at: string;
    last_failed_at: string;
    attempt: number;
  }>,
): SharedRecoveryHold {
  const failure = entries[0]!.failure;
  const errorFingerprint = failureFingerprint(failure);
  const firstFailedAt = entries
    .map(({ initial_failed_at }) => initial_failed_at)
    .sort()[0]!;
  const lastFailedAt = entries
    .map(({ last_failed_at }) => last_failed_at)
    .sort()
    .at(-1)!;
  const consecutiveFailures = Math.max(
    ...entries.map(({ attempt }) => attempt),
  );
  return {
    error_fingerprint: errorFingerprint,
    failure,
    first_failed_at: firstFailedAt,
    last_failed_at: lastFailedAt,
    consecutive_failures: consecutiveFailures,
    next_probe_at: sharedProbeAt(lastFailedAt, consecutiveFailures),
    notified: consecutiveFailures >= 4,
  };
}

export function migrateOperationsState(
  value: unknown,
  at: string,
): StateMigrationResult {
  if (
    value !== null &&
    typeof value === "object" &&
    "schema_version" in value &&
    value.schema_version === 2
  )
    throw new Error("Operations state is already schema version 2.");
  if (!Number.isFinite(Date.parse(at)))
    throw new Error("Operations state migration time is invalid.");

  const legacy = LegacyOperationsStateSchema.parse(value);
  const classified = legacy.retries.map((entry) => ({
    ...entry,
    failure: legacyFailure(entry.error_code, entry.scope),
  }));
  const summary = classified.reduce(
    (counts, { failure }) => ({
      ...counts,
      [failure.domain]: counts[failure.domain] + 1,
    }),
    { target: 0, shared: 0, security: 0 },
  );

  const sharedGroups = new Map<string, typeof classified>();
  for (const entry of classified) {
    if (entry.failure.domain !== "shared") continue;
    const fingerprint = failureFingerprint(entry.failure);
    const group = sharedGroups.get(fingerprint) ?? [];
    group.push(entry);
    sharedGroups.set(fingerprint, group);
  }
  const sharedHolds = [...sharedGroups.values()].map(sharedHoldFor);
  const holdByFingerprint = new Map(
    sharedHolds.map((hold) => [hold.error_fingerprint, hold]),
  );

  const targetRetries: TargetRetryEntry[] = classified.map((entry) => {
    const fingerprint = failureFingerprint(entry.failure);
    if (entry.failure.domain === "security")
      return {
        source_id: entry.source_id,
        repository_id: entry.repository_id,
        repository: entry.repository,
        target_sha: entry.target_sha,
        failure: entry.failure,
        error_fingerprint: fingerprint,
        initial_failed_at: entry.initial_failed_at,
        last_failed_at: entry.last_failed_at,
        attempt: Math.min(entry.attempt, 4),
        next_retry_at: null,
        exhausted: true,
      };
    if (entry.failure.domain === "shared")
      return {
        source_id: entry.source_id,
        repository_id: entry.repository_id,
        repository: entry.repository,
        target_sha: entry.target_sha,
        failure: entry.failure,
        error_fingerprint: fingerprint,
        initial_failed_at: entry.initial_failed_at,
        last_failed_at: entry.last_failed_at,
        attempt: Math.min(entry.attempt, 4),
        next_retry_at: holdByFingerprint.get(fingerprint)!.next_probe_at,
        exhausted: false,
      };

    const exhausted = entry.exhausted;
    const attempt = exhausted ? 4 : Math.min(entry.attempt, 3);
    return {
      source_id: entry.source_id,
      repository_id: entry.repository_id,
      repository: entry.repository,
      target_sha: entry.target_sha,
      failure: entry.failure,
      error_fingerprint: fingerprint,
      initial_failed_at: entry.initial_failed_at,
      last_failed_at: entry.last_failed_at,
      attempt,
      next_retry_at: exhausted
        ? null
        : targetRetryAt(entry.initial_failed_at, attempt),
      exhausted,
    };
  });

  const hasSecurityFailure = summary.security > 0;
  const state = OperationsStateSchema.parse({
    schema_version: 2,
    updated_at: at,
    coverage_started_at: legacy.coverage_started_at,
    pause: hasSecurityFailure
      ? { kind: "system", reason_code: "SECURITY_HOLD", paused_at: at }
      : legacy.pause,
    target_retries: targetRetries,
    shared_holds: sharedHolds,
    active_scans: legacy.active_scans,
    policy_campaigns: legacy.policy_campaigns,
  });
  return { state, summary };
}
