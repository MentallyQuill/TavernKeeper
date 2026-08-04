import { z } from "zod";

import {
  ReportIndexV5Schema,
  type ReportIndexV5,
} from "../contracts/reports-v5.js";
import {
  FullShaSchema,
  TargetManifestV2Schema,
  TargetManifestV3Schema,
  type CurrentTargetManifest,
} from "../contracts/targets.js";
import {
  reconcileCurrentScanQueue,
  type QueueSyncSummary,
} from "../queue/reconcile.js";
import { FailureDescriptorSchema, failureFingerprint } from "./failure.js";
import {
  ActiveScanSchema,
  OperationsStateSchema,
  PolicyCampaignSchema,
  type OperationsState,
  type ScanQueueEntry,
} from "./state.js";

const FingerprintSchema = z.string().regex(/^[0-9a-f]{64}$/u);
const SourceIdSchema = z.string().regex(/^github-[1-9][0-9]*$/u);
const RepositorySchema = z.string().regex(/^[^/\s]+\/[^/\s]+$/u);
const LegacyPauseSchema = z.strictObject({
  kind: z.enum(["staff", "system"]),
  reason_code: z.string().regex(/^[A-Z][A-Z0-9_]{0,79}$/u),
  paused_at: z.iso.datetime(),
});
const LegacyTargetRetrySchema = z
  .strictObject({
    source_id: SourceIdSchema,
    repository_id: z.number().int().positive(),
    repository: RepositorySchema,
    target_sha: FullShaSchema,
    failure: FailureDescriptorSchema,
    error_fingerprint: FingerprintSchema,
    initial_failed_at: z.iso.datetime(),
    last_failed_at: z.iso.datetime(),
    attempt: z.number().int().min(1).max(4),
    next_retry_at: z.iso.datetime().nullable(),
    exhausted: z.boolean(),
  })
  .superRefine((entry, context) => {
    if (entry.source_id !== `github-${entry.repository_id}`)
      context.addIssue({
        code: "custom",
        path: ["source_id"],
        message: "Legacy source ID must match repository ID.",
      });
    if (entry.error_fingerprint !== failureFingerprint(entry.failure))
      context.addIssue({
        code: "custom",
        path: ["error_fingerprint"],
        message: "Legacy failure fingerprint is invalid.",
      });
  });
const LegacySharedHoldSchema = z.strictObject({
  error_fingerprint: FingerprintSchema,
  failure: FailureDescriptorSchema,
  first_failed_at: z.iso.datetime(),
  last_failed_at: z.iso.datetime(),
  consecutive_failures: z.number().int().positive(),
  next_probe_at: z.iso.datetime(),
  notified: z.boolean(),
});
const OperationsStateV2Schema = z.strictObject({
  schema_version: z.literal(2),
  updated_at: z.iso.datetime(),
  coverage_started_at: z.iso.datetime().nullable(),
  pause: LegacyPauseSchema.nullable(),
  target_retries: z.array(LegacyTargetRetrySchema),
  shared_holds: z.array(LegacySharedHoldSchema),
  active_scans: z.array(ActiveScanSchema),
  policy_campaigns: z.array(PolicyCampaignSchema),
});

export interface StateMigrationResult {
  state: OperationsState;
  summary: QueueSyncSummary;
}

function parseCurrentManifest(input: CurrentTargetManifest) {
  return input.schema_version === 3
    ? TargetManifestV3Schema.parse(input)
    : TargetManifestV2Schema.parse(input);
}

export function migrateOperationsState(
  value: unknown,
  input: {
    manifest: CurrentTargetManifest;
    index: ReportIndexV5;
    at: string;
    scannerPolicyVersion: string;
  },
): StateMigrationResult {
  if (!Number.isFinite(Date.parse(input.at)))
    throw new Error("Operations state migration time is invalid.");
  const legacy = OperationsStateV2Schema.parse(value);
  const manifest = parseCurrentManifest(input.manifest);
  const index = ReportIndexV5Schema.parse(input.index);
  const base = OperationsStateSchema.parse({
    schema_version: 3,
    updated_at: input.at,
    coverage_started_at: legacy.coverage_started_at,
    emergency_stop:
      legacy.pause?.kind === "staff"
        ? {
            kind: "staff",
            reason_code: legacy.pause.reason_code,
            paused_at: legacy.pause.paused_at,
          }
        : null,
    scan_queue: { next_ticket: 1, entries: [] },
    active_scans: legacy.active_scans,
    policy_campaigns: legacy.policy_campaigns,
  });
  const seeded = reconcileCurrentScanQueue({
    manifest,
    index,
    state: base,
    now: input.at,
    scannerPolicyVersion: input.scannerPolicyVersion,
  });

  const retryByRepositoryId = new Map(
    legacy.target_retries.map((entry) => [entry.repository_id, entry]),
  );
  const retryEntries = seeded.state.scan_queue.entries
    .filter((entry) => {
      const retry = retryByRepositoryId.get(entry.repository_id);
      return retry !== undefined && retry.target_sha === entry.target_sha;
    })
    .sort((left, right) => {
      const leftRetry = retryByRepositoryId.get(left.repository_id)!;
      const rightRetry = retryByRepositoryId.get(right.repository_id)!;
      return (
        leftRetry.initial_failed_at.localeCompare(
          rightRetry.initial_failed_at,
        ) || left.repository_id - right.repository_id
      );
    });
  const retryRepositoryIds = new Set(
    retryEntries.map(({ repository_id }) => repository_id),
  );
  const healthyEntries = seeded.state.scan_queue.entries.filter(
    ({ repository_id }) => !retryRepositoryIds.has(repository_id),
  );
  let nextTicket = 1;
  const normalizedHealthy = healthyEntries.map((entry) => ({
    ...entry,
    ticket: nextTicket++,
  }));
  const normalizedRetries: ScanQueueEntry[] = retryEntries.map((entry) => {
    const retry = retryByRepositoryId.get(entry.repository_id)!;
    const futureCooldown =
      retry.next_retry_at !== null &&
      Date.parse(retry.next_retry_at) > Date.parse(input.at) &&
      Date.parse(retry.next_retry_at) >= Date.parse(retry.last_failed_at)
        ? retry.next_retry_at
        : null;
    const consecutiveFailures = retry.attempt;
    return {
      ...entry,
      ticket: nextTicket++,
      consecutive_failures: consecutiveFailures,
      total_failures: Math.max(entry.total_failures, retry.attempt),
      not_before: futureCooldown,
      last_failure: retry.failure,
      last_failed_at: retry.last_failed_at,
      chronic: consecutiveFailures >= 5,
    };
  });

  const state = OperationsStateSchema.parse({
    ...seeded.state,
    updated_at: input.at,
    scan_queue: {
      next_ticket: nextTicket,
      entries: [...normalizedHealthy, ...normalizedRetries],
    },
  });
  return {
    state,
    summary: {
      ...seeded.summary,
      migrated_from: 2,
      automatic_stops_cleared: legacy.pause?.kind === "system" ? 1 : 0,
      legacy_retries_preserved: normalizedRetries.length,
    },
  };
}
