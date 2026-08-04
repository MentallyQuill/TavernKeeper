import { z } from "zod";

import { FullShaSchema } from "../contracts/targets.js";
import {
  isRepositoryModelReplyFailure,
  legacyHourlyRetryAt,
  scheduledRetryAt,
} from "./retry-schedule.js";

const FingerprintSchema = z.string().regex(/^[0-9a-f]{64}$/u);
const SafeCodeSchema = z.string().regex(/^[A-Z][A-Z0-9_]{0,79}$/u);
const SourceIdSchema = z.string().regex(/^github-[1-9][0-9]*$/u);
const RepositorySchema = z.string().regex(/^[^/\s]+\/[^/\s]+$/u);

export const RetryEntrySchema = z
  .strictObject({
    source_id: SourceIdSchema,
    repository_id: z.number().int().positive(),
    repository: RepositorySchema,
    target_sha: FullShaSchema,
    error_fingerprint: FingerprintSchema,
    error_code: SafeCodeSchema,
    scope: z.enum(["repository", "system"]),
    initial_failed_at: z.iso.datetime(),
    last_failed_at: z.iso.datetime(),
    attempt: z.number().int().min(1).max(3),
    next_retry_at: z.iso.datetime().nullable(),
    exhausted: z.boolean(),
  })
  .refine((entry) => entry.source_id === `github-${entry.repository_id}`, {
    path: ["source_id"],
    message: "Retry source ID must match repository ID.",
  })
  .superRefine((entry, context) => {
    const initial = Date.parse(entry.initial_failed_at);
    const last = Date.parse(entry.last_failed_at);
    if (last < initial)
      context.addIssue({
        code: "custom",
        path: ["last_failed_at"],
        message: "Retry failure time cannot precede its initial failure.",
      });
    if (entry.exhausted) {
      if (entry.attempt !== 3 || entry.next_retry_at !== null)
        context.addIssue({
          code: "custom",
          path: ["exhausted"],
          message: "Exhausted retries must end after attempt three.",
        });
      return;
    }
    const expected = scheduledRetryAt({
      initialFailedAt: entry.initial_failed_at,
      attempt: entry.attempt,
      scope: entry.scope,
      code: entry.error_code,
    });
    const legacyExpected = isRepositoryModelReplyFailure(
      entry.scope,
      entry.error_code,
    )
      ? legacyHourlyRetryAt(entry.initial_failed_at, entry.attempt)
      : null;
    if (
      entry.next_retry_at !== expected &&
      (legacyExpected === null || entry.next_retry_at !== legacyExpected)
    )
      context.addIssue({
        code: "custom",
        path: ["next_retry_at"],
        message: "Retry time must match its failure class and initial failure.",
      });
  });

export const CircuitBreakerSchema = z.strictObject({
  error_fingerprint: FingerprintSchema,
  engaged_at: z.iso.datetime(),
  terminal: z.boolean(),
});

export const PauseSchema = z.strictObject({
  kind: z.enum(["staff", "system"]),
  reason_code: SafeCodeSchema,
  paused_at: z.iso.datetime(),
});

export const ActiveScanSchema = z
  .strictObject({
    source_id: SourceIdSchema,
    repository_id: z.number().int().positive(),
    target_sha: FullShaSchema,
    started_at: z.iso.datetime(),
    run_id: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/u),
  })
  .refine((entry) => entry.source_id === `github-${entry.repository_id}`, {
    path: ["source_id"],
    message: "Active scan source ID must match repository ID.",
  });

export const PolicyCampaignSchema = z.strictObject({
  id: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/u),
  scanner_policy_version: z
    .string()
    .regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/u),
  repository_ids: z.array(z.number().int().positive()),
  created_at: z.iso.datetime(),
  status: z.enum(["active", "completed"]),
});

export const OperationsStateSchema = z
  .strictObject({
    schema_version: z.literal(1),
    updated_at: z.iso.datetime(),
    coverage_started_at: z.iso.datetime().nullable(),
    pause: PauseSchema.nullable(),
    circuit_breaker: CircuitBreakerSchema.nullable(),
    retries: z.array(RetryEntrySchema),
    active_scans: z.array(ActiveScanSchema),
    policy_campaigns: z.array(PolicyCampaignSchema),
  })
  .superRefine((state, context) => {
    const retryIdentities = state.retries.map(
      (entry) => `${entry.repository_id}:${entry.target_sha}`,
    );
    if (new Set(retryIdentities).size !== retryIdentities.length)
      context.addIssue({
        code: "custom",
        path: ["retries"],
        message: "Each target may have only one classified retry sequence.",
      });
    const activeIdentities = state.active_scans.map(
      (entry) => `${entry.repository_id}:${entry.target_sha}`,
    );
    if (new Set(activeIdentities).size !== activeIdentities.length)
      context.addIssue({
        code: "custom",
        path: ["active_scans"],
        message: "Active scan identities must be unique.",
      });
    for (const campaign of state.policy_campaigns) {
      if (
        new Set(campaign.repository_ids).size !==
          campaign.repository_ids.length ||
        campaign.repository_ids.some(
          (value, index) =>
            index > 0 && campaign.repository_ids[index - 1]! >= value,
        )
      )
        context.addIssue({
          code: "custom",
          path: ["policy_campaigns"],
          message: "Campaign repository IDs must be unique and sorted.",
        });
    }
  });

export type RetryEntry = z.infer<typeof RetryEntrySchema>;
export type OperationsState = z.infer<typeof OperationsStateSchema>;

export function initialOperationsState(now: string): OperationsState {
  return OperationsStateSchema.parse({
    schema_version: 1,
    updated_at: now,
    coverage_started_at: null,
    pause: null,
    circuit_breaker: null,
    retries: [],
    active_scans: [],
    policy_campaigns: [],
  });
}

export function parseOperationsState(value: unknown) {
  return OperationsStateSchema.parse(value);
}

export function serializeOperationsState(state: OperationsState) {
  const parsed = OperationsStateSchema.parse(state);
  const canonical = OperationsStateSchema.parse({
    ...parsed,
    retries: [...parsed.retries].sort((left, right) =>
      [left.repository_id, left.target_sha, left.error_fingerprint]
        .join(":")
        .localeCompare(
          [right.repository_id, right.target_sha, right.error_fingerprint].join(
            ":",
          ),
        ),
    ),
    active_scans: [...parsed.active_scans].sort((left, right) =>
      [left.repository_id, left.target_sha, left.run_id]
        .join(":")
        .localeCompare(
          [right.repository_id, right.target_sha, right.run_id].join(":"),
        ),
    ),
    policy_campaigns: [...parsed.policy_campaigns].sort((left, right) =>
      left.id.localeCompare(right.id),
    ),
  });
  return `${JSON.stringify(canonical, null, 2)}\n`;
}

export function pauseSystem(
  state: OperationsState,
  input: {
    kind: "staff" | "system";
    reasonCode: string;
    at: string;
  },
) {
  return OperationsStateSchema.parse({
    ...state,
    updated_at: input.at,
    pause: {
      kind: input.kind,
      reason_code: input.reasonCode,
      paused_at: input.at,
    },
  });
}

export function resumeSystem(state: OperationsState, at: string) {
  return OperationsStateSchema.parse({
    ...state,
    updated_at: at,
    coverage_started_at: state.coverage_started_at ?? at,
    pause: null,
    circuit_breaker: null,
  });
}
