import { z } from "zod";

import { FullShaSchema } from "../contracts/targets.js";
import { FailureDescriptorSchema, failureFingerprint } from "./failure.js";
import { targetRetryAt } from "./retry-schedule.js";

const FingerprintSchema = z.string().regex(/^[0-9a-f]{64}$/u);
const SafeCodeSchema = z.string().regex(/^[A-Z][A-Z0-9_]{0,79}$/u);
const SourceIdSchema = z.string().regex(/^github-[1-9][0-9]*$/u);
const RepositorySchema = z.string().regex(/^[^/\s]+\/[^/\s]+$/u);

export const TargetRetryEntrySchema = z
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
        message: "Retry source ID must match repository ID.",
      });
    if (entry.error_fingerprint !== failureFingerprint(entry.failure))
      context.addIssue({
        code: "custom",
        path: ["error_fingerprint"],
        message: "Retry fingerprint must match its failure descriptor.",
      });
    if (Date.parse(entry.last_failed_at) < Date.parse(entry.initial_failed_at))
      context.addIssue({
        code: "custom",
        path: ["last_failed_at"],
        message: "Retry failure time cannot precede its initial failure.",
      });

    if (entry.failure.domain === "target") {
      if (entry.exhausted) {
        if (entry.attempt !== 4 || entry.next_retry_at !== null)
          context.addIssue({
            code: "custom",
            path: ["exhausted"],
            message: "An exhausted target must end on its fourth failure.",
          });
      } else if (
        entry.attempt === 4 ||
        entry.next_retry_at !==
          targetRetryAt(entry.initial_failed_at, entry.attempt)
      )
        context.addIssue({
          code: "custom",
          path: ["next_retry_at"],
          message: "Target retry time must match its bounded schedule.",
        });
      return;
    }

    if (entry.failure.domain === "shared") {
      if (entry.exhausted || entry.next_retry_at === null)
        context.addIssue({
          code: "custom",
          path: ["exhausted"],
          message: "Shared failures must remain automatically retryable.",
        });
      return;
    }

    if (!entry.exhausted || entry.next_retry_at !== null)
      context.addIssue({
        code: "custom",
        path: ["exhausted"],
        message: "Security failures are held for explicit staff recovery.",
      });
  });

export const SharedRecoveryHoldSchema = z
  .strictObject({
    error_fingerprint: FingerprintSchema,
    failure: FailureDescriptorSchema.refine(
      ({ domain }) => domain === "shared",
      "Recovery holds require a shared failure.",
    ),
    first_failed_at: z.iso.datetime(),
    last_failed_at: z.iso.datetime(),
    consecutive_failures: z.number().int().positive(),
    next_probe_at: z.iso.datetime(),
    notified: z.boolean(),
  })
  .superRefine((hold, context) => {
    if (hold.error_fingerprint !== failureFingerprint(hold.failure))
      context.addIssue({
        code: "custom",
        path: ["error_fingerprint"],
        message: "Hold fingerprint must match its failure descriptor.",
      });
    if (Date.parse(hold.last_failed_at) < Date.parse(hold.first_failed_at))
      context.addIssue({
        code: "custom",
        path: ["last_failed_at"],
        message: "Shared failure time cannot precede its first failure.",
      });
    if (hold.notified !== hold.consecutive_failures >= 4)
      context.addIssue({
        code: "custom",
        path: ["notified"],
        message: "Shared notification state must match its threshold.",
      });
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
    schema_version: z.literal(2),
    updated_at: z.iso.datetime(),
    coverage_started_at: z.iso.datetime().nullable(),
    pause: PauseSchema.nullable(),
    target_retries: z.array(TargetRetryEntrySchema),
    shared_holds: z.array(SharedRecoveryHoldSchema),
    active_scans: z.array(ActiveScanSchema),
    policy_campaigns: z.array(PolicyCampaignSchema),
  })
  .superRefine((state, context) => {
    const retryIdentities = state.target_retries.map(
      (entry) => `${entry.repository_id}:${entry.target_sha}`,
    );
    if (new Set(retryIdentities).size !== retryIdentities.length)
      context.addIssue({
        code: "custom",
        path: ["target_retries"],
        message: "Each target may have only one classified retry sequence.",
      });
    const holdFingerprints = state.shared_holds.map(
      ({ error_fingerprint }) => error_fingerprint,
    );
    if (new Set(holdFingerprints).size !== holdFingerprints.length)
      context.addIssue({
        code: "custom",
        path: ["shared_holds"],
        message: "Shared recovery hold fingerprints must be unique.",
      });
    for (const fingerprint of holdFingerprints)
      if (
        !state.target_retries.some(
          (entry) => entry.error_fingerprint === fingerprint,
        )
      )
        context.addIssue({
          code: "custom",
          path: ["shared_holds"],
          message: "Every shared hold must retain an eligible probe target.",
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
    for (const campaign of state.policy_campaigns)
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
  });

export type TargetRetryEntry = z.infer<typeof TargetRetryEntrySchema>;
export type SharedRecoveryHold = z.infer<typeof SharedRecoveryHoldSchema>;
export type OperationsState = z.infer<typeof OperationsStateSchema>;

export function initialOperationsState(now: string): OperationsState {
  return OperationsStateSchema.parse({
    schema_version: 2,
    updated_at: now,
    coverage_started_at: null,
    pause: null,
    target_retries: [],
    shared_holds: [],
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
    target_retries: [...parsed.target_retries].sort((left, right) =>
      [left.repository_id, left.target_sha, left.error_fingerprint]
        .join(":")
        .localeCompare(
          [right.repository_id, right.target_sha, right.error_fingerprint].join(
            ":",
          ),
        ),
    ),
    shared_holds: [...parsed.shared_holds].sort((left, right) =>
      left.error_fingerprint.localeCompare(right.error_fingerprint),
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
  const releasingSecurityHold = state.pause?.reason_code === "SECURITY_HOLD";
  return OperationsStateSchema.parse({
    ...state,
    updated_at: at,
    coverage_started_at: state.coverage_started_at ?? at,
    pause: null,
    target_retries: releasingSecurityHold
      ? state.target_retries.filter(
          ({ failure }) => failure.domain !== "security",
        )
      : state.target_retries,
  });
}
