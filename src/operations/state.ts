import { z } from "zod";

import { FullShaSchema } from "../contracts/targets.js";
import { FailureDescriptorSchema, failureFingerprint } from "./failure.js";

const SafeCodeSchema = z.string().regex(/^[A-Z][A-Z0-9_]{0,79}$/u);
const SourceIdSchema = z.string().regex(/^github-[1-9][0-9]*$/u);
const RepositorySchema = z.string().regex(/^[^/\s]+\/[^/\s]+$/u);
const SafePositiveIntegerSchema = z
  .number()
  .int()
  .positive()
  .max(Number.MAX_SAFE_INTEGER);
const SafeNonnegativeIntegerSchema = z
  .number()
  .int()
  .nonnegative()
  .max(Number.MAX_SAFE_INTEGER);
const FingerprintSchema = z.string().regex(/^[a-f0-9]{64}$/u);

export const AutomaticRecoveryHoldSchema = z
  .strictObject({
    error_fingerprint: FingerprintSchema,
    failure: FailureDescriptorSchema.refine(
      ({ domain }) => domain === "shared" || domain === "security",
      "Automatic holds require a shared or security failure.",
    ),
    first_failed_at: z.iso.datetime(),
    last_failed_at: z.iso.datetime(),
    consecutive_failures: SafePositiveIntegerSchema,
    next_probe_at: z.iso.datetime(),
    chronic: z.boolean(),
  })
  .superRefine((hold, context) => {
    if (hold.error_fingerprint !== failureFingerprint(hold.failure))
      context.addIssue({
        code: "custom",
        path: ["error_fingerprint"],
        message: "Automatic hold fingerprint must match its failure.",
      });
    if (hold.chronic !== hold.consecutive_failures >= 5)
      context.addIssue({
        code: "custom",
        path: ["chronic"],
        message: "Chronic state must match the automatic failure streak.",
      });
    if (Date.parse(hold.last_failed_at) < Date.parse(hold.first_failed_at))
      context.addIssue({
        code: "custom",
        path: ["last_failed_at"],
        message: "Latest automatic failure cannot precede the first.",
      });
    if (Date.parse(hold.next_probe_at) < Date.parse(hold.last_failed_at))
      context.addIssue({
        code: "custom",
        path: ["next_probe_at"],
        message: "Automatic probe cannot precede the latest failure.",
      });
  });

export const ScanQueueEntrySchema = z
  .strictObject({
    source_id: SourceIdSchema,
    repository_id: SafePositiveIntegerSchema,
    repository: RepositorySchema,
    target_sha: FullShaSchema,
    ticket: SafePositiveIntegerSchema,
    consecutive_failures: SafeNonnegativeIntegerSchema,
    total_failures: SafeNonnegativeIntegerSchema,
    not_before: z.iso.datetime().nullable(),
    last_failure: FailureDescriptorSchema.nullable(),
    last_failed_at: z.iso.datetime().nullable(),
    chronic: z.boolean(),
    staff_requested: z.literal(true).optional(),
  })
  .superRefine((entry, context) => {
    if (entry.source_id !== `github-${entry.repository_id}`)
      context.addIssue({
        code: "custom",
        path: ["source_id"],
        message: "Queue source ID must match repository ID.",
      });
    if (entry.total_failures < entry.consecutive_failures)
      context.addIssue({
        code: "custom",
        path: ["total_failures"],
        message: "Total failures cannot be below the current failure streak.",
      });
    if (entry.chronic !== entry.consecutive_failures >= 5)
      context.addIssue({
        code: "custom",
        path: ["chronic"],
        message: "Chronic state must match the current failure streak.",
      });

    if (entry.consecutive_failures === 0) {
      if (
        entry.last_failure !== null ||
        entry.last_failed_at !== null ||
        entry.not_before !== null
      )
        context.addIssue({
          code: "custom",
          path: ["consecutive_failures"],
          message:
            "A clear failure streak cannot retain failure cooldown data.",
        });
      return;
    }

    if (entry.last_failure === null || entry.last_failed_at === null)
      context.addIssue({
        code: "custom",
        path: ["last_failure"],
        message: "A failure streak requires its latest sanitized failure.",
      });
    if (
      entry.not_before !== null &&
      entry.last_failed_at !== null &&
      Date.parse(entry.not_before) < Date.parse(entry.last_failed_at)
    )
      context.addIssue({
        code: "custom",
        path: ["not_before"],
        message: "A retry cooldown cannot precede its failure.",
      });
  });

export const ScanQueueSchema = z
  .strictObject({
    next_ticket: SafePositiveIntegerSchema,
    entries: z.array(ScanQueueEntrySchema),
  })
  .superRefine((queue, context) => {
    const repositoryIds = queue.entries.map(
      ({ repository_id }) => repository_id,
    );
    if (new Set(repositoryIds).size !== repositoryIds.length)
      context.addIssue({
        code: "custom",
        path: ["entries"],
        message: "Each repository may have only one queued target.",
      });
    const tickets = queue.entries.map(({ ticket }) => ticket);
    if (new Set(tickets).size !== tickets.length)
      context.addIssue({
        code: "custom",
        path: ["entries"],
        message: "Queue tickets must be unique.",
      });
    if (tickets.some((ticket) => ticket >= queue.next_ticket))
      context.addIssue({
        code: "custom",
        path: ["next_ticket"],
        message: "Next queue ticket must exceed every issued ticket.",
      });
  });

export const EmergencyStopSchema = z.strictObject({
  kind: z.literal("staff"),
  reason_code: SafeCodeSchema,
  paused_at: z.iso.datetime(),
});

export const ActiveScanSchema = z
  .strictObject({
    source_id: SourceIdSchema,
    repository_id: SafePositiveIntegerSchema,
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
  repository_ids: z.array(SafePositiveIntegerSchema),
  created_at: z.iso.datetime(),
  status: z.enum(["active", "completed"]),
});

export const OperationsStateSchema = z
  .strictObject({
    schema_version: z.literal(3),
    updated_at: z.iso.datetime(),
    coverage_started_at: z.iso.datetime().nullable(),
    emergency_stop: EmergencyStopSchema.nullable(),
    automatic_holds: z.array(AutomaticRecoveryHoldSchema),
    scan_queue: ScanQueueSchema,
    active_scans: z.array(ActiveScanSchema),
    policy_campaigns: z.array(PolicyCampaignSchema),
  })
  .superRefine((state, context) => {
    const holdFingerprints = state.automatic_holds.map(
      ({ error_fingerprint }) => error_fingerprint,
    );
    if (new Set(holdFingerprints).size !== holdFingerprints.length)
      context.addIssue({
        code: "custom",
        path: ["automatic_holds"],
        message: "Automatic hold fingerprints must be unique.",
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

export type ScanQueueEntry = z.infer<typeof ScanQueueEntrySchema>;
export type ScanQueue = z.infer<typeof ScanQueueSchema>;
export type AutomaticRecoveryHold = z.infer<typeof AutomaticRecoveryHoldSchema>;
export type OperationsState = z.infer<typeof OperationsStateSchema>;

export function initialOperationsState(now: string): OperationsState {
  return OperationsStateSchema.parse({
    schema_version: 3,
    updated_at: now,
    coverage_started_at: null,
    emergency_stop: null,
    automatic_holds: [],
    scan_queue: { next_ticket: 1, entries: [] },
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
    automatic_holds: [...parsed.automatic_holds].sort((left, right) =>
      left.error_fingerprint.localeCompare(right.error_fingerprint),
    ),
    scan_queue: {
      ...parsed.scan_queue,
      entries: [...parsed.scan_queue.entries].sort(
        (left, right) => left.ticket - right.ticket,
      ),
    },
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
  input: { kind: "staff"; reasonCode: string; at: string },
) {
  return OperationsStateSchema.parse({
    ...state,
    updated_at: input.at,
    emergency_stop: {
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
    emergency_stop: null,
  });
}
