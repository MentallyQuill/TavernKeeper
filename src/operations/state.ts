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

export const CatalogChangeSchema = z.enum(["new", "updated"]);

export const CatalogObservationSchema = z
  .strictObject({
    initialized_at: z.iso.datetime(),
    repositories: z.array(
      z.strictObject({
        repository_id: SafePositiveIntegerSchema,
        target_sha: FullShaSchema,
      }),
    ),
  })
  .refine(
    ({ repositories }) =>
      repositories.every(
        (entry, index) =>
          index === 0 ||
          repositories[index - 1]!.repository_id < entry.repository_id,
      ),
    {
      path: ["repositories"],
      message: "Observed repositories must be unique and sorted.",
    },
  );

export const ScanFailureHistoryEntrySchema = z
  .strictObject({
    failed_at: z.iso.datetime(),
    failure: FailureDescriptorSchema,
    error_fingerprint: FingerprintSchema,
  })
  .refine(
    (entry) => entry.error_fingerprint === failureFingerprint(entry.failure),
    {
      path: ["error_fingerprint"],
      message: "Scan failure fingerprint must match its failure.",
    },
  );

export const UnscannableTargetSchema = z
  .strictObject({
    source_id: SourceIdSchema,
    repository_id: SafePositiveIntegerSchema,
    repository: RepositorySchema,
    target_sha: FullShaSchema,
    unscannable_at: z.iso.datetime(),
    consecutive_failures: SafePositiveIntegerSchema.refine(
      (value) => value >= 3,
      "An unscannable target requires at least three consecutive failures.",
    ),
    total_failures: SafePositiveIntegerSchema,
    last_failure: FailureDescriptorSchema.refine(
      ({ domain }) => domain === "target",
      "An unscannable target requires a target-local failure.",
    ),
    last_failed_at: z.iso.datetime(),
    failure_history: z.array(ScanFailureHistoryEntrySchema).min(1).max(4),
  })
  .superRefine((entry, context) => {
    if (entry.source_id !== `github-${entry.repository_id}`)
      context.addIssue({
        code: "custom",
        path: ["source_id"],
        message: "Unscannable source ID must match repository ID.",
      });
    if (entry.total_failures < entry.consecutive_failures)
      context.addIssue({
        code: "custom",
        path: ["total_failures"],
        message: "Total failures cannot be below the terminal streak.",
      });
    if (
      entry.failure_history.some(
        (failure, index) =>
          index > 0 &&
          Date.parse(entry.failure_history[index - 1]!.failed_at) >
            Date.parse(failure.failed_at),
      )
    )
      context.addIssue({
        code: "custom",
        path: ["failure_history"],
        message: "Unscannable failure history must be chronological.",
      });
    const latest = entry.failure_history.at(-1)!;
    if (
      latest.failed_at !== entry.last_failed_at ||
      latest.error_fingerprint !== failureFingerprint(entry.last_failure)
    )
      context.addIssue({
        code: "custom",
        path: ["failure_history"],
        message: "Terminal history must end with the latest failure.",
      });
    if (Date.parse(entry.unscannable_at) < Date.parse(entry.last_failed_at))
      context.addIssue({
        code: "custom",
        path: ["unscannable_at"],
        message: "An unscannable timestamp cannot precede its last failure.",
      });
  });

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
    rescan_not_before: z.iso.datetime().optional(),
    catalog_change: CatalogChangeSchema.optional(),
    chronic: z.boolean(),
    failure_history: z
      .array(ScanFailureHistoryEntrySchema)
      .min(1)
      .max(4)
      .optional(),
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
    const history = entry.failure_history ?? [];
    if (history.length > entry.consecutive_failures)
      context.addIssue({
        code: "custom",
        path: ["failure_history"],
        message: "Failure history cannot exceed the current failure streak.",
      });
    if (
      history.some(
        (failure, index) =>
          index > 0 &&
          Date.parse(history[index - 1]!.failed_at) >
            Date.parse(failure.failed_at),
      )
    )
      context.addIssue({
        code: "custom",
        path: ["failure_history"],
        message: "Failure history must be chronological.",
      });
    if (entry.chronic !== entry.consecutive_failures >= 2)
      context.addIssue({
        code: "custom",
        path: ["chronic"],
        message: "Chronic state must match the current failure streak.",
      });

    if (entry.consecutive_failures === 0) {
      if (
        entry.last_failure !== null ||
        entry.last_failed_at !== null ||
        entry.not_before !== null ||
        history.length > 0
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
    const latestHistory = history.at(-1);
    if (
      latestHistory !== undefined &&
      (latestHistory.failed_at !== entry.last_failed_at ||
        entry.last_failure === null ||
        latestHistory.error_fingerprint !==
          failureFingerprint(entry.last_failure))
    )
      context.addIssue({
        code: "custom",
        path: ["failure_history"],
        message: "Failure history must end with the latest failure.",
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

export const COVERAGE_CAMPAIGN_ID =
  "one-time-top20-popular-latest-release-v2" as const;

const SortedRepositoryIdsSchema = z
  .array(SafePositiveIntegerSchema)
  .superRefine((repositoryIds, context) => {
    if (
      repositoryIds.some(
        (repositoryId, index) =>
          index > 0 && repositoryIds[index - 1]! >= repositoryId,
      )
    )
      context.addIssue({
        code: "custom",
        message: "Repository IDs must be unique and sorted.",
      });
  });

const CoverageComponentIdsSchema = SortedRepositoryIdsSchema.max(20);

export const CoverageCampaignSchema = z
  .strictObject({
    id: z.literal(COVERAGE_CAMPAIGN_ID),
    scanner_policy_version: z
      .string()
      .regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/u),
    created_at: z.iso.datetime(),
    status: z.enum(["active", "completed"]),
    popular_repository_ids: CoverageComponentIdsSchema,
    latest_release_repository_ids: CoverageComponentIdsSchema,
    repository_ids: SortedRepositoryIdsSchema,
    remaining_repository_ids: SortedRepositoryIdsSchema,
  })
  .superRefine((campaign, context) => {
    const exactUnion = [
      ...new Set([
        ...campaign.popular_repository_ids,
        ...campaign.latest_release_repository_ids,
      ]),
    ].sort((left, right) => left - right);
    if (JSON.stringify(campaign.repository_ids) !== JSON.stringify(exactUnion))
      context.addIssue({
        code: "custom",
        path: ["repository_ids"],
        message: "Coverage repository IDs must be the exact component union.",
      });
    const selected = new Set(campaign.repository_ids);
    if (
      campaign.remaining_repository_ids.some(
        (repositoryId) => !selected.has(repositoryId),
      )
    )
      context.addIssue({
        code: "custom",
        path: ["remaining_repository_ids"],
        message: "Remaining coverage IDs must belong to the selection.",
      });
    if (
      (campaign.status === "active") !==
      campaign.remaining_repository_ids.length > 0
    )
      context.addIssue({
        code: "custom",
        path: ["status"],
        message: "Coverage status must match whether members remain.",
      });
  });

export const OperationsStateSchema = z
  .strictObject({
    schema_version: z.literal(3),
    updated_at: z.iso.datetime(),
    coverage_started_at: z.iso.datetime().nullable(),
    emergency_stop: EmergencyStopSchema.nullable(),
    automatic_holds: z.array(AutomaticRecoveryHoldSchema),
    unscannable_targets: z.array(UnscannableTargetSchema).default([]),
    catalog_observation: CatalogObservationSchema.nullable().optional(),
    scan_queue: ScanQueueSchema,
    active_scans: z.array(ActiveScanSchema),
    policy_campaigns: z.array(PolicyCampaignSchema),
    coverage_campaigns: z.array(CoverageCampaignSchema).default([]),
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
    const unscannableRepositoryIds = state.unscannable_targets.map(
      ({ repository_id }) => repository_id,
    );
    if (
      new Set(unscannableRepositoryIds).size !== unscannableRepositoryIds.length
    )
      context.addIssue({
        code: "custom",
        path: ["unscannable_targets"],
        message: "Each repository may have only one unscannable tombstone.",
      });
    const unscannableSet = new Set(unscannableRepositoryIds);
    if (
      state.scan_queue.entries.some(({ repository_id }) =>
        unscannableSet.has(repository_id),
      )
    )
      context.addIssue({
        code: "custom",
        path: ["scan_queue"],
        message: "An unscannable repository cannot remain queued.",
      });
    if (
      state.active_scans.some(({ repository_id }) =>
        unscannableSet.has(repository_id),
      )
    )
      context.addIssue({
        code: "custom",
        path: ["active_scans"],
        message: "An unscannable repository cannot remain active.",
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
    const coverageCampaignIds = state.coverage_campaigns.map(({ id }) => id);
    if (new Set(coverageCampaignIds).size !== coverageCampaignIds.length)
      context.addIssue({
        code: "custom",
        path: ["coverage_campaigns"],
        message: "Coverage campaign IDs must be unique.",
      });
  });

export type ScanQueueEntry = z.infer<typeof ScanQueueEntrySchema>;
export type ScanQueue = z.infer<typeof ScanQueueSchema>;
export type AutomaticRecoveryHold = z.infer<typeof AutomaticRecoveryHoldSchema>;
export type UnscannableTarget = z.infer<typeof UnscannableTargetSchema>;
export type CatalogChange = z.infer<typeof CatalogChangeSchema>;
export type CatalogObservation = z.infer<typeof CatalogObservationSchema>;
export type CoverageCampaign = z.infer<typeof CoverageCampaignSchema>;
export type OperationsState = z.infer<typeof OperationsStateSchema>;

export function initialOperationsState(now: string): OperationsState {
  return OperationsStateSchema.parse({
    schema_version: 3,
    updated_at: now,
    coverage_started_at: null,
    emergency_stop: null,
    automatic_holds: [],
    unscannable_targets: [],
    catalog_observation: null,
    scan_queue: { next_ticket: 1, entries: [] },
    active_scans: [],
    policy_campaigns: [],
    coverage_campaigns: [],
  });
}

function normalizeLegacyRetryPolicyState(value: unknown): unknown {
  if (value === null || typeof value !== "object" || Array.isArray(value))
    return value;
  const state = value as Record<string, unknown>;
  if (
    state.schema_version !== 3 ||
    Object.prototype.hasOwnProperty.call(state, "unscannable_targets")
  )
    return value;
  const scanQueue = state.scan_queue;
  if (
    scanQueue === null ||
    typeof scanQueue !== "object" ||
    Array.isArray(scanQueue)
  )
    return { ...state, unscannable_targets: [] };
  const queue = scanQueue as Record<string, unknown>;
  const entries = Array.isArray(queue.entries)
    ? queue.entries.map((entry) => {
        if (entry === null || typeof entry !== "object" || Array.isArray(entry))
          return entry;
        const queueEntry = entry as Record<string, unknown>;
        return typeof queueEntry.consecutive_failures === "number"
          ? {
              ...queueEntry,
              chronic: queueEntry.consecutive_failures >= 2,
            }
          : entry;
      })
    : queue.entries;
  return {
    ...state,
    unscannable_targets: [],
    scan_queue: { ...queue, entries },
  };
}

export function parseOperationsState(value: unknown) {
  return OperationsStateSchema.parse(normalizeLegacyRetryPolicyState(value));
}

export function serializeOperationsState(state: OperationsState) {
  const parsed = OperationsStateSchema.parse(state);
  const canonical = OperationsStateSchema.parse({
    ...parsed,
    automatic_holds: [...parsed.automatic_holds].sort((left, right) =>
      left.error_fingerprint.localeCompare(right.error_fingerprint),
    ),
    unscannable_targets: [...parsed.unscannable_targets].sort(
      (left, right) => left.repository_id - right.repository_id,
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
    coverage_campaigns: [...parsed.coverage_campaigns].sort((left, right) =>
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

export function releaseAutomaticHolds(state: OperationsState, at: string) {
  if (state.automatic_holds.length === 0) return state;
  return OperationsStateSchema.parse({
    ...state,
    updated_at: at,
    automatic_holds: [],
  });
}
