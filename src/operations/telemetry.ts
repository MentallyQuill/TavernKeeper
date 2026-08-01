import { z } from "zod";

const UsageSchema = z.strictObject({
  inputTokens: z.number().int().nonnegative(),
  outputTokens: z.number().int().nonnegative(),
  cacheReadTokens: z.number().int().nonnegative(),
  reasoningTokens: z.number().int().nonnegative(),
});

const ScanTelemetrySchema = z.strictObject({
  repositoryId: z.number().int().positive(),
  outcome: z.enum(["completed", "repository-failed", "system-failed"]),
  chunks: z.number().int().nonnegative(),
  usage: UsageSchema,
});

const QueueTelemetrySchema = z.strictObject({
  desired: z.number().int().nonnegative(),
  pending: z.number().int().nonnegative(),
  active: z.number().int().nonnegative(),
  retrying: z.number().int().nonnegative(),
  blocked: z.number().int().nonnegative(),
  superseded: z.number().int().nonnegative(),
  oldestPendingAt: z.iso.datetime().nullable(),
});

const ScannerTelemetrySchema = z.strictObject({
  name: z.string().regex(/^[a-z0-9][a-z0-9-]{0,79}$/u),
  version: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/u),
  status: z.enum(["completed", "not-applicable", "failed"]),
  runtimeMs: z.number().int().nonnegative(),
});

const VersionSchema = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/u);

const TelemetryInputSchema = z.strictObject({
  runId: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/u),
  startedAt: z.iso.datetime(),
  completedAt: z.iso.datetime(),
  queue: QueueTelemetrySchema,
  scans: z.array(ScanTelemetrySchema),
  scanners: z.array(ScannerTelemetrySchema),
  cache: z.strictObject({
    hits: z.number().int().nonnegative(),
    misses: z.number().int().nonnegative(),
  }),
  retry: z
    .strictObject({
      scope: z.enum(["repository", "system"]),
      attempt: z.number().int().min(1).max(3),
    })
    .nullable(),
  publication: z.strictObject({
    reportCommit: z
      .string()
      .regex(/^[0-9a-f]{40}$/u)
      .nullable(),
    pagesVerifiedAt: z.iso.datetime().nullable(),
    tavernaryWakeAt: z.iso.datetime().nullable(),
  }),
  versions: z.strictObject({
    contract: VersionSchema,
    scanner: VersionSchema,
    scannerPolicy: VersionSchema,
    promptPolicy: VersionSchema,
  }),
});

export function buildTelemetry(input: z.input<typeof TelemetryInputSchema>) {
  const parsed = TelemetryInputSchema.parse(input);
  const started = Date.parse(parsed.startedAt);
  const completed = Date.parse(parsed.completedAt);
  if (completed < started)
    throw new Error("Telemetry completion precedes start.");
  const usage = parsed.scans.reduce(
    (totals, scan) => ({
      inputTokens: totals.inputTokens + scan.usage.inputTokens,
      outputTokens: totals.outputTokens + scan.usage.outputTokens,
      cacheReadTokens: totals.cacheReadTokens + scan.usage.cacheReadTokens,
      reasoningTokens: totals.reasoningTokens + scan.usage.reasoningTokens,
    }),
    {
      inputTokens: 0,
      outputTokens: 0,
      cacheReadTokens: 0,
      reasoningTokens: 0,
    },
  );
  const scanCounts = {
    completed: parsed.scans.filter(({ outcome }) => outcome === "completed")
      .length,
    repositoryFailed: parsed.scans.filter(
      ({ outcome }) => outcome === "repository-failed",
    ).length,
    systemFailed: parsed.scans.filter(
      ({ outcome }) => outcome === "system-failed",
    ).length,
  };
  const durationMs = completed - started;
  const oldestPendingAgeMs =
    parsed.queue.oldestPendingAt === null
      ? null
      : Math.max(0, completed - Date.parse(parsed.queue.oldestPendingAt));
  return {
    schemaVersion: 1,
    runId: parsed.runId,
    startedAt: parsed.startedAt,
    completedAt: parsed.completedAt,
    durationMs,
    queue: {
      desired: parsed.queue.desired,
      pending: parsed.queue.pending,
      active: parsed.queue.active,
      retrying: parsed.queue.retrying,
      blocked: parsed.queue.blocked,
      superseded: parsed.queue.superseded,
      oldestPendingAgeMs,
    },
    scans: scanCounts,
    throughput: {
      completedPerHour:
        durationMs === 0 ? 0 : scanCounts.completed / (durationMs / 3_600_000),
    },
    scanners: [...parsed.scanners].sort((left, right) =>
      left.name.localeCompare(right.name),
    ),
    model: {
      chunks: parsed.scans.reduce((total, scan) => total + scan.chunks, 0),
      usage,
    },
    cache: parsed.cache,
    retry: parsed.retry,
    publication: parsed.publication,
    versions: parsed.versions,
  } as const;
}

export function allowanceWarnings({
  used,
  allowance,
}: {
  used: number;
  allowance: number;
}) {
  if (
    !Number.isFinite(used) ||
    !Number.isFinite(allowance) ||
    used < 0 ||
    allowance <= 0
  )
    throw new Error("Allowance accounting is invalid.");
  const percentage = (used / allowance) * 100;
  if (percentage >= 90) return [90] as const;
  if (percentage >= 75) return [75] as const;
  if (percentage >= 50) return [50] as const;
  return [] as const;
}
