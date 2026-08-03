import { z } from "zod";

const CountSchema = z.number().int().nonnegative();
const DigestSchema = z.string().regex(/^[0-9a-f]{64}$/u);
const VersionSchema = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/u);

const ScanTelemetrySchema = z.strictObject({
  repositoryId: z.number().int().positive(),
  outcome: z.enum(["completed", "repository-failed", "system-failed"]),
  packageDigest: DigestSchema.nullable(),
  result: z.enum(["teal", "red"]).nullable(),
  findings: CountSchema,
  inventory: z.strictObject({ files: CountSchema, bytes: CountSchema }),
  tools: z.strictObject({
    completed: CountSchema,
    notApplicable: CountSchema,
    failed: CountSchema,
  }),
});

const QueueTelemetrySchema = z.strictObject({
  desired: CountSchema,
  pending: CountSchema,
  active: CountSchema,
  retrying: CountSchema,
  blocked: CountSchema,
  superseded: CountSchema,
  oldestPendingAt: z.iso.datetime().nullable(),
});

const ScannerTelemetrySchema = z.strictObject({
  name: z.string().regex(/^[a-z0-9][a-z0-9-]{0,79}$/u),
  version: VersionSchema,
  status: z.enum(["completed", "not-applicable", "failed"]),
  runtimeMs: CountSchema,
});

const TelemetryInputSchema = z.strictObject({
  runId: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$/u),
  startedAt: z.iso.datetime(),
  completedAt: z.iso.datetime(),
  queue: QueueTelemetrySchema,
  scans: z.array(ScanTelemetrySchema),
  scanners: z.array(ScannerTelemetrySchema),
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
    ruleCatalog: VersionSchema,
    packageSchema: z.number().int().positive(),
  }),
});

export function buildTelemetry(input: z.input<typeof TelemetryInputSchema>) {
  const parsed = TelemetryInputSchema.parse(input);
  const started = Date.parse(parsed.startedAt);
  const completed = Date.parse(parsed.completedAt);
  if (completed < started)
    throw new Error("Telemetry completion precedes start.");
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
  const { oldestPendingAt: _oldestPendingAt, ...queueCounts } = parsed.queue;
  return {
    schemaVersion: 2,
    runId: parsed.runId,
    startedAt: parsed.startedAt,
    completedAt: parsed.completedAt,
    durationMs,
    queue: { ...queueCounts, oldestPendingAgeMs },
    scans: scanCounts,
    scanResults: parsed.scans.map((scan) => ({
      repositoryId: scan.repositoryId,
      outcome: scan.outcome,
      packageDigest: scan.packageDigest,
      result: scan.result,
      findings: scan.findings,
      inventory: scan.inventory,
      tools: scan.tools,
    })),
    throughput: {
      completedPerHour:
        durationMs === 0 ? 0 : scanCounts.completed / (durationMs / 3_600_000),
    },
    scanners: [...parsed.scanners].sort((left, right) =>
      left.name.localeCompare(right.name),
    ),
    retry: parsed.retry,
    publication: parsed.publication,
    versions: parsed.versions,
  } as const;
}
