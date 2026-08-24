import {
  readJsonFile,
  fetchFixedJson,
  isDirectExecution,
  runJsonCli,
} from "./io.js";
import {
  parseReportIndexV5,
  type ReportIndexV5,
} from "../contracts/reports-v5.js";
import {
  parseTargetManifest,
  type CurrentTargetManifest,
} from "../contracts/targets.js";
import { parseOperationsState } from "../operations/state.js";
import { planBatch, type PlannedTarget } from "../queue/backlog.js";
import { ScanRequestSchema } from "./staff-request.js";
import {
  CURRENT_CONTEXTUAL_REVIEW_POLICY_VERSION,
  CURRENT_SCANNER_POLICY_VERSION,
} from "../config/policy.js";
import { nextRepositoryReportLineage } from "../publish/report-lineage.js";

export const TARGET_MANIFEST_URL =
  "https://tavernary.org/security/tavernkeeper-targets.json";
export const REPORT_INDEX_URL =
  "https://mentallyquill.github.io/TavernKeeper/reports/index.json";

export function buildRequestsForPlannedTargets(input: {
  manifest: CurrentTargetManifest;
  index: ReportIndexV5;
  plannedTargets: PlannedTarget[];
  scannerPolicyVersion: string;
}) {
  const targetMetadata = new Map(
    input.manifest.repositories.map((target) => [target.repository_id, target]),
  );
  return input.plannedTargets.map(({ target, reason, recoveryFingerprint }) => {
    const repositoryReports = input.index.reports.filter(
      ({ repository_id }) => repository_id === target.repository_id,
    );
    const lineage = nextRepositoryReportLineage(input.index, target);
    const previousShas = [
      ...new Set(repositoryReports.map(({ target_sha }) => target_sha)),
    ].slice(0, 20);
    return ScanRequestSchema.parse({
      ...targetMetadata.get(target.repository_id),
      reason,
      ...lineage,
      previous_report_shas: previousShas,
      ...(recoveryFingerprint === undefined
        ? {}
        : { recovery_fingerprint: recoveryFingerprint }),
    });
  });
}

export function buildReconcileMatrix({
  manifest: manifestInput,
  index: indexInput,
  state: stateInput,
  now,
  scannerPolicyVersion = CURRENT_SCANNER_POLICY_VERSION,
  contextualReviewPolicyVersion = CURRENT_CONTEXTUAL_REVIEW_POLICY_VERSION,
  forceProviderProbe = false,
}: {
  manifest: unknown;
  index: unknown;
  state: unknown;
  now: string;
  scannerPolicyVersion?: string;
  contextualReviewPolicyVersion?: string;
  forceProviderProbe?: boolean;
}) {
  const manifest = parseTargetManifest(manifestInput);
  const index = parseReportIndexV5(indexInput);
  const state = parseOperationsState(stateInput);
  if (manifest.schema_version === 1) {
    return {
      include: [],
      total_remaining: 0,
      runnable_remaining: 0,
      delayed_entries: 0,
      next_wake_at: null,
      emergency_stopped: false,
      automatic_holds: 0,
      recovery_probes: 0,
      provider_probe_fingerprint: null,
    };
  }
  const plan = planBatch(
    manifest,
    index,
    state,
    now,
    scannerPolicyVersion,
    contextualReviewPolicyVersion,
    forceProviderProbe,
  );
  const include = buildRequestsForPlannedTargets({
    manifest,
    index,
    plannedTargets: plan.targets,
    scannerPolicyVersion,
  });
  return {
    include,
    total_remaining: plan.totalRemaining,
    runnable_remaining: plan.runnableRemaining,
    delayed_entries: plan.delayedEntries,
    next_wake_at: plan.nextWakeAt,
    emergency_stopped: plan.emergencyStopped,
    automatic_holds: plan.automaticHolds,
    recovery_probes: plan.recoveryProbes,
    provider_probe_fingerprint: plan.providerProbeFingerprint,
  };
}

async function main() {
  const [manifestInput, indexInput, stateInput] = await Promise.all([
    fetchFixedJson(TARGET_MANIFEST_URL),
    fetchFixedJson(REPORT_INDEX_URL),
    readJsonFile("operations/state.json"),
  ]);
  const planned = buildReconcileMatrix({
    manifest: manifestInput,
    index: indexInput,
    state: stateInput,
    now: new Date().toISOString(),
    forceProviderProbe:
      process.env.TAVERNKEEPER_FORCE_PROVIDER_PROBE === "true",
  });
  return planned;
}

if (isDirectExecution(import.meta.url)) runJsonCli(main);
