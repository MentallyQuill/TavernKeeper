import {
  readJsonFile,
  fetchFixedJson,
  isDirectExecution,
  runJsonCli,
} from "./io.js";
import { parseReportIndexV5 } from "../contracts/reports-v5.js";
import { parseTargetManifest } from "../contracts/targets.js";
import { parseOperationsState } from "../operations/state.js";
import { planBatch } from "../queue/backlog.js";
import { ScanRequestSchema } from "./staff-request.js";

export const TARGET_MANIFEST_URL =
  "https://tavernary.org/security/tavernkeeper-targets.json";
export const REPORT_INDEX_URL =
  "https://mentallyquill.github.io/TavernKeeper/reports/index.json";

export function buildReconcileMatrix({
  manifest: manifestInput,
  index: indexInput,
  state: stateInput,
  now,
  scannerPolicyVersion,
}: {
  manifest: unknown;
  index: unknown;
  state: unknown;
  now: string;
  scannerPolicyVersion: string;
}) {
  const manifest = parseTargetManifest(manifestInput);
  const index = parseReportIndexV5(indexInput);
  const state = parseOperationsState(stateInput);
  if (manifest.schema_version === 1) {
    return {
      include: [],
      total_remaining: 0,
      runnable_remaining: 0,
      delayed_retries: 0,
      shared_holds: 0,
      next_wake_at: null,
      blocked: false,
    };
  }
  const plan = planBatch(manifest, index, state, now, scannerPolicyVersion);
  const targetMetadata = new Map(
    manifest.repositories.map((target) => [target.repository_id, target]),
  );
  const include = plan.targets.map(
    ({ target, reason, recoveryFingerprint }) => {
      const repositoryReports = index.reports.filter(
        ({ repository_id }) => repository_id === target.repository_id,
      );
      const previousShas = [
        ...new Set(repositoryReports.map(({ target_sha }) => target_sha)),
      ].slice(0, 20);
      return ScanRequestSchema.parse({
        ...targetMetadata.get(target.repository_id),
        reason,
        ...(recoveryFingerprint === undefined
          ? {}
          : { recovery_fingerprint: recoveryFingerprint }),
        report_version: 1,
        supersedes_report_id: null,
        previous_report_shas: previousShas,
      });
    },
  );
  return {
    include,
    total_remaining: plan.totalRemaining,
    runnable_remaining: plan.runnableRemaining,
    delayed_retries: plan.delayedRetries,
    shared_holds: plan.sharedHolds,
    next_wake_at: plan.nextWakeAt,
    blocked: plan.blocked,
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
    scannerPolicyVersion: "3",
  });
  return planned;
}

if (isDirectExecution(import.meta.url)) runJsonCli(main);
