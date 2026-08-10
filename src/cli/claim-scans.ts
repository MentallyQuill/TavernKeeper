import { resolve } from "node:path";

import {
  CURRENT_CONTEXTUAL_REVIEW_POLICY_VERSION,
  CURRENT_SCANNER_POLICY_VERSION,
} from "../config/policy.js";
import { parseReportIndexV5 } from "../contracts/reports-v5.js";
import {
  parseTargetManifest,
  requireTargetManifestV2,
} from "../contracts/targets.js";
import { parseOperationsState } from "../operations/state.js";
import { planBatch } from "../queue/backlog.js";
import { claimScanSlots, expireStaleScanClaims } from "../queue/claims.js";
import { syncScanQueue } from "../queue/sync.js";
import {
  fetchFixedJson,
  isDirectExecution,
  readJsonFile,
  requiredEnvironment,
  runJsonCli,
  writeJsonFile,
} from "./io.js";
import {
  buildRequestsForPlannedTargets,
  TARGET_MANIFEST_URL,
} from "./reconcile.js";

export function buildScanClaims(input: {
  manifest: unknown;
  index: unknown;
  state: unknown;
  now: string;
  runId: string;
  scannerPolicyVersion?: string;
  contextualReviewPolicyVersion?: string;
  forceProviderProbe?: boolean;
}) {
  const manifest = requireTargetManifestV2(parseTargetManifest(input.manifest));
  const index = parseReportIndexV5(input.index);
  const scannerPolicyVersion =
    input.scannerPolicyVersion ?? CURRENT_SCANNER_POLICY_VERSION;
  const contextualReviewPolicyVersion =
    input.contextualReviewPolicyVersion ??
    CURRENT_CONTEXTUAL_REVIEW_POLICY_VERSION;
  const synchronized = syncScanQueue({
    manifest,
    index,
    state: parseOperationsState(input.state),
    now: input.now,
    scannerPolicyVersion,
    contextualReviewPolicyVersion,
  });
  const expired = expireStaleScanClaims(synchronized.state, input.now);
  const plan = planBatch(
    manifest,
    index,
    expired.state,
    input.now,
    scannerPolicyVersion,
    contextualReviewPolicyVersion,
    input.forceProviderProbe ?? false,
  );
  const claims = claimScanSlots({
    state: expired.state,
    plannedTargets: plan.targets,
    now: input.now,
    runId: input.runId,
  });
  const include = buildRequestsForPlannedTargets({
    manifest,
    index,
    plannedTargets: claims.claimed,
    scannerPolicyVersion,
  });
  const notClaimed = plan.targets.length - claims.claimed.length;
  return {
    state: claims.state,
    changed: synchronized.changed || expired.changed || claims.changed,
    include,
    total_remaining: plan.totalRemaining + notClaimed,
    runnable_remaining: plan.runnableRemaining + notClaimed,
    delayed_entries: plan.delayedEntries,
    next_wake_at: plan.nextWakeAt,
    emergency_stopped: plan.emergencyStopped,
    automatic_holds: plan.automaticHolds,
    recovery_probes: plan.recoveryProbes,
    provider_probe_fingerprint: plan.providerProbeFingerprint,
    queue_entries: claims.state.scan_queue.entries.length,
    active_scans: claims.state.active_scans.length,
    expired_claims: expired.expired,
    ...synchronized.summary,
  };
}

async function main() {
  const statePath = resolve("operations/state.json");
  const [manifest, index, state] = await Promise.all([
    fetchFixedJson(TARGET_MANIFEST_URL),
    readJsonFile(resolve("reports/index.json")),
    readJsonFile(statePath),
  ]);
  const claimed = buildScanClaims({
    manifest,
    index,
    state,
    now: new Date().toISOString(),
    runId: requiredEnvironment(process.env, "TAVERNKEEPER_CLAIM_RUN_ID"),
    forceProviderProbe:
      process.env.TAVERNKEEPER_FORCE_PROVIDER_PROBE === "true",
  });
  if (claimed.changed) await writeJsonFile(statePath, claimed.state);
  const { state: _state, ...output } = claimed;
  return output;
}

if (isDirectExecution(import.meta.url)) runJsonCli(main);
