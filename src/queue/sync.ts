import type { ReportIndexV5 } from "../contracts/reports-v5.js";
import type { CurrentTargetManifest } from "../contracts/targets.js";
import { migrateOperationsState } from "../operations/migrate-state.js";
import { parseOperationsState } from "../operations/state.js";
import { reconcileCurrentScanQueue } from "./reconcile.js";

export function syncScanQueue(input: {
  manifest: CurrentTargetManifest;
  index: ReportIndexV5;
  state: unknown;
  now: string;
  scannerPolicyVersion: string;
}) {
  if (
    input.state !== null &&
    typeof input.state === "object" &&
    "schema_version" in input.state &&
    input.state.schema_version === 2
  ) {
    const migrated = migrateOperationsState(input.state, {
      manifest: input.manifest,
      index: input.index,
      at: input.now,
      scannerPolicyVersion: input.scannerPolicyVersion,
    });
    return { state: migrated.state, changed: true, summary: migrated.summary };
  }
  return reconcileCurrentScanQueue({
    manifest: input.manifest,
    index: input.index,
    state: parseOperationsState(input.state),
    now: input.now,
    scannerPolicyVersion: input.scannerPolicyVersion,
  });
}
