import type { ReportIndexV5 } from "../contracts/reports-v5.js";
import type { CurrentTargetManifest } from "../contracts/targets.js";
import {
  CURRENT_CONTEXTUAL_REVIEW_POLICY_VERSION,
  CURRENT_SCANNER_POLICY_VERSION,
} from "../config/policy.js";
import { migrateOperationsState } from "../operations/migrate-state.js";
import { parseOperationsState } from "../operations/state.js";
import { reconcileCurrentScanQueue } from "./reconcile.js";

export function syncScanQueue(input: {
  manifest: CurrentTargetManifest;
  index: ReportIndexV5;
  state: unknown;
  now: string;
  scannerPolicyVersion: string;
  contextualReviewPolicyVersion?: string;
}) {
  const contextualReviewPolicyVersion =
    input.contextualReviewPolicyVersion ??
    (input.scannerPolicyVersion === CURRENT_SCANNER_POLICY_VERSION
      ? CURRENT_CONTEXTUAL_REVIEW_POLICY_VERSION
      : "1");
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
      contextualReviewPolicyVersion,
    });
    return { state: migrated.state, changed: true, summary: migrated.summary };
  }
  return reconcileCurrentScanQueue({
    manifest: input.manifest,
    index: input.index,
    state: parseOperationsState(input.state),
    now: input.now,
    scannerPolicyVersion: input.scannerPolicyVersion,
    contextualReviewPolicyVersion,
  });
}
