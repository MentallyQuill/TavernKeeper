import { parseReportIndex } from "../contracts/reports.js";
import {
  parseTargetManifest,
  requireTargetManifestV2,
} from "../contracts/targets.js";
import { parseOperationsState } from "../operations/state.js";
import {
  fetchFixedJson,
  isDirectExecution,
  readJsonFile,
  requiredEnvironment,
  runJsonCli,
} from "./io.js";
import { REPORT_INDEX_URL, TARGET_MANIFEST_URL } from "./reconcile.js";
import {
  ScanRequestSchema,
  validateTargetedScanHint,
} from "./staff-request.js";

export function buildTargetedMatrix({
  manifest: manifestInput,
  index: indexInput,
  state: stateInput,
  repositoryId,
  scannerPolicyVersion,
}: {
  manifest: unknown;
  index: unknown;
  state: unknown;
  repositoryId: number;
  scannerPolicyVersion: string;
}) {
  const manifest = requireTargetManifestV2(parseTargetManifest(manifestInput));
  const index = parseReportIndex(indexInput);
  if (index.schema_version !== 2)
    throw new Error("TavernKeeper report index version 2 is not published.");
  const state = parseOperationsState(stateInput);
  const target = manifest.repositories.find(
    ({ repository_id }) => repository_id === repositoryId,
  );
  if (target === undefined)
    throw new Error(
      "Targeted repository ID is not in Tavernary's V2 manifest.",
    );
  if (
    state.active_scans.some(
      (active) =>
        active.repository_id === target.repository_id &&
        active.target_sha === target.target_sha,
    )
  )
    return { include: [], coalesced: true };

  const previous = index.reports.filter(
    ({ repository_id }) => repository_id === target.repository_id,
  );
  const prior = previous
    .filter(
      ({ target_sha, scanner_policy_version, mode }) =>
        target_sha === target.target_sha &&
        scanner_policy_version === scannerPolicyVersion &&
        mode === "standard",
    )
    .sort((left, right) => right.report_version - left.report_version)[0];
  const request = ScanRequestSchema.parse({
    ...target,
    reason: "staff",
    mode: "standard",
    report_version: (prior?.report_version ?? 0) + 1,
    supersedes_report_id: prior?.report_id ?? null,
    previous_report_shas: [
      ...new Set(previous.map(({ target_sha }) => target_sha)),
    ].slice(0, 20),
  });
  return { include: [request], coalesced: false };
}

async function main() {
  const hint = validateTargetedScanHint(
    JSON.parse(requiredEnvironment(process.env, "TAVERNKEEPER_TARGETED_SCAN")),
  );
  const [manifest, index, state] = await Promise.all([
    fetchFixedJson(TARGET_MANIFEST_URL),
    fetchFixedJson(REPORT_INDEX_URL),
    readJsonFile("operations/state.json"),
  ]);
  return buildTargetedMatrix({
    manifest,
    index,
    state,
    repositoryId: hint.repository_id,
    scannerPolicyVersion: "1",
  });
}

if (isDirectExecution(import.meta.url)) runJsonCli(main);
