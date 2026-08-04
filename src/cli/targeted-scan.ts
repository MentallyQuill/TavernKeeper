import { parseReportIndexV5 } from "../contracts/reports-v5.js";
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
import { TARGET_MANIFEST_URL } from "./reconcile.js";
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
  requestCreatedAt,
}: {
  manifest: unknown;
  index: unknown;
  state: unknown;
  repositoryId: number;
  scannerPolicyVersion: string;
  requestCreatedAt: string;
}) {
  const manifest = requireTargetManifestV2(parseTargetManifest(manifestInput));
  const index = parseReportIndexV5(indexInput);
  const state = parseOperationsState(stateInput);
  const target = manifest.repositories.find(
    ({ repository_id }) => repository_id === repositoryId,
  );
  if (target === undefined)
    throw new Error(
      "Targeted repository ID is not in Tavernary's current target manifest.",
    );
  const requestCreatedAtMs = Date.parse(requestCreatedAt);
  if (!Number.isFinite(requestCreatedAtMs))
    throw new Error("Targeted workflow creation time is invalid.");
  const previous = index.reports.filter(
    ({ repository_id }) => repository_id === target.repository_id,
  );
  if (state.pause !== null || state.shared_holds.length > 0)
    return { include: [], coalesced: true };
  const matchingReports = previous.filter(
    ({ target_sha, scanner_policy_version }) =>
      target_sha === target.target_sha &&
      scanner_policy_version === scannerPolicyVersion,
  );
  if (
    state.active_scans.some(
      (active) =>
        active.repository_id === target.repository_id &&
        active.target_sha === target.target_sha,
    ) ||
    matchingReports.some(
      ({ completed_at }) => Date.parse(completed_at) >= requestCreatedAtMs,
    )
  )
    return { include: [], coalesced: true };

  const prior = matchingReports.sort(
    (left, right) => right.report_version - left.report_version,
  )[0];
  const request = ScanRequestSchema.parse({
    ...target,
    reason: "staff",
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
    readJsonFile("reports/index.json"),
    readJsonFile("operations/state.json"),
  ]);
  return buildTargetedMatrix({
    manifest,
    index,
    state,
    repositoryId: hint.repository_id,
    scannerPolicyVersion: "3",
    requestCreatedAt: requiredEnvironment(
      process.env,
      "TAVERNKEEPER_REQUEST_CREATED_AT",
    ),
  });
}

if (isDirectExecution(import.meta.url)) runJsonCli(main);
