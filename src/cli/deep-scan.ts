import { parseReportIndex } from "../contracts/reports.js";
import {
  parseTargetManifest,
  requireTargetManifestV2,
} from "../contracts/targets.js";
import {
  fetchFixedJson,
  isDirectExecution,
  requiredEnvironment,
  runJsonCli,
} from "./io.js";
import { REPORT_INDEX_URL, TARGET_MANIFEST_URL } from "./reconcile.js";
import {
  ScanRequestSchema,
  validateStaffScanRequest,
} from "./staff-request.js";

async function main() {
  const request = validateStaffScanRequest(
    JSON.parse(requiredEnvironment(process.env, "TAVERNKEEPER_STAFF_SCAN")),
  );
  const [manifest, index] = await Promise.all([
    fetchFixedJson(TARGET_MANIFEST_URL).then((value) =>
      requireTargetManifestV2(parseTargetManifest(value)),
    ),
    fetchFixedJson(REPORT_INDEX_URL).then((value) => {
      const index = parseReportIndex(value);
      if (index.schema_version !== 2)
        throw new Error(
          "TavernKeeper report index version 2 is not published.",
        );
      return index;
    }),
  ]);
  const target = manifest.repositories.find(
    ({ repository_id }) => repository_id === request.repository_id,
  );
  if (target === undefined)
    throw new Error("Staff scan repository ID is not in Tavernary's manifest.");
  const previous = index.reports.filter(
    ({ repository_id }) => repository_id === target.repository_id,
  );
  const priorDeep = previous
    .filter(
      ({ target_sha, scanner_policy_version, mode }) =>
        target_sha === target.target_sha &&
        scanner_policy_version === "1" &&
        mode === "deep",
    )
    .sort((left, right) => right.report_version - left.report_version)[0];
  return ScanRequestSchema.parse({
    ...target,
    reason: "staff",
    mode: "deep",
    report_version: (priorDeep?.report_version ?? 0) + 1,
    supersedes_report_id: priorDeep?.report_id ?? null,
    previous_report_shas: [
      ...new Set(previous.map(({ target_sha }) => target_sha)),
    ].slice(0, 20),
  });
}

if (isDirectExecution(import.meta.url)) runJsonCli(main);
