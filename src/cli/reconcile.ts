import {
  readJsonFile,
  fetchFixedJson,
  isDirectExecution,
  runJsonCli,
} from "./io.js";
import { parseReportIndex } from "../contracts/reports.js";
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
  const index = parseReportIndex(indexInput);
  const state = parseOperationsState(stateInput);
  if (manifest.schema_version === 1) {
    return { include: [], remaining: 0, blocked: false };
  }
  const plan = planBatch(manifest, index, state, now, scannerPolicyVersion);
  const targetMetadata = new Map(
    manifest.repositories.map((target) => [target.repository_id, target]),
  );
  const include = plan.targets.map(({ target, reason }) => {
    const repositoryReports = index.reports.filter(
      ({ repository_id }) => repository_id === target.repository_id,
    );
    const previousShas = [
      ...new Set(repositoryReports.map(({ target_sha }) => target_sha)),
    ].slice(0, 20);
    return ScanRequestSchema.parse({
      ...targetMetadata.get(target.repository_id),
      reason,
      report_version: 1,
      supersedes_report_id: null,
      previous_report_shas: previousShas,
    });
  });
  return { include, remaining: plan.remaining, blocked: plan.blocked };
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
    scannerPolicyVersion: "2",
  });
  return planned;
}

if (isDirectExecution(import.meta.url)) runJsonCli(main);
