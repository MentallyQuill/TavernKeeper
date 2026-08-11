import { randomUUID } from "node:crypto";
import { writeFile } from "node:fs/promises";

import { z } from "zod";

import {
  CURRENT_SCANNER_POLICY_PATH,
  loadScannerPolicy,
} from "../config/policy.js";
import {
  parseTargetManifest,
  requireTargetManifestV2,
  type CurrentTargetManifest,
} from "../contracts/targets.js";
import {
  parseReportIndexV5,
  type ReportIndexV5,
} from "../contracts/reports-v5.js";
import {
  OperationsStateSchema,
  parseOperationsState,
  serializeOperationsState,
} from "../operations/state.js";
import {
  fetchFixedJson,
  isDirectExecution,
  readJsonFile,
  runJsonCli,
} from "./io.js";
import { TARGET_MANIFEST_URL } from "./reconcile.js";

const PolicyRescanScopeSchema = z.enum(["all", "yellow"]);

export function selectPolicyRescanRepositoryIds({
  scope,
  manifest,
  index,
}: {
  scope: unknown;
  manifest: CurrentTargetManifest;
  index: ReportIndexV5;
}): number[] {
  const parsedScope = PolicyRescanScopeSchema.parse(scope);
  if (parsedScope === "all")
    return manifest.repositories.map(({ repository_id }) => repository_id);

  const yellowRepositoryIds = new Set(
    index.reports
      .filter(
        ({ counts }) =>
          counts.recommended_risk.material > 0 ||
          counts.recommended_risk.high > 0,
      )
      .map(({ repository_id }) => repository_id),
  );
  const selected = manifest.repositories
    .filter(({ repository_id }) => yellowRepositoryIds.has(repository_id))
    .map(({ repository_id }) => repository_id);
  if (selected.length === 0)
    throw new Error("Yellow policy rescan selected no repositories.");
  return selected;
}

async function main() {
  const scope = PolicyRescanScopeSchema.parse(
    process.env.TAVERNKEEPER_POLICY_RESCAN_SCOPE ?? "all",
  );
  const [policy, manifest, index, state] = await Promise.all([
    loadScannerPolicy(CURRENT_SCANNER_POLICY_PATH),
    fetchFixedJson(TARGET_MANIFEST_URL).then((value) =>
      requireTargetManifestV2(parseTargetManifest(value)),
    ),
    readJsonFile("reports/index.json").then(parseReportIndexV5),
    readJsonFile("operations/state.json").then(parseOperationsState),
  ]);
  const repositoryIds = selectPolicyRescanRepositoryIds({
    scope,
    manifest,
    index,
  });
  const now = new Date().toISOString();
  const next = OperationsStateSchema.parse({
    ...state,
    updated_at: now,
    policy_campaigns: [
      ...state.policy_campaigns,
      {
        id: `policy-${policy.version}-${randomUUID()}`,
        scanner_policy_version: policy.version,
        repository_ids: repositoryIds,
        created_at: now,
        status: "active",
      },
    ],
  });
  await writeFile("operations/state.json", serializeOperationsState(next));
  return {
    status: "scheduled",
    scanner_policy_version: policy.version,
    scope,
    repositories: repositoryIds.length,
  };
}

if (isDirectExecution(import.meta.url)) runJsonCli(main);
