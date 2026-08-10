import { randomUUID } from "node:crypto";
import { rename, rm, writeFile } from "node:fs/promises";
import { resolve } from "node:path";

import {
  COVERAGE_CAMPAIGN_ID,
  OperationsStateSchema,
  parseOperationsState,
  serializeOperationsState,
} from "../operations/state.js";
import {
  selectCoverageCampaign,
  type CoverageFetch,
} from "../coverage/select-campaign.js";
import {
  fetchFixedJson,
  isDirectExecution,
  readJsonFile,
  requiredEnvironment,
  runJsonCli,
} from "./io.js";
import { TARGET_MANIFEST_URL } from "./reconcile.js";

async function replaceOperationsState(path: string, serialized: string) {
  const temporary = `${path}.${randomUUID()}.tmp`;
  try {
    await writeFile(temporary, serialized, { flag: "wx" });
    await rename(temporary, path);
  } finally {
    await rm(temporary, { force: true });
  }
}

export async function runCoverageCampaign(input: {
  statePath: string;
  githubToken: string;
  fetchManifest: () => Promise<unknown>;
  fetcher: CoverageFetch;
  now: () => string;
}) {
  const state = parseOperationsState(await readJsonFile(input.statePath));
  if (
    state.coverage_campaigns.some(
      (campaign) => campaign.id === COVERAGE_CAMPAIGN_ID,
    )
  )
    return { status: "already-present" as const };
  const campaign = await selectCoverageCampaign({
    manifest: await input.fetchManifest(),
    githubToken: input.githubToken,
    fetcher: input.fetcher,
    now: input.now,
  });
  const next = OperationsStateSchema.parse({
    ...state,
    updated_at: campaign.created_at,
    coverage_campaigns: [...state.coverage_campaigns, campaign],
  });
  await replaceOperationsState(input.statePath, serializeOperationsState(next));
  return {
    status: "created" as const,
    repositories: campaign.repository_ids.length,
  };
}

async function main() {
  return runCoverageCampaign({
    statePath: resolve(process.argv[2] ?? "operations/state.json"),
    githubToken: requiredEnvironment(process.env, "GITHUB_TOKEN"),
    fetchManifest: () => fetchFixedJson(TARGET_MANIFEST_URL),
    fetcher: fetch,
    now: () => new Date().toISOString(),
  });
}

if (isDirectExecution(import.meta.url)) runJsonCli(main);
