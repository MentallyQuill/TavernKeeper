import { randomUUID } from "node:crypto";
import { writeFile } from "node:fs/promises";

import { loadScannerPolicy } from "../config/policy.js";
import {
  parseTargetManifest,
  requireTargetManifestV2,
} from "../contracts/targets.js";
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

async function main() {
  const [policy, manifest, state] = await Promise.all([
    loadScannerPolicy("config/scanner-policy.v2.json"),
    fetchFixedJson(TARGET_MANIFEST_URL).then((value) =>
      requireTargetManifestV2(parseTargetManifest(value)),
    ),
    readJsonFile("operations/state.json").then(parseOperationsState),
  ]);
  const now = new Date().toISOString();
  const next = OperationsStateSchema.parse({
    ...state,
    updated_at: now,
    policy_campaigns: [
      ...state.policy_campaigns,
      {
        id: `policy-${policy.version}-${randomUUID()}`,
        scanner_policy_version: policy.version,
        repository_ids: manifest.repositories.map(
          ({ repository_id }) => repository_id,
        ),
        created_at: now,
        status: "active",
      },
    ],
  });
  await writeFile("operations/state.json", serializeOperationsState(next));
  return {
    status: "scheduled",
    scanner_policy_version: policy.version,
    repositories: manifest.repositories.length,
  };
}

if (isDirectExecution(import.meta.url)) runJsonCli(main);
