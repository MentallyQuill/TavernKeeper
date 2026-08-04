import { resolve } from "node:path";

import {
  fetchFixedJson,
  isDirectExecution,
  readJsonFile,
  runJsonCli,
  writeJsonFile,
} from "./io.js";
import { parseReportIndexV5 } from "../contracts/reports-v5.js";
import {
  parseTargetManifest,
  requireTargetManifestV2,
} from "../contracts/targets.js";
import { syncScanQueue } from "../queue/sync.js";
import { TARGET_MANIFEST_URL } from "./reconcile.js";

export function buildQueueSynchronization(input: {
  manifest: unknown;
  index: unknown;
  state: unknown;
  now: string;
  scannerPolicyVersion: string;
}) {
  const manifest = requireTargetManifestV2(parseTargetManifest(input.manifest));
  const index = parseReportIndexV5(input.index);
  return syncScanQueue({ ...input, manifest, index });
}

export async function synchronizeQueueFile(input: {
  statePath: string;
  check: boolean;
  now: string;
}) {
  const [manifest, index, state] = await Promise.all([
    fetchFixedJson(TARGET_MANIFEST_URL),
    readJsonFile(resolve("reports/index.json")),
    readJsonFile(input.statePath),
  ]);
  const synchronized = buildQueueSynchronization({
    manifest,
    index,
    state,
    now: input.now,
    scannerPolicyVersion: "3",
  });
  if (input.check && synchronized.changed)
    throw new Error("Committed scan queue is not synchronized.");
  if (!input.check && synchronized.changed)
    await writeJsonFile(input.statePath, synchronized.state);
  return {
    changed: synchronized.changed,
    queue_entries: synchronized.state.scan_queue.entries.length,
    next_ticket: synchronized.state.scan_queue.next_ticket,
    ...synchronized.summary,
  };
}

async function main() {
  const check = process.argv.includes("--check");
  const pathArgument = process.argv
    .slice(2)
    .find((argument) => argument !== "--check");
  return synchronizeQueueFile({
    statePath: resolve(pathArgument ?? "operations/state.json"),
    check,
    now: new Date().toISOString(),
  });
}

if (isDirectExecution(import.meta.url)) runJsonCli(main);
