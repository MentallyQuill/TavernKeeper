import { join } from "node:path";

import { loadScannerPolicy } from "../config/policy.js";
import { TargetManifestSchema } from "../contracts/targets.js";
import { verifyExactHead } from "../git/checkout.js";
import { FileModelChunkCache } from "../model/chunk-cache.js";
import { reviewPreparedSession } from "../orchestrator/session.js";
import { ProcessCommandRunner } from "../process/command-runner.js";
import {
  fetchFixedJson,
  isDirectExecution,
  requiredEnvironment,
  runJsonCli,
  writeJsonFile,
} from "./io.js";
import { TARGET_MANIFEST_URL } from "./reconcile.js";

async function main() {
  const repositoryRoot = process.cwd();
  const sessionRoot = requiredEnvironment(
    process.env,
    "TAVERNKEEPER_SESSION_ROOT",
  );
  const checkoutRoot = requiredEnvironment(
    process.env,
    "TAVERNKEEPER_CHECKOUT_ROOT",
  );
  const output = process.argv[2] ?? "review.json";
  const policy = await loadScannerPolicy(
    join(repositoryRoot, "config", "scanner-policy.v1.json"),
  );
  const manifest = TargetManifestSchema.parse(
    await fetchFixedJson(TARGET_MANIFEST_URL),
  );
  const runner = new ProcessCommandRunner();
  const prepared = JSON.parse(
    await (
      await import("node:fs/promises")
    ).readFile(join(sessionRoot, "prepared.json"), "utf8"),
  ) as { target: { target_sha: string } };
  const review = await reviewPreparedSession({
    sessionRoot,
    manifest,
    endpoint: requiredEnvironment(process.env, "TAVERNKEEPER_API_ENDPOINT"),
    apiKey: requiredEnvironment(process.env, "TAVERNKEEPER_API_KEY"),
    model: requiredEnvironment(process.env, "TAVERNKEEPER_MODEL"),
    policy,
    cache: new FileModelChunkCache(
      requiredEnvironment(process.env, "TAVERNKEEPER_MODEL_CACHE"),
    ),
    verifyHead: () =>
      verifyExactHead(checkoutRoot, prepared.target.target_sha, runner),
  });
  await writeJsonFile(output, review);
  return { status: review.status, session_id: review.session_id };
}

if (isDirectExecution(import.meta.url)) runJsonCli(main);
