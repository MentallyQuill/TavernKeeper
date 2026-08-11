import { readFile, writeFile } from "node:fs/promises";

import {
  createReviewCheckpoint,
  restoreReviewCheckpoint,
} from "../contracts/review-checkpoint.js";
import { decodeTransportKey } from "../publish/encrypted-transport.js";
import {
  isDirectExecution,
  requiredEnvironment,
  runJsonCli,
  writeJsonFile,
} from "./io.js";

function configuredRequest(environment: NodeJS.ProcessEnv) {
  return JSON.parse(
    requiredEnvironment(environment, "TAVERNKEEPER_SCAN_REQUEST"),
  ) as unknown;
}

function configuredReviewIdentity(environment: NodeJS.ProcessEnv) {
  const endpoint = new URL(
    requiredEnvironment(environment, "TAVERNKEEPER_API_ENDPOINT"),
  );
  return {
    contextual_policy_version: "5" as const,
    prompt_version: "contextual-review-v7" as const,
    assessment_schema_version: "contextual-assessment-v2" as const,
    provider: endpoint.hostname,
    endpoint_origin: endpoint.origin,
    model: requiredEnvironment(environment, "TAVERNKEEPER_MODEL"),
  };
}

function configuredKey(environment: NodeJS.ProcessEnv) {
  return decodeTransportKey(
    requiredEnvironment(environment, "TAVERNKEEPER_ARTIFACT_KEY"),
  );
}

export async function runReviewCheckpointCli(
  args: readonly string[],
  environment: NodeJS.ProcessEnv,
) {
  const operation = args[0];
  const request = configuredRequest(environment);
  const reviewIdentity = configuredReviewIdentity(environment);
  const key = configuredKey(environment);
  if (operation === "pack") {
    const sessionRoot = args[1];
    const output = args[2];
    const metadataOutput = args[3];
    if (
      sessionRoot === undefined ||
      output === undefined ||
      metadataOutput === undefined
    )
      throw new Error("Review checkpoint pack paths are required.");
    const createdAt = new Date().toISOString();
    const expiresAt = new Date(
      Date.parse(createdAt) + 90 * 24 * 60 * 60 * 1_000,
    ).toISOString();
    const checkpoint = await createReviewCheckpoint({
      sessionRoot,
      request,
      reviewIdentity,
      key,
      createdAt,
      expiresAt,
    });
    await writeFile(output, checkpoint.encrypted, { flag: "wx" });
    const { encrypted: _encrypted, ...metadata } = checkpoint;
    await writeJsonFile(metadataOutput, metadata);
    return { status: "packed", ...metadata };
  }
  if (operation === "restore") {
    const input = args[1];
    const sessionRoot = args[2];
    if (input === undefined || sessionRoot === undefined)
      throw new Error("Review checkpoint restore paths are required.");
    const restored = await restoreReviewCheckpoint({
      encrypted: await readFile(input),
      sessionRoot,
      expectedRequest: request,
      expectedReviewIdentity: reviewIdentity,
      key,
      now: new Date().toISOString(),
    });
    return { status: "restored", ...restored };
  }
  throw new Error("Review checkpoint operation must be pack or restore.");
}

if (isDirectExecution(import.meta.url))
  runJsonCli(() => runReviewCheckpointCli(process.argv.slice(2), process.env), {
    code: "PREPARED_ARTIFACT_INVALID",
    domain: "security",
    component: "artifact-transport",
  });
