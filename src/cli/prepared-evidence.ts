import { rm } from "node:fs/promises";
import { basename, resolve } from "node:path";

import {
  createFailedPreparedEvidenceArtifact,
  createPreparedEvidenceArtifact,
  restorePreparedEvidenceArtifact,
} from "../contracts/prepared-evidence.js";
import {
  isDirectExecution,
  readJsonFile,
  requiredEnvironment,
  runJsonCli,
} from "./io.js";

function configuredRequest() {
  return JSON.parse(
    requiredEnvironment(process.env, "TAVERNKEEPER_SCAN_REQUEST"),
  ) as unknown;
}

async function replacePreparedArtifactRoot(path: string) {
  const root = resolve(path);
  if (!basename(root).startsWith("tavernkeeper-prepared-"))
    throw new Error("Prepared artifact directory name is unsafe.");
  await rm(root, { recursive: true, force: true });
}

async function main() {
  const operation = process.argv[2];
  if (operation === "pack") {
    const sessionRoot = process.argv[3];
    const artifactRoot = process.argv[4];
    if (sessionRoot === undefined || artifactRoot === undefined)
      throw new Error("Prepared evidence pack paths are required.");
    await replacePreparedArtifactRoot(artifactRoot);
    const manifest = await createPreparedEvidenceArtifact({
      request: configuredRequest(),
      sessionRoot,
      artifactRoot,
    });
    return {
      status: manifest.status,
      session_id: manifest.session_id,
      evidence_digest: manifest.evidence_digest,
    };
  }
  if (operation === "fail") {
    const failurePath = process.argv[3];
    const artifactRoot = process.argv[4];
    if (failurePath === undefined || artifactRoot === undefined)
      throw new Error("Prepared evidence failure paths are required.");
    await replacePreparedArtifactRoot(artifactRoot);
    const manifest = await createFailedPreparedEvidenceArtifact({
      request: configuredRequest(),
      failure: await readJsonFile(failurePath),
      artifactRoot,
    });
    return { status: manifest.status };
  }
  if (operation === "restore") {
    const artifactRoot = process.argv[3];
    const sessionRoot = process.argv[4];
    const failureOutput = process.argv[5];
    if (
      artifactRoot === undefined ||
      sessionRoot === undefined ||
      failureOutput === undefined
    )
      throw new Error("Prepared evidence restore paths are required.");
    return restorePreparedEvidenceArtifact({
      artifactRoot,
      sessionRoot,
      expectedRequest: configuredRequest(),
      failureOutput,
    });
  }
  throw new Error(
    "Prepared evidence operation must be pack, fail, or restore.",
  );
}

if (isDirectExecution(import.meta.url))
  runJsonCli(main, {
    code: "PREPARED_ARTIFACT_INVALID",
    domain: "security",
    component: "artifact-transport",
  });
