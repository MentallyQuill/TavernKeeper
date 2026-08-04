import { access } from "node:fs/promises";

import {
  isDirectExecution,
  readJsonFile,
  requiredEnvironment,
  runJsonCli,
  writeJsonFile,
} from "./io.js";
import { ScanRequestSchema } from "./staff-request.js";
import { completedScanTransition, failedScanTransition } from "./transition.js";
import { FailureDescriptorSchema } from "../operations/failure.js";

const PhaseErrorSchema = FailureDescriptorSchema;

async function exists(path: string) {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

async function main() {
  const candidatePath = process.argv[2] ?? "candidate.json";
  const output = process.argv[3] ?? "transition.json";
  const errorPath = process.argv[4] ?? "phase-error.json";
  const request = ScanRequestSchema.parse(
    JSON.parse(requiredEnvironment(process.env, "TAVERNKEEPER_SCAN_REQUEST")),
  );
  const target = {
    source_id: request.source_id,
    provider: request.provider,
    repository_id: request.repository_id,
    repository: request.repository,
    target_sha: request.target_sha,
    canonical_url: request.canonical_url,
  };
  const at = new Date().toISOString();
  let transition;
  if (await exists(candidatePath)) {
    transition = completedScanTransition(target, at);
  } else {
    const phaseError = (await exists(errorPath))
      ? PhaseErrorSchema.parse(await readJsonFile(errorPath))
      : {
          code: "SCAN_PHASE_FAILED",
          domain: "security" as const,
          component: "orchestrator" as const,
        };
    transition = failedScanTransition(target, phaseError, at);
  }
  await writeJsonFile(output, transition);
  return { status: transition.status };
}

if (isDirectExecution(import.meta.url)) runJsonCli(main);
