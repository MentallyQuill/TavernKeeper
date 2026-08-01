import { access } from "node:fs/promises";

import {
  isDirectExecution,
  readJsonFile,
  requiredEnvironment,
  runJsonCli,
  writeJsonFile,
} from "./io.js";
import { ScanRequestSchema } from "./staff-request.js";
import { ScanTransitionSchema } from "./transition.js";
import { z } from "zod";

const PhaseErrorSchema = z.strictObject({
  code: z.string().regex(/^[A-Z][A-Z0-9_]{0,79}$/u),
  scope: z.enum(["repository", "system"]),
});

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
  const reviewPath = process.argv[3] ?? "review.json";
  const output = process.argv[4] ?? "transition.json";
  const errorPath = process.argv[5] ?? "phase-error.json";
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
    transition = { schema_version: 1, status: "completed", target, at };
  } else if (
    (await exists(reviewPath)) &&
    ((await readJsonFile(reviewPath)) as { status?: unknown }).status ===
      "obsolete"
  ) {
    transition = { schema_version: 1, status: "obsolete", target, at };
  } else {
    const phaseError = (await exists(errorPath))
      ? PhaseErrorSchema.parse(await readJsonFile(errorPath))
      : { code: "SCAN_PHASE_FAILED", scope: "system" as const };
    transition = {
      schema_version: 1,
      status: "failure",
      target,
      code: phaseError.code,
      scope: phaseError.scope,
      at,
    };
  }
  const parsed = ScanTransitionSchema.parse(transition);
  await writeJsonFile(output, parsed);
  return { status: parsed.status };
}

if (isDirectExecution(import.meta.url)) runJsonCli(main);
