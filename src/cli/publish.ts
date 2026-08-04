import { z } from "zod";

import { publishArtifactBatch } from "../publish/artifact-batch.js";
import { ScanRequestSchema } from "./staff-request.js";
import { isDirectExecution, requiredEnvironment, runJsonCli } from "./io.js";

const ScanRequestBatchSchema = z.array(ScanRequestSchema).min(1).max(5);

async function main() {
  return publishArtifactBatch({
    root: process.cwd(),
    artifactsRoot: process.argv[2] ?? "artifacts",
    generatedAt: new Date().toISOString(),
    expectedTargets: ScanRequestBatchSchema.parse(
      JSON.parse(
        requiredEnvironment(process.env, "TAVERNKEEPER_SCAN_REQUESTS"),
      ),
    ),
  });
}

if (isDirectExecution(import.meta.url)) runJsonCli(main);
