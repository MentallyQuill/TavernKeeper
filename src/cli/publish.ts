import { publishArtifactBatch } from "../publish/artifact-batch.js";
import { ScanRequestSchema } from "./staff-request.js";
import { isDirectExecution, requiredEnvironment, runJsonCli } from "./io.js";

async function main() {
  return publishArtifactBatch({
    root: process.cwd(),
    artifactsRoot: process.argv[2] ?? "artifacts",
    generatedAt: new Date().toISOString(),
    expectedTargets: [
      ScanRequestSchema.parse(
        JSON.parse(
          requiredEnvironment(process.env, "TAVERNKEEPER_SCAN_REQUEST"),
        ),
      ),
    ],
  });
}

if (isDirectExecution(import.meta.url))
  runJsonCli(main, {
    code: "CLI_FAILED",
    domain: "shared",
    component: "publication",
  });
