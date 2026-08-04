import { publishArtifactBatch } from "../publish/artifact-batch.js";
import { isDirectExecution, runJsonCli } from "./io.js";

async function main() {
  return publishArtifactBatch({
    root: process.cwd(),
    artifactsRoot: process.argv[2] ?? "artifacts",
    generatedAt: new Date().toISOString(),
  });
}

if (isDirectExecution(import.meta.url)) runJsonCli(main);
