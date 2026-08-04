import { resolve } from "node:path";

import { isDirectExecution, runJsonCli } from "./io.js";
import { synchronizeQueueFile } from "./sync-queue.js";

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
