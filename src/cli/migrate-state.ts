import { resolve } from "node:path";

import {
  isDirectExecution,
  readJsonFile,
  runJsonCli,
  writeJsonFile,
} from "./io.js";
import { migrateOperationsState } from "../operations/migrate-state.js";
import { parseOperationsState } from "../operations/state.js";

async function main() {
  const check = process.argv.includes("--check");
  const pathArgument = process.argv
    .slice(2)
    .find((argument) => argument !== "--check");
  const path = resolve(pathArgument ?? "operations/state.json");
  const value = await readJsonFile(path);

  if (
    value !== null &&
    typeof value === "object" &&
    "schema_version" in value &&
    value.schema_version === 2
  ) {
    if (!check)
      throw new Error("Operations state is already schema version 2.");
    parseOperationsState(value);
    return { target: 0, shared: 0, security: 0 };
  }

  const migrated = migrateOperationsState(value, new Date().toISOString());
  if (!check) await writeJsonFile(path, migrated.state);
  return migrated.summary;
}

if (isDirectExecution(import.meta.url)) runJsonCli(main);
