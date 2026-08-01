import { parseOperationsState } from "../operations/state.js";
import { isDirectExecution, readJsonFile, runJsonCli } from "./io.js";

async function main() {
  const state = parseOperationsState(
    await readJsonFile("operations/state.json"),
  );
  return state.retries
    .filter(({ exhausted }) => exhausted)
    .map(
      ({
        repository_id,
        target_sha,
        error_fingerprint,
        error_code,
        scope,
        initial_failed_at,
        last_failed_at,
      }) => ({
        repository_id,
        target_sha,
        error_fingerprint,
        error_code,
        scope,
        initial_failed_at,
        last_failed_at,
      }),
    );
}

if (isDirectExecution(import.meta.url)) runJsonCli(main);
