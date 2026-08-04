import { parseOperationsState } from "../operations/state.js";
import { isDirectExecution, readJsonFile, runJsonCli } from "./io.js";

async function main() {
  const state = parseOperationsState(
    await readJsonFile("operations/state.json"),
  );
  return {
    chronic_failures: state.scan_queue.entries
      .filter(({ chronic }) => chronic)
      .map(
        ({
          repository_id,
          repository,
          target_sha,
          ticket,
          consecutive_failures,
          total_failures,
          not_before,
          last_failure,
          last_failed_at,
        }) => ({
          repository_id,
          repository,
          target_sha,
          ticket,
          consecutive_failures,
          total_failures,
          not_before,
          last_failure,
          last_failed_at,
        }),
      ),
  };
}

if (isDirectExecution(import.meta.url)) runJsonCli(main);
