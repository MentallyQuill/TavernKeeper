import { parseOperationsState } from "../operations/state.js";
import { isDirectExecution, readJsonFile, runJsonCli } from "./io.js";

async function main() {
  const state = parseOperationsState(
    await readJsonFile("operations/state.json"),
  );
  return {
    target_exhaustions: state.target_retries
      .filter(
        ({ exhausted, failure }) => exhausted && failure.domain === "target",
      )
      .map(
        ({
          repository_id,
          target_sha,
          error_fingerprint,
          failure,
          initial_failed_at,
          last_failed_at,
        }) => ({
          repository_id,
          target_sha,
          error_fingerprint,
          failure,
          initial_failed_at,
          last_failed_at,
        }),
      ),
    shared_holds: state.shared_holds,
    security_holds: state.target_retries
      .filter(({ failure }) => failure.domain === "security")
      .map(({ repository_id, target_sha, error_fingerprint, failure }) => ({
        repository_id,
        target_sha,
        error_fingerprint,
        failure,
      })),
  };
}

if (isDirectExecution(import.meta.url)) runJsonCli(main);
