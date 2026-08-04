import { parseOperationsState } from "../operations/state.js";
import { targetIncidentKey } from "../operations/incidents.js";
import { isDirectExecution, readJsonFile, runJsonCli } from "./io.js";

export function exhaustedIncidents(stateInput: unknown) {
  const state = parseOperationsState(stateInput);
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
          failure_history,
        }) => ({
          target_incident_key: targetIncidentKey(repository_id, target_sha),
          repository_id,
          target_sha,
          error_fingerprint,
          failure,
          initial_failed_at,
          last_failed_at,
          failure_history: failure_history ?? [
            {
              failed_at: last_failed_at,
              failure,
              error_fingerprint,
            },
          ],
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

async function main() {
  return exhaustedIncidents(await readJsonFile("operations/state.json"));
}

if (isDirectExecution(import.meta.url)) runJsonCli(main);
