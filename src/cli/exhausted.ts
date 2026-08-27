import { parseOperationsState } from "../operations/state.js";
import { targetIncidentKey } from "../operations/incidents.js";
import { failureFingerprint } from "../operations/failure.js";
import { isDirectExecution, readJsonFile, runJsonCli } from "./io.js";

export function operationalIncidents(stateInput: unknown) {
  const state = parseOperationsState(stateInput);
  return {
    automatic_holds: state.automatic_holds,
    chronic_failures: state.scan_queue.entries
      .filter(
        (entry) =>
          entry.chronic &&
          entry.last_failure !== null &&
          entry.last_failed_at !== null,
      )
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
          failure_history,
        }) => ({
          target_incident_key: targetIncidentKey(repository_id, target_sha),
          repository_id,
          repository,
          target_sha,
          ticket,
          consecutive_failures,
          total_failures,
          not_before,
          last_failure,
          last_failed_at,
          failure_history: failure_history ?? [
            {
              failed_at: last_failed_at!,
              failure: last_failure!,
              error_fingerprint: failureFingerprint(last_failure!),
            },
          ],
        }),
      ),
    unscannable_targets: state.unscannable_targets.map((entry) => ({
      target_incident_key: targetIncidentKey(
        entry.repository_id,
        entry.target_sha,
      ),
      ...entry,
    })),
  };
}

async function main() {
  return operationalIncidents(await readJsonFile("operations/state.json"));
}

if (isDirectExecution(import.meta.url)) runJsonCli(main);
