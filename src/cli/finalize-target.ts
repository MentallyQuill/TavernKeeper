import { finalizePreparedSession } from "../orchestrator/session.js";
import { isDirectExecution, requiredEnvironment, runJsonCli } from "./io.js";

async function main() {
  const output = process.argv[2] ?? "candidate.json";
  const result = await finalizePreparedSession({
    sessionRoot: requiredEnvironment(process.env, "TAVERNKEEPER_SESSION_ROOT"),
    output,
    completedAt: new Date().toISOString(),
  });
  return { status: result.status };
}

if (isDirectExecution(import.meta.url))
  runJsonCli(main, {
    code: "CLI_FAILED",
    domain: "target",
    component: "finalization",
  });
