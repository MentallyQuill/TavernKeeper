import { finalizePreparedSession } from "../orchestrator/session.js";
import {
  isDirectExecution,
  readJsonFile,
  requiredEnvironment,
  runJsonCli,
} from "./io.js";

async function main() {
  const reviewPath = process.argv[2] ?? "review.json";
  const output = process.argv[3] ?? "candidate.json";
  const result = await finalizePreparedSession({
    sessionRoot: requiredEnvironment(process.env, "TAVERNKEEPER_SESSION_ROOT"),
    review: await readJsonFile(reviewPath),
    output,
    completedAt: new Date().toISOString(),
  });
  return { status: result.status };
}

if (isDirectExecution(import.meta.url)) runJsonCli(main);
