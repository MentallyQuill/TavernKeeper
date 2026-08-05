import { join } from "node:path";

import { verifyExactHead } from "../git/checkout.js";
import { finalizePreparedSession } from "../orchestrator/session.js";
import { ProcessCommandRunner } from "../process/command-runner.js";
import { isDirectExecution, requiredEnvironment, runJsonCli } from "./io.js";

async function main() {
  const output = process.argv[2] ?? "candidate.json";
  const checkoutRoot = requiredEnvironment(
    process.env,
    "TAVERNKEEPER_CHECKOUT_ROOT",
  );
  const runner = new ProcessCommandRunner();
  const result = await finalizePreparedSession({
    sessionRoot: requiredEnvironment(process.env, "TAVERNKEEPER_SESSION_ROOT"),
    output,
    completedAt: new Date().toISOString(),
    verifyHead: (expectedSha) =>
      verifyExactHead(join(checkoutRoot), expectedSha, runner),
  });
  return { status: result.status };
}

if (isDirectExecution(import.meta.url))
  runJsonCli(main, {
    code: "CLI_FAILED",
    domain: "target",
    component: "finalization",
  });
