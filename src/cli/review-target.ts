import { join } from "node:path";

import { loadContextualReviewPolicy } from "../config/policy.js";
import {
  expandEvidenceContextGroup,
  loadEvidenceSourceFromCheckout,
} from "../context/evidence-context.js";
import { reviewPreparedSession } from "../orchestrator/session.js";
import { ProcessCommandRunner } from "../process/command-runner.js";
import { isDirectExecution, requiredEnvironment, runJsonCli } from "./io.js";

export async function reviewConfiguredTarget(environment: NodeJS.ProcessEnv) {
  const repositoryRoot = process.cwd();
  const checkoutRoot = requiredEnvironment(
    environment,
    "TAVERNKEEPER_CHECKOUT_ROOT",
  );
  const runner = new ProcessCommandRunner();
  const result = await reviewPreparedSession({
    sessionRoot: requiredEnvironment(environment, "TAVERNKEEPER_SESSION_ROOT"),
    provider: {
      endpoint: requiredEnvironment(environment, "TAVERNKEEPER_API_ENDPOINT"),
      apiKey: requiredEnvironment(environment, "TAVERNKEEPER_API_KEY"),
      model: requiredEnvironment(environment, "TAVERNKEEPER_MODEL"),
    },
    policy: await loadContextualReviewPolicy(
      join(repositoryRoot, "config", "contextual-review.v1.json"),
    ),
    expandContext: async (group, _request, attempt) =>
      expandEvidenceContextGroup(
        group,
        await loadEvidenceSourceFromCheckout({
          checkoutRoot,
          group,
          runner,
        }),
        attempt,
      ),
  });
  return { status: result.status };
}

if (isDirectExecution(import.meta.url))
  runJsonCli(() => reviewConfiguredTarget(process.env));
