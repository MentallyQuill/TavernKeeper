import { join } from "node:path";

import { loadContextualReviewPolicy } from "../config/policy.js";
import { expandEvidenceContextGroup } from "../context/evidence-context.js";
import { createOpenAIWorkloadIdentityProvider } from "../model/openai-workload-identity.js";
import { reviewPreparedSession } from "../orchestrator/session.js";
import { isDirectExecution, requiredEnvironment, runJsonCli } from "./io.js";

const defaultDependencies = {
  createProvider: createOpenAIWorkloadIdentityProvider,
  loadPolicy: loadContextualReviewPolicy,
  review: reviewPreparedSession,
};

export async function reviewConfiguredTarget(
  environment: NodeJS.ProcessEnv,
  dependencies: typeof defaultDependencies = defaultDependencies,
) {
  const repositoryRoot = process.cwd();
  const result = await dependencies.review({
    sessionRoot: requiredEnvironment(environment, "TAVERNKEEPER_SESSION_ROOT"),
    provider: dependencies.createProvider(environment),
    policy: await dependencies.loadPolicy(
      join(repositoryRoot, "config", "contextual-review.v2.json"),
    ),
    expandContext: async (group, _request, attempt) =>
      expandEvidenceContextGroup(group, attempt),
  });
  return { status: result.status };
}

if (isDirectExecution(import.meta.url))
  runJsonCli(() => reviewConfiguredTarget(process.env), {
    code: "CLI_FAILED",
    domain: "target",
    component: "contextual-model",
  });
