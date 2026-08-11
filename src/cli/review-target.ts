import { join } from "node:path";

import { loadContextualReviewPolicy } from "../config/policy.js";
import { expandEvidenceContextGroup } from "../context/evidence-context.js";
import { reviewPreparedSession } from "../orchestrator/session.js";
import { isDirectExecution, requiredEnvironment, runJsonCli } from "./io.js";

const defaultDependencies = {
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
    repositoryRoot,
    provider: {
      endpoint: requiredEnvironment(environment, "TAVERNKEEPER_API_ENDPOINT"),
      apiKey: requiredEnvironment(environment, "TAVERNKEEPER_API_KEY"),
      model: requiredEnvironment(environment, "TAVERNKEEPER_MODEL"),
    },
    jsonRepairProvider: {
      endpoint: requiredEnvironment(environment, "JSONREPAIR_API_ENDPOINT"),
      apiKey: requiredEnvironment(environment, "JSONREPAIR_API_KEY"),
      model: requiredEnvironment(environment, "JSONREPAIR_MODEL"),
    },
    policy: await dependencies.loadPolicy(
      join(repositoryRoot, "config", "contextual-review.v5.json"),
    ),
    expandContext: async (group, _request, attempt) =>
      expandEvidenceContextGroup(group, attempt),
  });
  if (result.status === "review_pending")
    return {
      status: result.status,
      pending_groups: result.pending_groups,
      completed_groups: result.progress.completed_group_ids.length,
      json_repairs: result.progress.completion_ids.filter((completionId) =>
        completionId.startsWith("jsonrepair:"),
      ).length,
    };
  return {
    status: result.status,
    json_repairs: result.review.completion_ids.filter((completionId) =>
      completionId.startsWith("jsonrepair:"),
    ).length,
  };
}

if (isDirectExecution(import.meta.url))
  runJsonCli(() => reviewConfiguredTarget(process.env), {
    code: "CLI_FAILED",
    domain: "target",
    component: "contextual-model",
  });
