import { checkModelProviderCompatibility } from "../model/provider-check.js";
import { createOpenAIWorkloadIdentityProvider } from "../model/openai-workload-identity.js";
import { isDirectExecution, runJsonCli } from "./io.js";

export function checkConfiguredProvider(environment: NodeJS.ProcessEnv) {
  return checkModelProviderCompatibility(
    createOpenAIWorkloadIdentityProvider(environment),
  );
}

if (isDirectExecution(import.meta.url))
  runJsonCli(() => checkConfiguredProvider(process.env));
