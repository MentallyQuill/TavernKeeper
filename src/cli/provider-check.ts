import { checkModelProviderCompatibility } from "../model/provider-check.js";
import { isDirectExecution, requiredEnvironment, runJsonCli } from "./io.js";

export function checkConfiguredProvider(environment: NodeJS.ProcessEnv) {
  return checkModelProviderCompatibility({
    endpoint: requiredEnvironment(environment, "TAVERNKEEPER_API_ENDPOINT"),
    apiKey: requiredEnvironment(environment, "TAVERNKEEPER_API_KEY"),
    model: requiredEnvironment(environment, "TAVERNKEEPER_MODEL"),
  });
}

if (isDirectExecution(import.meta.url))
  runJsonCli(() => checkConfiguredProvider(process.env));
