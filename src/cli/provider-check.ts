import { checkModelProviderCompatibility } from "../model/provider-check.js";
import { isDirectExecution, runJsonCli } from "./io.js";

export function checkConfiguredProvider(environment: NodeJS.ProcessEnv) {
  return checkModelProviderCompatibility({
    endpoint: environment.TAVERNKEEPER_API_ENDPOINT ?? "",
    apiKey: environment.TAVERNKEEPER_API_KEY ?? "",
    model: environment.TAVERNKEEPER_MODEL ?? "",
  });
}

if (isDirectExecution(import.meta.url))
  runJsonCli(() => checkConfiguredProvider(process.env));
