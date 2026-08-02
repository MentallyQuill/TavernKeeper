import { checkModelProviderConnectivity } from "../model/openai-compatible-client.js";
import { isDirectExecution, runJsonCli } from "./io.js";

export function checkConfiguredProvider(environment: NodeJS.ProcessEnv) {
  return checkModelProviderConnectivity({
    endpoint: environment.TAVERNKEEPER_API_ENDPOINT ?? "",
    apiKey: environment.TAVERNKEEPER_API_KEY ?? "",
    model: environment.TAVERNKEEPER_MODEL ?? "",
  });
}

if (isDirectExecution(import.meta.url))
  runJsonCli(() => checkConfiguredProvider(process.env));
