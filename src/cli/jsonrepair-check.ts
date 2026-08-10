import { checkJsonRepairProvider } from "../model/json-repair.js";
import { isDirectExecution, requiredEnvironment, runJsonCli } from "./io.js";

const defaultDependencies = { check: checkJsonRepairProvider };

export async function checkConfiguredJsonRepair(
  environment: NodeJS.ProcessEnv,
  dependencies: typeof defaultDependencies = defaultDependencies,
) {
  return dependencies.check({
    endpoint: requiredEnvironment(environment, "JSONREPAIR_API_ENDPOINT"),
    apiKey: requiredEnvironment(environment, "JSONREPAIR_API_KEY"),
    model: requiredEnvironment(environment, "JSONREPAIR_MODEL"),
  });
}

if (isDirectExecution(import.meta.url))
  runJsonCli(() => checkConfiguredJsonRepair(process.env), {
    code: "MODEL_PROVIDER",
    domain: "shared",
    component: "contextual-model",
  });
