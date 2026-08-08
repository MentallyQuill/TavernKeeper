import { FailureDescriptorSchema } from "../operations/failure.js";
import { isDirectExecution, readJsonFile, runJsonCli } from "./io.js";

const SharedRecoveryTargetCodes = new Set([
  "MODEL_CONTEXT_INCOMPLETE",
  "MODEL_EVIDENCE_INVALID",
  "MODEL_INVALID_RESPONSE",
]);

export function probeFailureProvesSharedRecovery(input: unknown) {
  const parsed = FailureDescriptorSchema.safeParse(input);
  return (
    parsed.success &&
    parsed.data.domain === "target" &&
    parsed.data.component === "contextual-model" &&
    SharedRecoveryTargetCodes.has(parsed.data.code)
  );
}

async function main() {
  const path = process.argv[2];
  if (path === undefined) throw new Error("Probe outcome path is required.");
  const failure = await readJsonFile(path);
  if (!probeFailureProvesSharedRecovery(failure))
    throw new Error("Probe outcome does not prove shared provider recovery.");
  return { status: "shared-provider-recovered" };
}

if (isDirectExecution(import.meta.url)) runJsonCli(main);
