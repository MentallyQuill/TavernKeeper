import { z } from "zod";

import {
  parseOperationsState,
  pauseSystem,
  resumeSystem,
  serializeOperationsState,
} from "../operations/state.js";
import { dueRetries } from "../operations/retry.js";
import {
  isDirectExecution,
  readJsonFile,
  requiredEnvironment,
  runJsonCli,
} from "./io.js";
import { writeFile } from "node:fs/promises";

const OperationSchema = z.discriminatedUnion("operation", [
  z.strictObject({ operation: z.literal("due") }),
  z.strictObject({
    operation: z.literal("pause"),
    reason_code: z.string().regex(/^[A-Z][A-Z0-9_]{0,79}$/u),
  }),
  z.strictObject({ operation: z.literal("resume") }),
  z.strictObject({
    operation: z.literal("retry"),
    repository_id: z.number().int().positive(),
  }),
]);

async function main() {
  const path = "operations/state.json";
  const state = parseOperationsState(await readJsonFile(path));
  const operation = OperationSchema.parse(
    JSON.parse(requiredEnvironment(process.env, "TAVERNKEEPER_OPERATION")),
  );
  const now = new Date().toISOString();
  if (operation.operation === "due")
    return { status: "due", retries: dueRetries(state, now) };
  const next =
    operation.operation === "pause"
      ? pauseSystem(state, {
          kind: "staff",
          reasonCode: operation.reason_code,
          at: now,
        })
      : operation.operation === "resume"
        ? resumeSystem(state, now)
        : parseOperationsState({
            ...state,
            updated_at: now,
            circuit_breaker: null,
            retries: state.retries.filter(
              ({ repository_id }) => repository_id !== operation.repository_id,
            ),
          });
  await writeFile(path, serializeOperationsState(next));
  return { status: operation.operation };
}

if (isDirectExecution(import.meta.url)) runJsonCli(main);
