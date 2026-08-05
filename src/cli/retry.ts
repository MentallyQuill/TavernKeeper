import { writeFile } from "node:fs/promises";

import { z } from "zod";

import {
  parseOperationsState,
  pauseSystem,
  releaseAutomaticHolds,
  resumeSystem,
  serializeOperationsState,
} from "../operations/state.js";
import { dueRetries } from "../operations/retry.js";
import { prioritizeQueuedTargetRetry } from "../queue/durable-queue.js";
import {
  isDirectExecution,
  readJsonFile,
  requiredEnvironment,
  runJsonCli,
} from "./io.js";

const OperationSchema = z.discriminatedUnion("operation", [
  z.strictObject({ operation: z.literal("due") }),
  z.strictObject({
    operation: z.literal("pause"),
    reason_code: z.string().regex(/^[A-Z][A-Z0-9_]{0,79}$/u),
  }),
  z.strictObject({ operation: z.literal("resume") }),
  z.strictObject({ operation: z.literal("release-holds") }),
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
        : operation.operation === "release-holds"
          ? releaseAutomaticHolds(state, now)
          : parseOperationsState({
              ...prioritizeQueuedTargetRetry(state, operation.repository_id),
              updated_at: now,
            });
  await writeFile(path, serializeOperationsState(next));
  return { status: operation.operation };
}

if (isDirectExecution(import.meta.url)) runJsonCli(main);
