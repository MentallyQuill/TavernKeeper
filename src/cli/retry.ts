import { writeFile } from "node:fs/promises";

import { z } from "zod";

import {
  parseOperationsState,
  pauseSystem,
  releaseAutomaticHolds,
  resumeSystem,
  serializeOperationsState,
} from "../operations/state.js";
import {
  dueRetries,
  recordAutomaticProbeFailure,
  recordAutomaticProbeSuccess,
} from "../operations/retry.js";
import {
  addBackUnscannableTarget,
  prioritizeQueuedTargetRetry,
  revokeQueuedTargetStaffRequest,
} from "../queue/durable-queue.js";
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
    operation: z.literal("provider-probe-success"),
    error_fingerprint: z.string().regex(/^[a-f0-9]{64}$/u),
    probed_at: z.iso.datetime(),
  }),
  z.strictObject({
    operation: z.literal("provider-probe-failure"),
    error_fingerprint: z.string().regex(/^[a-f0-9]{64}$/u),
    probed_at: z.iso.datetime(),
  }),
  z.strictObject({
    operation: z.literal("retry"),
    repository_id: z.number().int().positive(),
  }),
  z.strictObject({
    operation: z.literal("revoke"),
    repository_id: z.number().int().positive(),
  }),
  z.strictObject({
    operation: z.literal("add-back"),
    repository_id: z.number().int().positive(),
  }),
]);

export function applyRetryOperation(
  stateInput: unknown,
  operationInput: unknown,
  now: string,
) {
  const state = parseOperationsState(stateInput);
  const operation = OperationSchema.parse(operationInput);
  if (operation.operation === "due")
    throw new Error("Due retry inspection does not mutate state.");
  if (
    operation.operation === "provider-probe-success" ||
    operation.operation === "provider-probe-failure"
  ) {
    const holdExists = state.automatic_holds.some(
      ({ error_fingerprint }) =>
        error_fingerprint === operation.error_fingerprint,
    );
    if (!holdExists) return state;
    return operation.operation === "provider-probe-success"
      ? recordAutomaticProbeSuccess(
          state,
          operation.error_fingerprint,
          operation.probed_at,
        )
      : recordAutomaticProbeFailure(
          state,
          operation.error_fingerprint,
          operation.probed_at,
        );
  }
  if (operation.operation === "add-back")
    return parseOperationsState({
      ...addBackUnscannableTarget(state, operation.repository_id),
      updated_at: now,
    });
  if (operation.operation === "revoke") {
    const hasStaffRequest = state.scan_queue.entries.some(
      (entry) =>
        entry.repository_id === operation.repository_id &&
        entry.staff_requested === true,
    );
    const revoked = revokeQueuedTargetStaffRequest(
      state,
      operation.repository_id,
    );
    return hasStaffRequest
      ? parseOperationsState({ ...revoked, updated_at: now })
      : state;
  }
  return operation.operation === "pause"
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
}

async function main() {
  const path = "operations/state.json";
  const state = parseOperationsState(await readJsonFile(path));
  const operationInput = JSON.parse(
    requiredEnvironment(process.env, "TAVERNKEEPER_OPERATION"),
  );
  const operation = OperationSchema.parse(operationInput);
  const now = new Date().toISOString();
  if (operation.operation === "due")
    return { status: "due", retries: dueRetries(state, now) };
  const next = applyRetryOperation(state, operationInput, now);
  await writeFile(path, serializeOperationsState(next));
  return { status: operation.operation };
}

if (isDirectExecution(import.meta.url)) runJsonCli(main);
