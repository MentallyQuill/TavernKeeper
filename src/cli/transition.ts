import { z } from "zod";

import { TargetSchema } from "../contracts/targets.js";
import type { Target } from "../contracts/targets.js";
import {
  FailureDescriptorSchema,
  type FailureDescriptor,
} from "../operations/failure.js";

export const ScanTransitionSchema = z.discriminatedUnion("status", [
  z.strictObject({
    schema_version: z.literal(2),
    status: z.literal("completed"),
    target: TargetSchema,
    at: z.iso.datetime(),
  }),
  z.strictObject({
    schema_version: z.literal(2),
    status: z.literal("failure"),
    target: TargetSchema,
    failure: FailureDescriptorSchema,
    at: z.iso.datetime(),
  }),
]);

export type ScanTransition = z.infer<typeof ScanTransitionSchema>;

export function completedScanTransition(target: Target, at: string) {
  return ScanTransitionSchema.parse({
    schema_version: 2,
    status: "completed",
    target,
    at,
  });
}

export function failedScanTransition(
  target: Target,
  failure: FailureDescriptor,
  at: string,
) {
  return ScanTransitionSchema.parse({
    schema_version: 2,
    status: "failure",
    target,
    failure,
    at,
  });
}
