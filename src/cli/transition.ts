import { z } from "zod";

import { TargetSchema } from "../contracts/targets.js";

export const ScanTransitionSchema = z.discriminatedUnion("status", [
  z.strictObject({
    schema_version: z.literal(1),
    status: z.literal("completed"),
    target: TargetSchema,
    at: z.iso.datetime(),
  }),
  z.strictObject({
    schema_version: z.literal(1),
    status: z.literal("obsolete"),
    target: TargetSchema,
    at: z.iso.datetime(),
  }),
  z.strictObject({
    schema_version: z.literal(1),
    status: z.literal("failure"),
    target: TargetSchema,
    code: z.string().regex(/^[A-Z][A-Z0-9_]{0,79}$/u),
    scope: z.enum(["repository", "system"]),
    at: z.iso.datetime(),
  }),
]);

export type ScanTransition = z.infer<typeof ScanTransitionSchema>;
