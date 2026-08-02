import { z } from "zod";

import { TargetV2Schema } from "../contracts/targets.js";

export const StaffScanRequestSchema = z.strictObject({
  repository_id: z.number().int().positive(),
  mode: z.literal("deep"),
});

export const TargetedScanHintSchema = z.strictObject({
  repository_id: z.number().int().positive(),
});

export function validateStaffScanRequest(input: unknown) {
  return StaffScanRequestSchema.parse(input);
}

export function validateTargetedScanHint(input: unknown) {
  return TargetedScanHintSchema.parse(input);
}

export const ScanRequestSchema = TargetV2Schema.extend({
  reason: z.enum(["new", "changed", "retry", "policy", "staff"]),
  mode: z.enum(["standard", "deep"]),
  report_version: z.number().int().positive(),
  supersedes_report_id: z
    .string()
    .regex(/^[0-9a-f]{64}$/u)
    .nullable(),
  previous_report_shas: z.array(z.string().regex(/^[0-9a-f]{40}$/u)).max(20),
});

export type ScanRequest = z.infer<typeof ScanRequestSchema>;
