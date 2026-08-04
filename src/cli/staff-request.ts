import { z } from "zod";

import { TargetV2Schema, TargetV3Schema } from "../contracts/targets.js";

export const StaffScanRequestSchema = z.strictObject({
  repository_id: z.number().int().positive(),
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

const ScanRequestFields = {
  reason: z.enum(["new", "changed", "retry", "policy", "staff"]),
  report_version: z.number().int().positive(),
  supersedes_report_id: z
    .string()
    .regex(/^[0-9a-f]{64}$/u)
    .nullable(),
  previous_report_shas: z.array(z.string().regex(/^[0-9a-f]{40}$/u)).max(20),
};

export const ScanRequestSchema = z.union([
  TargetV2Schema.extend(ScanRequestFields),
  TargetV3Schema.extend(ScanRequestFields),
]);

export type ScanRequest = z.infer<typeof ScanRequestSchema>;
