import { z } from "zod";

export const FullShaSchema = z.string().regex(/^[0-9a-f]{40}$/u);

export const TargetSchema = z.strictObject({
  source_id: z.string().regex(/^github-[1-9][0-9]*$/u),
  provider: z.literal("github"),
  repository_id: z.number().int().positive(),
  repository: z.string().regex(/^[^/\s]+\/[^/\s]+$/u),
  target_sha: FullShaSchema,
  canonical_url: z.url().startsWith("https://github.com/"),
});

export const TargetManifestSchema = z.strictObject({
  schema_version: z.literal(1),
  generated_at: z.iso.datetime(),
  repositories: z.array(TargetSchema),
});

export type Target = z.infer<typeof TargetSchema>;
export type TargetManifest = z.infer<typeof TargetManifestSchema>;
