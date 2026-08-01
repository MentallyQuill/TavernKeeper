import { z } from "zod";

export const FullShaSchema = z.string().regex(/^[0-9a-f]{40}$/u);

const TargetIdentitySchema = z
  .strictObject({
    source_id: z.string().regex(/^github-[1-9][0-9]*$/u),
    provider: z.literal("github"),
    repository_id: z.number().int().positive(),
    repository: z.string().regex(/^[^/\s]+\/[^/\s]+$/u),
    target_sha: FullShaSchema,
    canonical_url: z.url().startsWith("https://github.com/"),
  })
  .refine(
    (target) =>
      target.canonical_url === `https://github.com/${target.repository}`,
    {
      path: ["canonical_url"],
      message: "Canonical URL must match repository.",
    },
  )
  .refine((target) => target.source_id === `github-${target.repository_id}`, {
    path: ["source_id"],
    message: "Source ID must match repository ID.",
  });

export const TargetSchema = TargetIdentitySchema;

export const TargetManifestSchema = z
  .strictObject({
    schema_version: z.literal(1),
    generated_at: z.iso.datetime(),
    repositories: z.array(TargetSchema),
  })
  .refine(
    (manifest) =>
      manifest.repositories.every(
        (target, index) =>
          index === 0 ||
          manifest.repositories[index - 1]!.repository_id <
            target.repository_id,
      ),
    {
      path: ["repositories"],
      message: "Repository IDs must be unique and strictly increasing.",
    },
  );

const ProjectKindSchema = z.enum(["extension", "frontend", "preset"]);

export const TargetV2Schema = TargetIdentitySchema.extend({
  project_kinds: z
    .array(ProjectKindSchema)
    .min(1)
    .refine(
      (kinds) =>
        kinds.every((kind, index) => index === 0 || kinds[index - 1]! < kind),
      "Project kinds must be unique and sorted.",
    ),
  catalog_priority: z.strictObject({
    top_30: z.boolean(),
    first_cataloged_at: z.iso.datetime(),
  }),
});

export const TargetManifestV2Schema = z
  .strictObject({
    schema_version: z.literal(2),
    generated_at: z.iso.datetime(),
    repositories: z.array(TargetV2Schema),
  })
  .refine(
    (manifest) =>
      manifest.repositories.every(
        (target, index) =>
          index === 0 ||
          manifest.repositories[index - 1]!.repository_id <
            target.repository_id,
      ),
    {
      path: ["repositories"],
      message: "Repository IDs must be unique and strictly increasing.",
    },
  );

export const TargetManifestV1Schema = TargetManifestSchema;

const TargetManifestInputSchema = z.union([
  TargetManifestV1Schema,
  TargetManifestV2Schema,
]);

export function parseTargetManifest(input: unknown) {
  return TargetManifestInputSchema.parse(input);
}

export function requireTargetManifestV2(
  manifest: z.infer<typeof TargetManifestInputSchema>,
) {
  if (manifest.schema_version !== 2) {
    throw new Error("TavernKeeper target manifest version 2 is not published.");
  }
  return manifest;
}

export type Target = z.infer<typeof TargetSchema>;
export type TargetManifest = z.infer<typeof TargetManifestSchema>;
export type TargetManifestV1 = z.infer<typeof TargetManifestV1Schema>;
export type TargetV2 = z.infer<typeof TargetV2Schema>;
export type TargetManifestV2 = z.infer<typeof TargetManifestV2Schema>;
