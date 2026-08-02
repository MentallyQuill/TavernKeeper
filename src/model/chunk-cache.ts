import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { z } from "zod";

import type { ModelUsage } from "./openai-compatible-client.js";
import { RepositorySynthesisSchema } from "./review-contracts.js";

const DigestSchema = z.string().regex(/^[a-f0-9]{64}$/u);
const UsageSchema = z.strictObject({
  inputTokens: z.number().int().nonnegative(),
  outputTokens: z.number().int().nonnegative(),
  cacheReadTokens: z.number().int().nonnegative(),
  reasoningTokens: z.number().int().nonnegative(),
});
const CompletionIdSchema = z
  .string()
  .regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/u);
const ChunkReviewCacheValueSchema = z.strictObject({
  stage: z.literal("chunk-review"),
  inputDigest: DigestSchema,
  completionId: CompletionIdSchema,
  result: z.strictObject({ recap: z.string().trim().min(1).max(100_000) }),
  usage: UsageSchema,
});
const SynthesisCacheValueSchema = z.strictObject({
  stage: z.literal("repository-synthesis"),
  inputDigest: DigestSchema,
  completionId: CompletionIdSchema,
  result: RepositorySynthesisSchema,
  usage: UsageSchema,
});
const CacheValueSchema = z.discriminatedUnion("stage", [
  ChunkReviewCacheValueSchema,
  SynthesisCacheValueSchema,
]);
const CacheRecordSchema = z.discriminatedUnion("stage", [
  ChunkReviewCacheValueSchema.extend({
    schemaVersion: z.literal(3),
    key: DigestSchema,
  }),
  SynthesisCacheValueSchema.extend({
    schemaVersion: z.literal(3),
    key: DigestSchema,
  }),
]);

export type CachedModelStage =
  | { stage: "chunk-review"; result: { recap: string } }
  | {
      stage: "repository-synthesis";
      result: z.infer<typeof RepositorySynthesisSchema>;
    };

export type CachedModelStageResult = CachedModelStage & {
  inputDigest: string;
  completionId: string;
  usage: ModelUsage;
};

export interface ModelChunkCache {
  load(key: string): Promise<CachedModelStageResult | null>;
  save(key: string, value: CachedModelStageResult): Promise<void>;
}

export class ModelCacheError extends Error {
  readonly code = "MODEL_CACHE_INVALID";
  readonly scope = "system";

  constructor(message: string) {
    super(message);
    this.name = "ModelCacheError";
  }
}

export function modelStageCacheKey(input: {
  stage: CachedModelStage["stage"];
  stagePromptDigest: string;
  endpointOrigin: string;
  modelIdentifier: string;
  promptPolicyVersion: string;
  scannerPolicyVersion: string;
  inputDigest: string;
}) {
  return createHash("sha256")
    .update(
      JSON.stringify({
        stage: input.stage,
        stage_prompt_digest: input.stagePromptDigest,
        endpoint_origin: input.endpointOrigin,
        model_identifier: input.modelIdentifier,
        prompt_policy_version: input.promptPolicyVersion,
        scanner_policy_version: input.scannerPolicyVersion,
        input_digest: input.inputDigest,
      }),
    )
    .digest("hex");
}

function validateKey(key: string) {
  const parsed = DigestSchema.safeParse(key);
  if (!parsed.success) throw new ModelCacheError("Model cache key is invalid.");
  return parsed.data;
}

function validateValue(value: CachedModelStageResult) {
  const parsed = CacheValueSchema.safeParse(value);
  if (!parsed.success)
    throw new ModelCacheError("Model cache value is invalid.");
  return parsed.data as CachedModelStageResult;
}

export class InMemoryModelChunkCache implements ModelChunkCache {
  readonly #records = new Map<string, CachedModelStageResult>();

  async load(key: string) {
    return this.#records.get(validateKey(key)) ?? null;
  }

  async save(key: string, value: CachedModelStageResult) {
    this.#records.set(validateKey(key), validateValue(value));
  }
}

export class FileModelChunkCache implements ModelChunkCache {
  constructor(readonly directory: string) {}

  async load(key: string): Promise<CachedModelStageResult | null> {
    const validatedKey = validateKey(key);
    let serialized: string;
    try {
      serialized = await readFile(
        join(this.directory, `${validatedKey}.json`),
        "utf8",
      );
    } catch (error) {
      if (
        typeof error === "object" &&
        error !== null &&
        "code" in error &&
        error.code === "ENOENT"
      )
        return null;
      throw new ModelCacheError("Model cache could not be read.");
    }

    try {
      const record = CacheRecordSchema.parse(JSON.parse(serialized));
      if (record.key !== validatedKey)
        throw new ModelCacheError("Model cache record key does not match.");
      const { schemaVersion: _schemaVersion, key: _key, ...value } = record;
      return validateValue(value as CachedModelStageResult);
    } catch (error) {
      if (error instanceof ModelCacheError) throw error;
      throw new ModelCacheError("Model cache record is invalid.");
    }
  }

  async save(key: string, value: CachedModelStageResult) {
    const validatedKey = validateKey(key);
    const validatedValue = validateValue(value);
    await mkdir(this.directory, { recursive: true });
    const temporary = join(
      this.directory,
      `.${validatedKey}.${randomUUID()}.tmp`,
    );
    const destination = join(this.directory, `${validatedKey}.json`);
    try {
      await writeFile(
        temporary,
        `${JSON.stringify({
          schemaVersion: 3,
          key: validatedKey,
          ...validatedValue,
        })}\n`,
        { flag: "wx", mode: 0o600 },
      );
      await rename(temporary, destination);
    } catch {
      throw new ModelCacheError("Model cache could not be written.");
    }
  }
}
