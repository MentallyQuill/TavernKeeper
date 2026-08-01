import { createHash, randomUUID } from "node:crypto";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import { join } from "node:path";

import { z } from "zod";

import type { ModelUsage } from "./openai-compatible-client.js";
import {
  AnalyzerPayloadSchema,
  ArbiterPayloadSchema,
  ChallengerPayloadSchema,
  DigestSchema,
  type AnalyzerPayload,
  type ArbiterPayload,
  type ChallengerPayload,
  type ModelRole,
} from "./role-contracts.js";

const UsageSchema = z.strictObject({
  inputTokens: z.number().int().nonnegative(),
  outputTokens: z.number().int().nonnegative(),
  cacheReadTokens: z.number().int().nonnegative(),
  reasoningTokens: z.number().int().nonnegative(),
});
const RolePayloadSchema = z.discriminatedUnion("role", [
  z.strictObject({
    role: z.literal("analyzer"),
    result: AnalyzerPayloadSchema,
  }),
  z.strictObject({
    role: z.literal("challenger"),
    result: ChallengerPayloadSchema,
  }),
  z.strictObject({ role: z.literal("arbiter"), result: ArbiterPayloadSchema }),
]);
const CacheValueSchema = z.strictObject({
  role: z.enum(["analyzer", "challenger", "arbiter"]),
  inputDigest: DigestSchema,
  completionId: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/u),
  payload: RolePayloadSchema,
  usage: UsageSchema,
});
const CacheRecordSchema = CacheValueSchema.extend({
  schemaVersion: z.literal(2),
  key: DigestSchema,
});

export type CachedRolePayload =
  | { role: "analyzer"; result: AnalyzerPayload }
  | { role: "challenger"; result: ChallengerPayload }
  | { role: "arbiter"; result: ArbiterPayload };

export interface CachedRoleResult {
  role: ModelRole;
  inputDigest: string;
  completionId: string;
  payload: CachedRolePayload;
  usage: ModelUsage;
}

export interface ModelChunkCache {
  load(key: string): Promise<CachedRoleResult | null>;
  save(key: string, value: CachedRoleResult): Promise<void>;
}

export class ModelCacheError extends Error {
  readonly code = "MODEL_CACHE_INVALID";
  readonly scope = "system";

  constructor(message: string) {
    super(message);
    this.name = "ModelCacheError";
  }
}

export function modelChunkCacheKey(input: {
  role: ModelRole;
  rolePromptDigest: string;
  endpointOrigin: string;
  modelIdentifier: string;
  promptPolicyVersion: string;
  scannerPolicyVersion: string;
  inputDigest: string;
}) {
  return createHash("sha256")
    .update(
      JSON.stringify({
        role: input.role,
        role_prompt_digest: input.rolePromptDigest,
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

function validateValue(value: CachedRoleResult) {
  const parsed = CacheValueSchema.safeParse(value);
  if (!parsed.success) {
    throw new ModelCacheError("Model cache value is invalid.");
  }
  if (parsed.data.role !== parsed.data.payload.role) {
    throw new ModelCacheError("Model cache role identity does not match.");
  }
  return parsed.data;
}

export class InMemoryModelChunkCache implements ModelChunkCache {
  readonly #records = new Map<string, CachedRoleResult>();

  async load(key: string) {
    validateKey(key);
    return this.#records.get(key) ?? null;
  }

  async save(key: string, value: CachedRoleResult) {
    this.#records.set(validateKey(key), validateValue(value));
  }
}

export class FileModelChunkCache implements ModelChunkCache {
  constructor(readonly directory: string) {}

  async load(key: string): Promise<CachedRoleResult | null> {
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
      ) {
        return null;
      }
      throw new ModelCacheError("Model cache could not be read.");
    }

    try {
      const record = CacheRecordSchema.parse(JSON.parse(serialized));
      if (record.key !== validatedKey) {
        throw new ModelCacheError("Model cache record key does not match.");
      }
      const { schemaVersion: _schemaVersion, key: _key, ...value } = record;
      return validateValue(value);
    } catch (error) {
      if (error instanceof ModelCacheError) throw error;
      throw new ModelCacheError("Model cache record is malformed.");
    }
  }

  async save(key: string, value: CachedRoleResult): Promise<void> {
    const validatedKey = validateKey(key);
    const validatedValue = validateValue(value);
    const record = CacheRecordSchema.parse({
      schemaVersion: 2,
      key: validatedKey,
      ...validatedValue,
    });
    await mkdir(this.directory, { recursive: true });
    const destination = join(this.directory, `${validatedKey}.json`);
    const temporary = join(
      this.directory,
      `${validatedKey}.${process.pid}.${randomUUID()}.tmp`,
    );
    try {
      await writeFile(temporary, `${JSON.stringify(record)}\n`, {
        encoding: "utf8",
        flag: "wx",
      });
      await rename(temporary, destination);
    } catch {
      throw new ModelCacheError("Model cache could not be written.");
    }
  }
}
