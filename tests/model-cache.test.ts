import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, test } from "vitest";

import {
  FileModelChunkCache,
  modelChunkCacheKey,
} from "../src/model/chunk-cache.js";

function cacheKey(role: "analyzer" | "challenger" | "arbiter" = "analyzer") {
  return modelChunkCacheKey({
    role,
    rolePromptDigest: "a".repeat(64),
    endpointOrigin: "https://provider.example",
    modelIdentifier: "vendor/model-test",
    promptPolicyVersion: "2",
    scannerPolicyVersion: "1",
    inputDigest: "b".repeat(64),
  });
}

function value() {
  return {
    role: "analyzer" as const,
    inputDigest: "b".repeat(64),
    completionId: "completion-1",
    payload: {
      role: "analyzer" as const,
      result: { assessments: [], discoveries: [] },
    },
    usage: {
      inputTokens: 100,
      outputTokens: 20,
      cacheReadTokens: 10,
      reasoningTokens: 5,
    },
  };
}

describe("sanitized model role cache", () => {
  test("round-trips strict parsed results without source, prompts, credentials, or raw responses", async () => {
    const directory = await mkdtemp(join(tmpdir(), "tavernkeeper-cache-test-"));
    const cache = new FileModelChunkCache(directory);
    const key = cacheKey();
    const cached = value();

    await cache.save(key, cached);
    await expect(cache.load(key)).resolves.toEqual(cached);
    const serialized = await readFile(join(directory, `${key}.json`), "utf8");
    expect(serialized).not.toMatch(
      /source|prompt|credential|api[_-]?key|raw[_-]?response/iu,
    );
  });

  test("separates cache identity by role and role-prompt digest", () => {
    expect(cacheKey("analyzer")).not.toBe(cacheKey("arbiter"));
    expect(cacheKey()).not.toBe(
      modelChunkCacheKey({
        role: "analyzer",
        rolePromptDigest: "c".repeat(64),
        endpointOrigin: "https://provider.example",
        modelIdentifier: "vendor/model-test",
        promptPolicyVersion: "2",
        scannerPolicyVersion: "1",
        inputDigest: "b".repeat(64),
      }),
    );
  });

  test("rejects cache records with unknown raw fields", async () => {
    const directory = await mkdtemp(join(tmpdir(), "tavernkeeper-cache-test-"));
    const cache = new FileModelChunkCache(directory);
    const key = cacheKey();
    await writeFile(
      join(directory, `${key}.json`),
      JSON.stringify({
        schemaVersion: 2,
        key,
        ...value(),
        rawResponse: "forbidden",
      }),
    );

    await expect(cache.load(key)).rejects.toMatchObject({
      code: "MODEL_CACHE_INVALID",
      scope: "system",
    });
  });

  test("rejects untrusted text in provider completion identities", async () => {
    const cache = new FileModelChunkCache(
      await mkdtemp(join(tmpdir(), "tavernkeeper-cache-test-")),
    );

    await expect(
      cache.save(cacheKey(), {
        ...value(),
        completionId: "source text must never enter the cache",
      }),
    ).rejects.toMatchObject({
      code: "MODEL_CACHE_INVALID",
      scope: "system",
    });
  });
});
