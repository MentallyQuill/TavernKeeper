import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, test } from "vitest";

import {
  FileModelChunkCache,
  modelChunkCacheKey,
} from "../src/model/chunk-cache.js";

describe("sanitized model chunk cache", () => {
  test("round-trips normalized results without source, prompt, credentials, or raw response", async () => {
    const directory = await mkdtemp(join(tmpdir(), "tavernkeeper-cache-test-"));
    const cache = new FileModelChunkCache(directory);
    const key = modelChunkCacheKey({
      endpointOrigin: "https://nano-gpt.com",
      modelIdentifier: "deepseek/deepseek-v4-flash",
      promptPolicyVersion: "1",
      scannerPolicyVersion: "1",
      chunkId: "a".repeat(64),
    });
    const value = {
      chunkId: "a".repeat(64),
      completionId: "completion-1",
      findings: [],
      usage: {
        inputTokens: 100,
        outputTokens: 20,
        cacheReadTokens: 10,
        reasoningTokens: 5,
      },
    };

    await cache.save(key, value);
    await expect(cache.load(key)).resolves.toEqual(value);
    const serialized = await readFile(join(directory, `${key}.json`), "utf8");
    expect(serialized).not.toMatch(
      /source|prompt|credential|api[_-]?key|raw[_-]?response/iu,
    );
  });

  test("rejects cache records with unknown raw fields", async () => {
    const directory = await mkdtemp(join(tmpdir(), "tavernkeeper-cache-test-"));
    const cache = new FileModelChunkCache(directory);
    const key = "b".repeat(64);
    await writeFile(
      join(directory, `${key}.json`),
      JSON.stringify({
        schemaVersion: 1,
        key,
        chunkId: "a".repeat(64),
        completionId: "completion-1",
        findings: [],
        usage: {
          inputTokens: 1,
          outputTokens: 1,
          cacheReadTokens: 0,
          reasoningTokens: 0,
        },
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
      cache.save("c".repeat(64), {
        chunkId: "a".repeat(64),
        completionId: "source text must never enter the cache",
        findings: [],
        usage: {
          inputTokens: 1,
          outputTokens: 1,
          cacheReadTokens: 0,
          reasoningTokens: 0,
        },
      }),
    ).rejects.toMatchObject({
      code: "MODEL_CACHE_INVALID",
      scope: "system",
    });
  });
});
