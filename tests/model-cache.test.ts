import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, test } from "vitest";

import {
  FileModelChunkCache,
  modelStageCacheKey,
  type CachedModelStageResult,
} from "../src/model/chunk-cache.js";

function cacheKey(stage: "chunk-review" | "repository-synthesis") {
  return modelStageCacheKey({
    stage,
    stagePromptDigest: "a".repeat(64),
    endpointOrigin: "https://provider.example",
    modelIdentifier: "vendor/model-test",
    promptPolicyVersion: "repository-review-v2",
    scannerPolicyVersion: "1",
    inputDigest: "b".repeat(64),
  });
}

function value(
  stage: "chunk-review" | "repository-synthesis" = "chunk-review",
): CachedModelStageResult {
  return {
    stage,
    inputDigest: "b".repeat(64),
    completionId: "completion-1",
    result:
      stage === "chunk-review"
        ? { recap: "Bounded private recap." }
        : {
            assessment: "no_concerning_evidence",
            recap: "The completed review found no review-level concern.",
            concerns: [],
          },
    usage: {
      inputTokens: 100,
      outputTokens: 20,
      cacheReadTokens: 10,
      reasoningTokens: 5,
    },
  } as CachedModelStageResult;
}

describe("sanitized model stage cache", () => {
  test("round-trips schema-version-3 stage results without private request data", async () => {
    const directory = await mkdtemp(join(tmpdir(), "tavernkeeper-cache-test-"));
    const cache = new FileModelChunkCache(directory);
    const key = cacheKey("chunk-review");
    const cached = value();

    await cache.save(key, cached);
    await expect(cache.load(key)).resolves.toEqual(cached);
    const serialized = await readFile(join(directory, `${key}.json`), "utf8");
    expect(JSON.parse(serialized)).toMatchObject({ schemaVersion: 3, key });
    expect(serialized).not.toMatch(
      /systemContent|userContent|credential|api[_-]?key|raw[_-]?response/iu,
    );
  });

  test("separates cache identity by stage and stage-prompt digest", () => {
    expect(cacheKey("chunk-review")).not.toBe(cacheKey("repository-synthesis"));
    expect(cacheKey("chunk-review")).not.toBe(
      modelStageCacheKey({
        stage: "chunk-review",
        stagePromptDigest: "c".repeat(64),
        endpointOrigin: "https://provider.example",
        modelIdentifier: "vendor/model-test",
        promptPolicyVersion: "repository-review-v2",
        scannerPolicyVersion: "1",
        inputDigest: "b".repeat(64),
      }),
    );
  });

  test("rejects schema-version-2 and records with unknown raw fields", async () => {
    const directory = await mkdtemp(join(tmpdir(), "tavernkeeper-cache-test-"));
    const cache = new FileModelChunkCache(directory);
    const key = cacheKey("chunk-review");
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

  test("rejects untrusted completion identities and invalid synthesis", async () => {
    const cache = new FileModelChunkCache(
      await mkdtemp(join(tmpdir(), "tavernkeeper-cache-test-")),
    );

    await expect(
      cache.save(cacheKey("chunk-review"), {
        ...value(),
        completionId: "source text must never enter the cache",
      }),
    ).rejects.toMatchObject({ code: "MODEL_CACHE_INVALID", scope: "system" });

    await expect(
      cache.save(cacheKey("repository-synthesis"), {
        ...value("repository-synthesis"),
        result: {
          assessment: "concerning",
          recap: "Contradictory synthesis.",
          concerns: [],
        },
      } as CachedModelStageResult),
    ).rejects.toMatchObject({ code: "MODEL_CACHE_INVALID", scope: "system" });
  });
});
