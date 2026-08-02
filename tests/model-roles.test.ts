import { readFile } from "node:fs/promises";
import { createHash } from "node:crypto";

import { describe, expect, test, vi } from "vitest";

import { InMemoryModelChunkCache } from "../src/model/chunk-cache.js";
import { chunkReviewUserContent } from "../src/model/chunk-review.js";
import type { ModelChunk } from "../src/model/chunker.js";
import { buildEvidenceManifest } from "../src/model/evidence-manifest.js";
import {
  reviewRepositoryWithConfiguredModel,
  type ConfiguredModelReviewSpec,
} from "../src/model/model-review.js";
import { ModelRequestError } from "../src/model/openai-compatible-client.js";
import {
  repositorySynthesisInput,
  validateRepositorySynthesis,
} from "../src/model/repository-synthesis.js";
import { normalizeFinding } from "../src/scanners/types.js";

const targetSha = "a".repeat(40);
const zeroUsage = {
  inputTokens: 1,
  outputTokens: 2,
  cacheReadTokens: 3,
  reasoningTokens: 4,
};

function chunk(id: string, path: string, content: string): ModelChunk {
  return {
    id,
    bytes: Buffer.byteLength(content),
    content_hashes: [id],
    segments: [
      {
        path,
        line_start: 1,
        line_end: 1,
        content,
        bytes: Buffer.byteLength(content),
        overlap_bytes: 0,
        content_hash: id,
        source_sha256: "f".repeat(64),
      },
    ],
  };
}

const chunks = [
  chunk("1".repeat(64), "src/alpha.ts", "alphaUniqueCall();\n"),
  chunk("2".repeat(64), "src/beta.ts", "betaUniqueCall();\n"),
];
const finding = normalizeFinding({
  origin: "opengrep",
  ruleId: "unsafe-call",
  category: "unsafe-execution",
  severity: "high",
  confidence: "high",
  path: "src/alpha.ts",
  lineStart: 1,
  lineEnd: 1,
  evidenceSha: null,
  title: "Unsafe call",
  explanation: "An unsafe call was detected.",
});

function completion(content: string, id: string) {
  return {
    completionId: id,
    endpointOrigin: "https://provider.example",
    provider: "provider.example",
    content,
    usage: zeroUsage,
  };
}

function cleanSynthesis() {
  return JSON.stringify({
    assessment: "no_concerning_evidence",
    recap: "The completed review found no review-level concern.",
    concerns: [],
  });
}

function configuredSpec(overrides: Partial<ConfiguredModelReviewSpec> = {}) {
  const evidenceManifest = buildEvidenceManifest(chunks, [finding], targetSha);
  return {
    endpoint: "https://provider.example/v1/chat/completions",
    apiKey: "test-api-key",
    model: "vendor/model:thinking",
    targetSha,
    projectKinds: ["extension"] as const,
    chunks,
    deterministicFindings: [finding],
    evidenceManifest,
    tools: [{ name: "opengrep", status: "completed" as const }],
    promptPolicyVersion: "repository-review-v2",
    scannerPolicyVersion: "1",
    chunkReviewPolicy: "chunk-review-v2",
    synthesisPolicy: "repository-synthesis-v2",
    maxOutputTokensPerChunkReview: 8_192,
    maxChunkReviewCharacters: 12_000,
    maxOutputTokensForSynthesis: 8_192,
    cache: new InMemoryModelChunkCache(),
    requestTextCompletion: vi.fn(async (_request) =>
      completion("No review-level concern appears in this chunk.", "text-1"),
    ),
    requestStructuredCompletion: vi.fn(async (_request) =>
      completion(cleanSynthesis(), "synthesis-1"),
    ),
    ...overrides,
  } satisfies ConfiguredModelReviewSpec;
}

async function expectInvalid(
  spec: ConfiguredModelReviewSpec,
  diagnostic: string,
) {
  let error: unknown;
  try {
    await reviewRepositoryWithConfiguredModel(spec);
  } catch (candidate) {
    error = candidate;
  }
  expect(error).toBeInstanceOf(ModelRequestError);
  expect(error).toMatchObject({
    code: "MODEL_INVALID_RESPONSE",
    scope: "repository",
    diagnostic,
  });
  expect(String((error as Error).message)).not.toContain("test-api-key");
}

describe("configured repository review", () => {
  test("reviews each chunk as text before one structured synthesis", async () => {
    const calls: Array<{ kind: string; system: string; user: string }> = [];
    const spec = configuredSpec({
      requestTextCompletion: vi.fn(async (request) => {
        calls.push({
          kind: "text",
          system: request.systemContent,
          user: request.userContent,
        });
        return completion("Bounded private recap.", `text-${calls.length}`);
      }),
      requestStructuredCompletion: vi.fn(async (request) => {
        calls.push({
          kind: "structured",
          system: request.systemContent,
          user: request.userContent,
        });
        return completion(cleanSynthesis(), "synthesis-1");
      }),
    });

    const result = await reviewRepositoryWithConfiguredModel(spec);

    expect(calls.map(({ kind }) => kind)).toEqual([
      "text",
      "text",
      "structured",
    ]);
    expect(result.stageCompletion).toEqual({
      chunkReview: { required: 2, completed: 2 },
      synthesis: { required: 1, completed: 1 },
    });
    expect(result.completedChunkIds).toEqual(chunks.map(({ id }) => id));
    expect(result.synthesis.assessment).toBe("no_concerning_evidence");
    expect(result.usage).toEqual({
      inputTokens: 3,
      outputTokens: 6,
      cacheReadTokens: 9,
      reasoningTokens: 12,
    });
    expect(result).toMatchObject({
      endpointOrigin: "https://provider.example",
      provider: "provider.example",
      model: "vendor/model:thinking",
      cacheHits: 0,
      cacheMisses: 3,
    });

    const [alpha, beta, synthesis] = calls;
    expect(alpha?.user).toContain("alphaUniqueCall");
    expect(alpha?.user).not.toContain("betaUniqueCall");
    expect(alpha?.user).toContain("tool-000001");
    expect(beta?.user).toContain("betaUniqueCall");
    expect(beta?.user).not.toContain("alphaUniqueCall");
    expect(beta?.user).not.toContain("tool-000001");
    for (const call of [alpha, beta]) {
      expect(call?.user).toContain(targetSha);
      expect(call?.user).toContain("extension");
      expect(call?.system).toMatch(/repository text.*data.*not instructions/iu);
      expect(call?.system).toMatch(/extension.*browser.*credential/iu);
    }
    expect(synthesis?.user).not.toContain("alphaUniqueCall");
    expect(synthesis?.user).not.toContain("betaUniqueCall");
  });

  test.each([
    ["empty", "   ", "chunk_review_empty"],
    ["oversized", "x".repeat(12_001), "chunk_review_size"],
  ])("rejects %s chunk prose", async (_label, content, diagnostic) => {
    const requestTextCompletion = vi.fn(async () =>
      completion(content, "text-invalid"),
    );
    await expectInvalid(configuredSpec({ requestTextCompletion }), diagnostic);
    expect(requestTextCompletion).toHaveBeenCalledTimes(3);
  });

  test("revalidates a cached chunk recap against the configured ceiling", async () => {
    const oneChunk = [chunks[0]!];
    const evidenceManifest = buildEvidenceManifest(
      oneChunk,
      [finding],
      targetSha,
    );
    const base = configuredSpec({ chunks: oneChunk, evidenceManifest });
    const inputDigest = createHash("sha256")
      .update(
        chunkReviewUserContent({
          targetSha: base.targetSha,
          projectKinds: base.projectKinds,
          chunkId: chunks[0]!.id,
          evidenceManifest: base.evidenceManifest!,
        }),
      )
      .digest("hex");
    const cache = {
      load: vi.fn(async () => ({
        stage: "chunk-review" as const,
        inputDigest,
        completionId: "cached-1",
        result: { recap: "x".repeat(12_001) },
        usage: zeroUsage,
      })),
      save: vi.fn(),
    };

    await expectInvalid(
      configuredSpec({ chunks: oneChunk, evidenceManifest, cache }),
      "chunk_review_cache",
    );
  });

  test.each([
    ["malformed JSON", "not json", "synthesis_schema"],
    [
      "concerning without a review-level concern",
      JSON.stringify({
        assessment: "concerning",
        recap: "Concern.",
        concerns: [],
      }),
      "synthesis_schema",
    ],
    [
      "clean with a concern",
      JSON.stringify({
        assessment: "no_concerning_evidence",
        recap: "Contradictory review.",
        concerns: [
          {
            title: "Concern",
            category: "unsafe-execution",
            severity: "high",
            confidence: "high",
            explanation: "A review-level concern was identified.",
            evidence_ids: ["source-000001"],
          },
        ],
      }),
      "synthesis_schema",
    ],
    [
      "unknown evidence",
      JSON.stringify({
        assessment: "concerning",
        recap: "A review-level concern was identified.",
        concerns: [
          {
            title: "Concern",
            category: "unsafe-execution",
            severity: "high",
            confidence: "high",
            explanation: "The concern is grounded in submitted evidence.",
            evidence_ids: ["source-999999"],
          },
        ],
      }),
      "synthesis_evidence",
    ],
    [
      "duplicated evidence",
      JSON.stringify({
        assessment: "concerning",
        recap: "A review-level concern was identified.",
        concerns: [
          {
            title: "Concern",
            category: "unsafe-execution",
            severity: "high",
            confidence: "high",
            explanation: "The concern is grounded in submitted evidence.",
            evidence_ids: ["source-000001", "source-000001"],
          },
        ],
      }),
      "synthesis_evidence",
    ],
    [
      "inconclusive assessment",
      JSON.stringify({
        assessment: "inconclusive",
        recap: "Unknown.",
        concerns: [],
      }),
      "synthesis_inconclusive",
    ],
  ])("rejects %s synthesis", async (_label, content, diagnostic) => {
    await expectInvalid(
      configuredSpec({
        requestStructuredCompletion: vi.fn(async () =>
          completion(content, "synthesis-invalid"),
        ),
      }),
      diagnostic,
    );
  });

  test("assigns stable concern identities without exposing internal scanner fingerprints", async () => {
    const concerning = JSON.stringify({
      assessment: "concerning",
      recap: "The reviewed behavior creates a review-level execution concern.",
      concerns: [
        {
          title: "Untrusted execution path",
          category: "unsafe-execution",
          severity: "high",
          confidence: "high",
          explanation:
            "Submitted source and tool evidence support the concern.",
          evidence_ids: ["source-000001", "tool-000001"],
        },
      ],
    });

    const result = await reviewRepositoryWithConfiguredModel(
      configuredSpec({
        requestStructuredCompletion: vi.fn(async () =>
          completion(concerning, "synthesis-concerning"),
        ),
      }),
    );

    expect(result.synthesis.concerns[0]).toMatchObject({
      id: expect.stringMatching(/^[a-f0-9]{64}$/u),
      fingerprint: expect.stringMatching(/^[a-f0-9]{64}$/u),
      evidence_ids: ["source-000001", "tool-000001"],
      evidence: [
        { evidenceId: "source-000001", kind: "source", targetSha },
        {
          evidenceId: "tool-000001",
          kind: "tool",
          targetSha,
          origin: "opengrep",
          ruleId: "unsafe-call",
        },
      ],
    });
    expect(result.synthesis.concerns[0]?.evidence).not.toEqual(
      expect.arrayContaining([
        expect.objectContaining({ scannerFingerprint: expect.any(String) }),
      ]),
    );
  });

  test.each([
    "Token: ghp_abcdefghijklmnopqrstuvwxyz123456",
    "The code uses const stolenCredential = accountToken;",
    "See https://untrusted.example/details for the result.",
    "This repository is verified safe for installation.",
  ])("rejects unsafe public synthesis prose", async (recap) => {
    await expectInvalid(
      configuredSpec({
        requestStructuredCompletion: vi.fn(async () =>
          completion(
            JSON.stringify({
              assessment: "no_concerning_evidence",
              recap,
              concerns: [],
            }),
            "synthesis-unsafe",
          ),
        ),
      }),
      "synthesis_schema",
    );
  });

  test("rejects mismatched provider identity without retrying system failures", async () => {
    const requestTextCompletion = vi.fn(async () => ({
      ...completion("Bounded private recap.", "wrong-origin"),
      endpointOrigin: "https://other.example",
    }));
    await expectInvalid(
      configuredSpec({ requestTextCompletion }),
      "chunk_review_identity",
    );
    expect(requestTextCompletion).toHaveBeenCalledTimes(3);

    const authentication = vi.fn(async () => {
      throw new ModelRequestError(
        "MODEL_AUTHENTICATION",
        "system",
        "Authentication failed.",
      );
    });
    await expect(
      reviewRepositoryWithConfiguredModel(
        configuredSpec({ requestTextCompletion: authentication }),
      ),
    ).rejects.toMatchObject({ code: "MODEL_AUTHENTICATION", scope: "system" });
    expect(authentication).toHaveBeenCalledTimes(1);
  });

  test("retries only synthesis and reuses validated cached chunk reviews", async () => {
    const cache = new InMemoryModelChunkCache();
    const requestTextCompletion = vi.fn(async () =>
      completion("Bounded private recap.", "text-valid"),
    );
    let attempts = 0;
    const requestStructuredCompletion = vi.fn(async () => {
      attempts += 1;
      return completion(
        attempts < 3 ? "not json" : cleanSynthesis(),
        `synthesis-${attempts}`,
      );
    });

    const result = await reviewRepositoryWithConfiguredModel(
      configuredSpec({
        cache,
        requestTextCompletion,
        requestStructuredCompletion,
      }),
    );

    expect(requestTextCompletion).toHaveBeenCalledTimes(2);
    expect(requestStructuredCompletion).toHaveBeenCalledTimes(3);
    expect(result).toMatchObject({ cacheHits: 4, cacheMisses: 3 });
    expect(result.usage).toEqual({
      inputTokens: 5,
      outputTokens: 10,
      cacheReadTokens: 15,
      reasoningTokens: 20,
    });

    const unusedText = vi.fn();
    const unusedStructured = vi.fn();
    const resumed = await reviewRepositoryWithConfiguredModel(
      configuredSpec({
        cache,
        requestTextCompletion: unusedText,
        requestStructuredCompletion: unusedStructured,
      }),
    );
    expect(unusedText).not.toHaveBeenCalled();
    expect(unusedStructured).not.toHaveBeenCalled();
    expect(resumed).toMatchObject({ cacheHits: 3, cacheMisses: 0 });
  });

  test("canonicalizes evidence order before assigning stable concern identities", () => {
    const manifest = buildEvidenceManifest(chunks, [finding], targetSha);
    const concern = {
      title: "Untrusted execution path",
      category: "unsafe-execution",
      severity: "high",
      confidence: "high",
      explanation: "Submitted source and tool evidence support the concern.",
    } as const;
    const forward = validateRepositorySynthesis(
      JSON.stringify({
        assessment: "concerning",
        recap: "The completed review found an execution concern.",
        concerns: [
          {
            ...concern,
            evidence_ids: ["source-000001", "tool-000001"],
          },
        ],
      }),
      manifest,
    );
    const reversed = validateRepositorySynthesis(
      JSON.stringify({
        assessment: "concerning",
        recap: "The completed review found an execution concern.",
        concerns: [
          {
            ...concern,
            evidence_ids: ["tool-000001", "source-000001"],
          },
        ],
      }),
      manifest,
    );

    expect(reversed.validated.concerns[0]).toEqual(
      forward.validated.concerns[0],
    );
    expect(forward.validated.concerns[0]?.evidence_ids).toEqual([
      "source-000001",
      "tool-000001",
    ]);
  });

  test("rejects duplicate computed concern identities", () => {
    const concern = {
      title: "Untrusted execution path",
      category: "unsafe-execution",
      severity: "high",
      confidence: "high",
      explanation: "Submitted source evidence supports the concern.",
      evidence_ids: ["source-000001"],
    } as const;
    expect(() =>
      validateRepositorySynthesis(
        JSON.stringify({
          assessment: "concerning",
          recap: "The completed review found duplicated concerns.",
          concerns: [concern, concern],
        }),
        buildEvidenceManifest(chunks, [finding], targetSha),
      ),
    ).toThrowError(
      expect.objectContaining({
        code: "MODEL_INVALID_RESPONSE",
        scope: "repository",
        diagnostic: "synthesis_evidence",
      }),
    );
  });

  test("rejects not-applicable tool coverage that has manifest signals", async () => {
    await expectInvalid(
      configuredSpec({
        tools: [{ name: "opengrep", status: "not-applicable" }],
      }),
      "synthesis_evidence",
    );
    expect(() =>
      repositorySynthesisInput({
        targetSha,
        projectKinds: ["extension"],
        tools: [{ name: "opengrep", status: "not-applicable" }],
        evidenceManifest: buildEvidenceManifest(chunks, [finding], targetSha),
        completedChunkReviews: [],
      }),
    ).toThrowError(
      expect.objectContaining({ diagnostic: "synthesis_evidence" }),
    );
  });

  test("rejects configured model mismatch at chunk and synthesis boundaries", async () => {
    const wrongChunkModel = vi.fn(async () => ({
      ...completion("Bounded private recap.", "wrong-chunk-model"),
      model: "vendor/other-model",
    }));
    await expectInvalid(
      configuredSpec({ requestTextCompletion: wrongChunkModel }),
      "chunk_review_identity",
    );
    expect(wrongChunkModel).toHaveBeenCalledTimes(3);

    const wrongSynthesisModel = vi.fn(async () => ({
      ...completion(cleanSynthesis(), "wrong-synthesis-model"),
      model: "vendor/other-model",
    }));
    await expectInvalid(
      configuredSpec({ requestStructuredCompletion: wrongSynthesisModel }),
      "synthesis_identity",
    );
    expect(wrongSynthesisModel).toHaveBeenCalledTimes(3);
  });

  test("fails closed when configured chunks and evidence manifest diverge", async () => {
    await expectInvalid(
      configuredSpec({ chunks: chunks.slice(0, 1) }),
      "synthesis_evidence",
    );
  });

  test("has no legacy role pipeline imports", async () => {
    const source = await readFile(
      new URL("../src/model/model-review.ts", import.meta.url),
      "utf8",
    );
    expect(source).not.toMatch(
      /(?:analyzer|challenger|arbiter|rolePolicies|maxOutputTokensPerRole|role-policy|automated-disposition|role-schema)/iu,
    );
  });
});
