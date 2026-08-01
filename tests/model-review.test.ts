import { describe, expect, test, vi } from "vitest";

import type { ModelChunk } from "../src/model/chunker.js";
import {
  requestStructuredCompletion,
  type StructuredCompletionRequest,
} from "../src/model/openai-compatible-client.js";
import { InMemoryModelChunkCache } from "../src/model/chunk-cache.js";
import { reviewWithConfiguredModel } from "../src/model/model-review.js";

function chunk(id: string, path: string): ModelChunk {
  const content = `export const ${id} = true;\n`;
  return {
    id: id.repeat(64).slice(0, 64),
    bytes: Buffer.byteLength(content),
    content_hashes: ["b".repeat(64)],
    segments: [
      {
        path,
        line_start: 1,
        line_end: 1,
        content,
        bytes: Buffer.byteLength(content),
        overlap_bytes: 0,
        content_hash: "b".repeat(64),
        source_sha256: "c".repeat(64),
      },
    ],
  };
}

const chunks = [chunk("1", "src/a.ts"), chunk("2", "src/b.ts")];

function configuredSpec() {
  return {
    endpoint: "https://nano-gpt.com/api/subscription/v1/chat/completions",
    apiKey: "test-model-key",
    model: "deepseek/deepseek-v4-flash",
    chunks,
    deterministicFindings: [],
    relationships: [{ from: "src/a.ts", to: "src/b.ts", kind: "imports" }],
    promptPolicyVersion: "1",
    scannerPolicyVersion: "1",
    maxOutputTokensPerChunk: 8_192,
    maxSynthesisOutputTokens: 8_192,
  };
}

describe("configured model review", () => {
  test("reviews every chunk, performs final synthesis, and sums actual usage", async () => {
    const provider = vi.fn(async (request: StructuredCompletionRequest) => {
      const isSynthesis = request.schemaName === "tavernkeeper_synthesis";
      const path = isSynthesis
        ? null
        : (
            JSON.parse(request.userContent) as {
              segments: Array<{ path: string }>;
            }
          ).segments[0]!.path;
      return {
        completionId: `completion-${provider.mock.calls.length}`,
        endpointOrigin: "https://nano-gpt.com",
        provider: "nano-gpt.com",
        content: JSON.stringify(
          isSynthesis
            ? { annotations: [] }
            : {
                findings: [
                  {
                    rule_id: "credential-network-flow",
                    category: "credential-theft",
                    severity: "high",
                    confidence: "high",
                    path,
                    line_start: 1,
                    line_end: 1,
                    title: "Credential flow needs review",
                    explanation: "Credential access reaches an outbound call.",
                    remediation: null,
                  },
                ],
              },
        ),
        usage: {
          inputTokens: 400,
          outputTokens: 100,
          cacheReadTokens: 50,
          reasoningTokens: 30,
        },
      };
    });

    const result = await reviewWithConfiguredModel({
      ...configuredSpec(),
      cache: new InMemoryModelChunkCache(),
      requestCompletion: provider,
    });

    expect(provider).toHaveBeenCalledTimes(chunks.length + 1);
    expect(result.completedChunkIds).toEqual(chunks.map(({ id }) => id));
    expect(result.usage).toEqual({
      inputTokens: 1_200,
      outputTokens: 300,
      cacheReadTokens: 150,
      reasoningTokens: 90,
    });
    expect(result).toMatchObject({
      endpointOrigin: "https://nano-gpt.com",
      provider: "nano-gpt.com",
      model: "deepseek/deepseek-v4-flash",
    });
    expect(result.findings).toHaveLength(2);
  });

  test("resumes from sanitized chunk cache and still performs final synthesis", async () => {
    const cache = new InMemoryModelChunkCache();
    const firstProvider = vi.fn(
      async (request: StructuredCompletionRequest) => ({
        completionId: "first",
        endpointOrigin: "https://nano-gpt.com",
        provider: "nano-gpt.com",
        content: JSON.stringify(
          request.schemaName === "tavernkeeper_synthesis"
            ? { annotations: [] }
            : { findings: [] },
        ),
        usage: {
          inputTokens: 10,
          outputTokens: 2,
          cacheReadTokens: 0,
          reasoningTokens: 0,
        },
      }),
    );
    await reviewWithConfiguredModel({
      ...configuredSpec(),
      cache,
      requestCompletion: firstProvider,
    });

    const secondProvider = vi.fn(async () => ({
      completionId: "second-synthesis",
      endpointOrigin: "https://nano-gpt.com",
      provider: "nano-gpt.com",
      content: JSON.stringify({ annotations: [] }),
      usage: {
        inputTokens: 5,
        outputTokens: 1,
        cacheReadTokens: 0,
        reasoningTokens: 0,
      },
    }));
    const result = await reviewWithConfiguredModel({
      ...configuredSpec(),
      cache,
      requestCompletion: secondProvider,
    });

    expect(secondProvider).toHaveBeenCalledTimes(1);
    expect(result.completedChunkIds).toHaveLength(chunks.length);
  });

  test("rejects missing runtime configuration before any provider call", async () => {
    const provider = vi.fn();
    await expect(
      reviewWithConfiguredModel({
        ...configuredSpec(),
        apiKey: null,
        cache: new InMemoryModelChunkCache(),
        requestCompletion: provider,
      }),
    ).rejects.toMatchObject({ code: "MODEL_CONFIGURATION", scope: "system" });
    expect(provider).not.toHaveBeenCalled();
  });

  test("rejects chunk findings that omit required structured fields", async () => {
    const provider = vi.fn(async (request: StructuredCompletionRequest) => ({
      completionId: "missing-field",
      endpointOrigin: "https://nano-gpt.com",
      provider: "nano-gpt.com",
      content: JSON.stringify(
        request.schemaName === "tavernkeeper_synthesis"
          ? { annotations: [] }
          : {
              findings: [
                {
                  rule_id: "credential-network-flow",
                  category: "credential-theft",
                  severity: "high",
                  confidence: "high",
                  path: "src/a.ts",
                  line_start: 1,
                  line_end: 1,
                  title: "Credential flow needs review",
                  explanation: "Credential access reaches an outbound call.",
                },
              ],
            },
      ),
      usage: {
        inputTokens: 10,
        outputTokens: 2,
        cacheReadTokens: 0,
        reasoningTokens: 0,
      },
    }));

    await expect(
      reviewWithConfiguredModel({
        ...configuredSpec(),
        chunks: [chunks[0]!],
        cache: new InMemoryModelChunkCache(),
        requestCompletion: provider,
      }),
    ).rejects.toMatchObject({ code: "MODEL_INVALID_RESPONSE" });
  });
});

describe("OpenAI-compatible client", () => {
  test("posts to the exact endpoint, uses assistant content only, and extracts NanoGPT usage", async () => {
    const fetchImpl = vi.fn(
      async (
        _input: Parameters<typeof fetch>[0],
        _init?: Parameters<typeof fetch>[1],
      ) =>
        new Response(
          JSON.stringify({
            id: "chatcmpl-1",
            choices: [
              {
                message: {
                  content: '{"findings":[]}',
                  reasoning_content: '{"findings":[{"path":"wrong"}]}',
                },
              },
            ],
            usage: {
              prompt_tokens: 100,
              prompt_tokens_details: { cached_tokens: 20 },
              cache_read_input_tokens: 25,
              completion_tokens: 30,
              completion_tokens_details: { reasoning_tokens: 7 },
              reasoning_tokens: 9,
            },
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        ),
    );
    const endpoint =
      "https://nano-gpt.com/api/subscription/v1/chat/completions";
    const result = await requestStructuredCompletion({
      endpoint,
      apiKey: "test-key",
      model: "deepseek/deepseek-v4-flash",
      systemContent: "System",
      userContent: "User",
      maxOutputTokens: 8_192,
      schemaName: "tavernkeeper_chunk_findings",
      jsonSchema: { type: "object" },
      fetchImpl,
      resolveAddresses: async () => ["104.21.10.20"],
    });

    expect(fetchImpl).toHaveBeenCalledWith(
      endpoint,
      expect.objectContaining({ method: "POST", redirect: "manual" }),
    );
    const request = fetchImpl.mock.calls[0]?.[1] as RequestInit;
    expect(JSON.parse(String(request.body))).toMatchObject({
      model: "deepseek/deepseek-v4-flash",
      stream: false,
      temperature: 0,
      max_tokens: 8_192,
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "tavernkeeper_chunk_findings",
          strict: true,
        },
      },
    });
    expect(result.content).toBe('{"findings":[]}');
    expect(result.usage).toEqual({
      inputTokens: 100,
      outputTokens: 30,
      cacheReadTokens: 25,
      reasoningTokens: 9,
    });
  });

  test("rejects private endpoints and redirects", async () => {
    await expect(
      requestStructuredCompletion({
        endpoint: "https://127.0.0.1/v1/chat/completions",
        apiKey: "test-key",
        model: "model",
        systemContent: "System",
        userContent: "User",
        maxOutputTokens: 100,
        schemaName: "test",
        jsonSchema: { type: "object" },
        fetchImpl: vi.fn(),
      }),
    ).rejects.toMatchObject({ code: "MODEL_CONFIGURATION" });

    await expect(
      requestStructuredCompletion({
        endpoint: "https://example.com/v1/chat/completions",
        apiKey: "test-key",
        model: "model",
        systemContent: "System",
        userContent: "User",
        maxOutputTokens: 100,
        schemaName: "test",
        jsonSchema: { type: "object" },
        fetchImpl: async () => new Response(null, { status: 302 }),
        resolveAddresses: async () => ["93.184.216.34"],
      }),
    ).rejects.toMatchObject({ code: "MODEL_PROVIDER" });
  });
});
