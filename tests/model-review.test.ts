import { describe, expect, test, vi } from "vitest";

import { requestStructuredCompletion } from "../src/model/openai-compatible-client.js";

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
                  content: '{"decisions":[]}',
                  reasoning_content: '{"decisions":[{"wrong":true}]}',
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
      apiKey: " \r\ntest-key\n ",
      model: "deepseek/deepseek-v4-flash",
      systemContent: "System",
      userContent: "User",
      maxOutputTokens: 8_192,
      schemaName: "tavernkeeper_arbiter",
      jsonSchema: { type: "object" },
      fetchImpl,
      resolveAddresses: async () => ["104.21.10.20"],
    });

    expect(fetchImpl).toHaveBeenCalledWith(
      endpoint,
      expect.objectContaining({
        method: "POST",
        redirect: "manual",
        headers: expect.objectContaining({ Authorization: "Bearer test-key" }),
      }),
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
          name: "tavernkeeper_arbiter",
          strict: true,
        },
      },
    });
    expect(result.content).toBe('{"decisions":[]}');
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
