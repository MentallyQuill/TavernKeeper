import { describe, expect, test, vi } from "vitest";

import { requestTextCompletion } from "../src/model/openai-compatible-client.js";

describe("OpenAI-compatible contextual-review transport", () => {
  test("uses Bearer auth at the exact endpoint and ignores hidden thinking", async () => {
    const fetchImpl = vi.fn<typeof fetch>(async () =>
      Promise.resolve(
        new Response(
          JSON.stringify({
            id: "chatcmpl-context-1",
            model: "deepseek/deepseek-v4-flash-0731:thinking",
            choices: [
              {
                message: {
                  content: '{"status":"complete"}',
                  reasoning_content: "private chain of thought",
                },
                finish_reason: "stop",
              },
            ],
            usage: {
              prompt_tokens: 100,
              completion_tokens: 30,
              reasoning_tokens: 20,
            },
          }),
          { status: 200 },
        ),
      ),
    );
    const endpoint = "https://nano-gpt.com/api/v1/chat/completions";

    const result = await requestTextCompletion({
      endpoint,
      apiKey: " test-key ",
      model: "deepseek/deepseek-v4-flash-0731:thinking",
      maxOutputTokens: 8_192,
      systemContent: "Trusted review policy.",
      userContent: "Delimited untrusted evidence.",
      responseJsonSchema: {
        type: "object",
        properties: { status: { const: "complete" } },
        required: ["status"],
        additionalProperties: false,
      },
      fetchImpl,
      resolveAddresses: async () => ["104.21.10.20"],
    });

    expect(fetchImpl).toHaveBeenCalledWith(
      endpoint,
      expect.objectContaining({
        method: "POST",
        redirect: "manual",
        headers: {
          Authorization: "Bearer test-key",
          "Content-Type": "application/json",
        },
      }),
    );
    expect(JSON.parse(String(fetchImpl.mock.calls[0]?.[1]?.body))).toEqual({
      model: "deepseek/deepseek-v4-flash-0731:thinking",
      messages: [
        { role: "system", content: "Trusted review policy." },
        { role: "user", content: "Delimited untrusted evidence." },
      ],
      stream: false,
      temperature: 0,
      max_tokens: 8_192,
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "tavernkeeper_contextual_assessment",
          strict: true,
          schema: {
            type: "object",
            properties: { status: { const: "complete" } },
            required: ["status"],
            additionalProperties: false,
          },
        },
      },
    });
    expect(result).toMatchObject({
      content: '{"status":"complete"}',
      usage: { inputTokens: 100, outputTokens: 30, reasoningTokens: 20 },
    });
    expect(JSON.stringify(result)).not.toContain("private chain of thought");
  });

  test("accepts beta providers that return final text as content parts", async () => {
    const result = await requestTextCompletion({
      endpoint: "https://provider.example/v1/chat/completions",
      apiKey: "test-key",
      model: "beta/model:thinking",
      maxOutputTokens: 1_000,
      systemContent: "System",
      userContent: "User",
      responseJsonSchema: {
        type: "object",
        properties: { status: { const: "complete" } },
        required: ["status"],
        additionalProperties: false,
      },
      fetchImpl: async () =>
        new Response(
          JSON.stringify({
            id: "chatcmpl-parts",
            choices: [
              {
                message: {
                  content: [
                    { type: "text", text: '{"status":' },
                    { type: "text", text: '"complete"}' },
                  ],
                },
                finish_reason: "stop",
              },
            ],
            usage: { input_tokens: 9, output_tokens: 4 },
          }),
          { status: 200 },
        ),
      resolveAddresses: async () => ["93.184.216.34"],
    });

    expect(result.content).toBe('{"status":"complete"}');
  });

  test("rejects private endpoints and redirects", async () => {
    const base = {
      apiKey: "test-key",
      model: "configured/model",
      maxOutputTokens: 100,
      systemContent: "System",
      userContent: "User",
      responseJsonSchema: {
        type: "object",
        properties: {},
        additionalProperties: false,
      },
    };
    await expect(
      requestTextCompletion({
        ...base,
        endpoint: "https://127.0.0.1/v1/chat/completions",
      }),
    ).rejects.toMatchObject({ code: "MODEL_CONFIGURATION", scope: "system" });
    await expect(
      requestTextCompletion({
        ...base,
        endpoint: "https://provider.example/v1/chat/completions",
        fetchImpl: async () => new Response(null, { status: 302 }),
        resolveAddresses: async () => ["93.184.216.34"],
      }),
    ).rejects.toMatchObject({ code: "MODEL_PROVIDER", scope: "system" });
  });
});
