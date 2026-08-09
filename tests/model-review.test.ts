import { describe, expect, test, vi } from "vitest";

import { requestTextCompletion } from "../src/model/openai-compatible-client.js";

describe("OpenAI-compatible contextual-review transport", () => {
  test("uses the strict modern Chat Completions contract", async () => {
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
    const responseJsonSchema = {
      name: "contextual_review",
      schema: {
        type: "object",
        properties: { status: { type: "string" } },
        required: ["status"],
        additionalProperties: false,
      },
    };

    const result = await requestTextCompletion({
      endpoint,
      apiKey: " test-key ",
      model: "deepseek/deepseek-v4-flash-0731:thinking",
      maxOutputTokens: 8_192,
      systemContent: "Trusted review policy.",
      userContent: "Delimited untrusted evidence.",
      responseJsonSchema,
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
        { role: "developer", content: "Trusted review policy." },
        { role: "user", content: "Delimited untrusted evidence." },
      ],
      stream: false,
      max_completion_tokens: 8_192,
      reasoning_effort: "low",
      store: false,
      response_format: {
        type: "json_schema",
        json_schema: { ...responseJsonSchema, strict: true },
      },
    });
    expect(result).toMatchObject({
      content: '{"status":"complete"}',
      usage: { inputTokens: 100, outputTokens: 30, reasoningTokens: 20 },
    });
    expect(JSON.stringify(result)).not.toContain("private chain of thought");
  });

  test("does not downgrade strict JSON Schema after rejection", async () => {
    const fetchImpl = vi
      .fn<typeof fetch>()
      .mockResolvedValue(new Response(null, { status: 400 }));

    await expect(
      requestTextCompletion({
        endpoint: "https://provider.example/v1/chat/completions",
        apiKey: "test-key",
        model: "configured/model",
        maxOutputTokens: 100,
        systemContent: "System",
        userContent: "User",
        responseJsonSchema: {
          name: "contextual_review",
          schema: { type: "object" },
        },
        fetchImpl,
        resolveAddresses: async () => ["93.184.216.34"],
      }),
    ).rejects.toMatchObject({ code: "MODEL_PROVIDER", httpStatus: 400 });

    expect(fetchImpl).toHaveBeenCalledOnce();
    expect(
      JSON.parse(String(fetchImpl.mock.calls[0]?.[1]?.body)).response_format,
    ).toMatchObject({ type: "json_schema" });
  });

  test.each([
    [401, "MODEL_AUTHENTICATION"],
    [429, "MODEL_QUOTA"],
    [500, "MODEL_PROVIDER"],
  ] as const)(
    "does not retry non-format HTTP %i failures",
    async (status, code) => {
      const fetchImpl = vi
        .fn<typeof fetch>()
        .mockResolvedValue(new Response(null, { status }));

      await expect(
        requestTextCompletion({
          endpoint: "https://provider.example/v1/chat/completions",
          apiKey: "test-key",
          model: "configured/model",
          maxOutputTokens: 100,
          systemContent: "System",
          userContent: "User",
          responseJsonSchema: {
            name: "contextual_review",
            schema: { type: "object" },
          },
          fetchImpl,
          resolveAddresses: async () => ["93.184.216.34"],
        }),
      ).rejects.toMatchObject({ code });

      expect(fetchImpl).toHaveBeenCalledOnce();
    },
  );

  test("accepts beta providers that return final text as content parts", async () => {
    const result = await requestTextCompletion({
      endpoint: "https://provider.example/v1/chat/completions",
      apiKey: "test-key",
      model: "beta/model:thinking",
      maxOutputTokens: 1_000,
      systemContent: "System",
      userContent: "User",
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

  test("separates response-origin and model-identity boundary failures", async () => {
    const base = {
      endpoint: "https://provider.example/v1/chat/completions",
      apiKey: "test-key",
      model: "configured/model",
      maxOutputTokens: 100,
      systemContent: "System",
      userContent: "User",
      resolveAddresses: async () => ["93.184.216.34"],
    };
    const responseBody = (model = "configured/model") =>
      JSON.stringify({
        id: "chatcmpl-boundary",
        model,
        choices: [
          {
            message: { content: '{"status":"complete"}' },
            finish_reason: "stop",
          },
        ],
        usage: { input_tokens: 1, output_tokens: 1 },
      });

    const wrongOrigin = new Response(responseBody(), { status: 200 });
    Object.defineProperty(wrongOrigin, "url", {
      value: "https://unexpected.example/v1/chat/completions",
    });
    await expect(
      requestTextCompletion({
        ...base,
        fetchImpl: async () => wrongOrigin,
      }),
    ).rejects.toMatchObject({
      code: "MODEL_RESPONSE_ORIGIN",
      scope: "system",
    });

    await expect(
      requestTextCompletion({
        ...base,
        fetchImpl: async () =>
          new Response(responseBody("unexpected/model"), { status: 200 }),
      }),
    ).rejects.toMatchObject({
      code: "MODEL_IDENTITY_MISMATCH",
      scope: "system",
    });
  });
});
