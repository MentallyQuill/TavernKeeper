import { describe, expect, test, vi } from "vitest";

import {
  createGithubActionsSubjectTokenProvider,
  createOpenAIRequestCompletion,
  createOpenAIWorkloadIdentityProvider,
  OPENAI_REVIEW_ENDPOINT,
  OPENAI_REVIEW_MODEL,
} from "../src/model/openai-workload-identity.js";

const environment = {
  OPENAI_WIF_AUDIENCE: "openai://tavernkeeper",
  OPENAI_IDENTITY_PROVIDER_ID: "wip_test",
  OPENAI_SERVICE_ACCOUNT_ID: "svc_test",
  ACTIONS_ID_TOKEN_REQUEST_URL:
    "https://pipelines.actions.githubusercontent.com/token?job=scan",
  ACTIONS_ID_TOKEN_REQUEST_TOKEN: "github-runtime-token",
};

describe("OpenAI GitHub Actions workload identity", () => {
  test("obtains a GitHub OIDC subject token for the configured audience", async () => {
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValue(
      new Response(JSON.stringify({ value: "signed-github-oidc-token" }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      }),
    );

    const provider = createGithubActionsSubjectTokenProvider(
      environment,
      fetchImpl,
    );

    await expect(provider.getToken()).resolves.toBe("signed-github-oidc-token");
    expect(provider.tokenType).toBe("jwt");
    expect(fetchImpl).toHaveBeenCalledOnce();
    const [url, init] = fetchImpl.mock.calls[0]!;
    expect(String(url)).toBe(
      "https://pipelines.actions.githubusercontent.com/token?job=scan&audience=openai%3A%2F%2Ftavernkeeper",
    );
    expect(init).toMatchObject({
      method: "GET",
      redirect: "error",
      headers: { Authorization: "Bearer github-runtime-token" },
    });
  });

  test("builds a fixed Luna provider without an API key or mutable endpoint", () => {
    const createClient = vi.fn(() => ({
      chat: { completions: { create: vi.fn() } },
    }));

    const provider = createOpenAIWorkloadIdentityProvider(environment, {
      createClient,
    });

    expect(provider).toMatchObject({
      endpoint: OPENAI_REVIEW_ENDPOINT,
      model: OPENAI_REVIEW_MODEL,
    });
    expect(provider.apiKey).toBe("github-actions-oidc");
    expect(provider.requestCompletion).toBeTypeOf("function");
    expect(createClient).toHaveBeenCalledWith({
      identityProviderId: "wip_test",
      serviceAccountId: "svc_test",
      provider: expect.objectContaining({ tokenType: "jwt" }),
    });
  });

  test("requests only strict JSON Schema from Luna with bounded low reasoning", async () => {
    const create = vi.fn().mockResolvedValue({
      id: "chatcmpl_luna_test",
      model: OPENAI_REVIEW_MODEL,
      choices: [
        {
          finish_reason: "stop",
          message: { content: '{"review":{"status":"complete"}}' },
        },
      ],
      usage: {
        prompt_tokens: 100,
        completion_tokens: 40,
        prompt_tokens_details: { cached_tokens: 25 },
        completion_tokens_details: { reasoning_tokens: 10 },
      },
    });
    const request = createOpenAIRequestCompletion({
      chat: { completions: { create } },
    });

    await expect(
      request({
        endpoint: OPENAI_REVIEW_ENDPOINT,
        apiKey: "github-actions-oidc",
        model: OPENAI_REVIEW_MODEL,
        maxOutputTokens: 16_384,
        maxResponseBytes: 1_000_000,
        timeoutMs: 120_000,
        systemContent: "system",
        userContent: "evidence",
        responseJsonSchema: {
          name: "tavernkeeper_contextual_review",
          schema: {
            type: "object",
            properties: {},
            additionalProperties: false,
          },
        },
      }),
    ).resolves.toEqual({
      completionId: "chatcmpl_luna_test",
      endpointOrigin: "https://api.openai.com",
      provider: "api.openai.com",
      content: '{"review":{"status":"complete"}}',
      usage: {
        inputTokens: 100,
        outputTokens: 40,
        cacheReadTokens: 25,
        reasoningTokens: 10,
      },
    });

    expect(create).toHaveBeenCalledOnce();
    expect(create.mock.calls[0]![0]).toEqual({
      model: OPENAI_REVIEW_MODEL,
      messages: [
        { role: "system", content: "system" },
        { role: "user", content: "evidence" },
      ],
      stream: false,
      store: false,
      reasoning_effort: "low",
      max_completion_tokens: 16_384,
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "tavernkeeper_contextual_review",
          strict: true,
          schema: {
            type: "object",
            properties: {},
            additionalProperties: false,
          },
        },
      },
    });
    expect(create.mock.calls[0]![1]).toEqual({ timeout: 120_000 });
    expect(JSON.stringify(create.mock.calls[0]![0])).not.toContain(
      "temperature",
    );
    expect(JSON.stringify(create.mock.calls[0]![0])).not.toContain(
      "json_object",
    );
  });

  test("does not downgrade when strict structured output is rejected", async () => {
    const create = vi.fn().mockRejectedValue(
      Object.assign(new Error("unsupported response format"), {
        status: 400,
      }),
    );
    const request = createOpenAIRequestCompletion({
      chat: { completions: { create } },
    });

    await expect(
      request({
        endpoint: OPENAI_REVIEW_ENDPOINT,
        apiKey: "github-actions-oidc",
        model: OPENAI_REVIEW_MODEL,
        maxOutputTokens: 1_000,
        timeoutMs: 1_000,
        systemContent: "system",
        userContent: "evidence",
        responseJsonSchema: {
          name: "review",
          schema: { type: "object", additionalProperties: false },
        },
      }),
    ).rejects.toMatchObject({ code: "MODEL_PROVIDER", httpStatus: 400 });
    expect(create).toHaveBeenCalledOnce();
  });

  test("requires the workload identity and GitHub OIDC configuration", () => {
    expect(() => createOpenAIWorkloadIdentityProvider({})).toThrowError(
      /OPENAI_IDENTITY_PROVIDER_ID/u,
    );
  });
});
