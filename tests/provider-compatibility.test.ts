import { describe, expect, test, vi } from "vitest";

import { checkModelProviderCompatibility } from "../src/model/provider-check.js";

function compatibleResponse(content: string) {
  return new Response(
    JSON.stringify({
      id: "chatcmpl-compatibility",
      choices: [
        {
          message: { content, reasoning: "not part of the checked result" },
          finish_reason: "stop",
        },
      ],
      usage: {
        prompt_tokens: 20,
        completion_tokens: 30,
        reasoning_tokens: 25,
      },
    }),
    { status: 200 },
  );
}

describe("model provider compatibility check", () => {
  test("validates text review and strict synthesis after Bearer connectivity", async () => {
    const fetchImpl = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(new Response(null, { status: 200 }))
      .mockResolvedValueOnce(
        compatibleResponse("No review-level concern appears in this chunk."),
      )
      .mockResolvedValueOnce(
        compatibleResponse(
          '{"assessment":"no_concerning_evidence","recap":"The compatibility review found no review-level concern.","concerns":[]}',
        ),
      );

    await expect(
      checkModelProviderCompatibility({
        endpoint: "https://provider.example/api/v1/chat/completions",
        apiKey: "test-key",
        model: "configured/model:thinking",
        fetchImpl,
        resolveAddresses: async () => ["93.184.216.34"],
      }),
    ).resolves.toEqual({
      status: "passed",
      authMode: "bearer",
      textReview: "passed",
      structuredOutput: "passed",
    });

    expect(fetchImpl).toHaveBeenCalledTimes(3);
    const textRequest = JSON.parse(String(fetchImpl.mock.calls[1]?.[1]?.body));
    expect(textRequest).not.toHaveProperty("response_format");
    expect(textRequest.messages[1].content).toContain("source-000001");
    const structuredRequest = JSON.parse(
      String(fetchImpl.mock.calls[2]?.[1]?.body),
    );
    expect(structuredRequest).toMatchObject({
      model: "configured/model:thinking",
      max_tokens: 8_192,
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "tavernkeeper_repository_synthesis",
          strict: true,
        },
      },
    });
  });

  test("classifies synthesis-schema incompatibility without returning model text", async () => {
    const fetchImpl = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(new Response(null, { status: 200 }))
      .mockResolvedValueOnce(
        compatibleResponse("No review-level concern appears in this chunk."),
      )
      .mockResolvedValueOnce(compatibleResponse("{}"));

    await expect(
      checkModelProviderCompatibility({
        endpoint: "https://provider.example/api/v1/chat/completions",
        apiKey: "test-key",
        model: "configured/model:thinking",
        fetchImpl,
        resolveAddresses: async () => ["93.184.216.34"],
      }),
    ).rejects.toMatchObject({
      code: "MODEL_INVALID_RESPONSE",
      scope: "repository",
      diagnostic: "synthesis_schema",
    });
  });
});
