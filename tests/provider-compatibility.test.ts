import { describe, expect, test, vi } from "vitest";

import { checkModelProviderCompatibility } from "../src/model/provider-check.js";

function compatibleResponse(content: string) {
  return new Response(
    JSON.stringify({
      id: "chatcmpl-contextual-compatibility",
      model: "configured/model:thinking",
      choices: [{ message: { content }, finish_reason: "stop" }],
      usage: {
        prompt_tokens: 120,
        completion_tokens: 80,
        reasoning_tokens: 30,
      },
    }),
    { status: 200 },
  );
}

describe("model provider contextual compatibility check", () => {
  test("validates a multi-assessment contextual review using Bearer authentication", async () => {
    const candidateIds = ["c", "d", "e", "f"].map((value) => value.repeat(64));
    const content = JSON.stringify({
      review: {
        status: "complete",
        assessments: candidateIds.map((candidateId) => ({
          candidate_id: candidateId,
          evidence_ids: [candidateId],
          disposition: "expected_behavior",
          impact: "none",
          exploitability: "unlikely",
          confidence: "high",
          risk_exposure: "not_demonstrated",
          recommended_risk: "low",
          technical_explanation:
            "The credential-like word appears only in explanatory documentation.",
          layman_explanation:
            "This is documentation, not code handling a real credential.",
          developer_action: "none",
        })),
        observations: [],
      },
    });
    const fetchImpl = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(compatibleResponse('{"status":"ok"}'))
      .mockResolvedValueOnce(compatibleResponse(content))
      .mockResolvedValueOnce(compatibleResponse(content));

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
      contextualReview: "passed",
    });

    expect(fetchImpl).toHaveBeenCalledTimes(3);
    const baselineRequest = fetchImpl.mock.calls[0]!;
    const unionRequest = fetchImpl.mock.calls[1]!;
    const finalRequest = fetchImpl.mock.calls[2]!;
    const baselineBody = JSON.parse(String(baselineRequest[1]?.body));
    expect(baselineBody.response_format).toMatchObject({
      type: "json_schema",
      json_schema: {
        name: "tavernkeeper_provider_baseline",
        strict: true,
        schema: {
          type: "object",
          required: ["status"],
          additionalProperties: false,
        },
      },
    });
    expect(unionRequest[1]?.headers).toMatchObject({
      Authorization: "Bearer test-key",
    });
    expect(finalRequest[1]?.headers).toMatchObject({
      Authorization: "Bearer test-key",
    });
    const unionBody = JSON.parse(String(unionRequest[1]?.body));
    const finalBody = JSON.parse(String(finalRequest[1]?.body));
    expect(unionBody).toMatchObject({
      max_completion_tokens: 8_192,
      reasoning_effort: "low",
      store: false,
    });
    expect(unionBody).not.toHaveProperty("temperature");
    expect(unionBody).not.toHaveProperty("max_tokens");
    expect(unionBody.messages[0]).toMatchObject({ role: "system" });
    expect(unionBody.response_format).toMatchObject({
      type: "json_schema",
      json_schema: {
        name: "tavernkeeper_contextual_review",
        strict: true,
        schema: {
          type: "object",
          properties: { review: { anyOf: expect.any(Array) } },
          required: ["review"],
          additionalProperties: false,
        },
      },
    });
    expect(JSON.stringify(unionBody.response_format)).toContain(
      "needs_more_context",
    );
    expect(JSON.stringify(finalBody.response_format)).not.toContain(
      "needs_more_context",
    );
    for (const candidateId of candidateIds)
      expect(unionBody.messages[1].content).toContain(candidateId);
  });

  test("does not downgrade the compatibility probe from strict JSON Schema", async () => {
    const fetchImpl = vi
      .fn<typeof fetch>()
      .mockResolvedValue(new Response(null, { status: 400 }));

    await expect(
      checkModelProviderCompatibility({
        endpoint: "https://provider.example/api/v1/chat/completions",
        apiKey: "test-key",
        model: "configured/model:thinking",
        fetchImpl,
        resolveAddresses: async () => ["93.184.216.34"],
      }),
    ).rejects.toMatchObject({ code: "MODEL_PROVIDER", httpStatus: 400 });

    expect(fetchImpl).toHaveBeenCalledOnce();
    const body = JSON.parse(String(fetchImpl.mock.calls[0]?.[1]?.body));
    expect(body.response_format.type).toBe("json_schema");
  });

  test("distinguishes the contextual contract from a passing baseline", async () => {
    const fetchImpl = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(compatibleResponse('{"status":"ok"}'))
      .mockResolvedValueOnce(new Response(null, { status: 400 }));

    await expect(
      checkModelProviderCompatibility({
        endpoint: "https://provider.example/api/v1/chat/completions",
        apiKey: "test-key",
        model: "configured/model:thinking",
        fetchImpl,
        resolveAddresses: async () => ["93.184.216.34"],
      }),
    ).rejects.toMatchObject({
      code: "MODEL_PROVIDER",
      diagnostic: "provider_contextual_contract_rejected",
      httpStatus: 400,
    });
    expect(fetchImpl).toHaveBeenCalledTimes(2);
  });

  test("rejects an incomplete local assessment schema without returning model text", async () => {
    const fetchImpl = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(compatibleResponse('{"status":"ok"}'))
      .mockImplementation(async () =>
        compatibleResponse('{"status":"complete"}'),
      );

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
    });
    expect(fetchImpl).toHaveBeenCalledTimes(3);
  });

  test("rejects a valid domain response when the provider ignores the wire envelope", async () => {
    const candidateIds = ["c", "d", "e", "f"].map((value) => value.repeat(64));
    const content = JSON.stringify({
      status: "complete",
      assessments: candidateIds.map((candidateId) => ({
        candidate_id: candidateId,
        evidence_ids: [candidateId],
        disposition: "expected_behavior",
        impact: "none",
        exploitability: "unlikely",
        confidence: "high",
        risk_exposure: "not_demonstrated",
        recommended_risk: "low",
        technical_explanation:
          "The credential-like word appears only in explanatory documentation.",
        layman_explanation:
          "This is documentation, not code handling a real credential.",
        developer_action: "none",
      })),
      observations: [],
    });
    const fetchImpl = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(compatibleResponse('{"status":"ok"}'))
      .mockImplementation(async () => compatibleResponse(content));

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
      diagnostic: "review_schema",
    });
    expect(fetchImpl).toHaveBeenCalledTimes(3);
  });
});
