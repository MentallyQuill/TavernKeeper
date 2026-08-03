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
  test("validates one complete contextual review using Bearer authentication", async () => {
    const candidateId = "c".repeat(64);
    const fetchImpl = vi.fn<typeof fetch>().mockResolvedValueOnce(
      compatibleResponse(
        JSON.stringify({
          status: "complete",
          assessments: [
            {
              candidate_id: candidateId,
              evidence_ids: [candidateId],
              disposition: "expected_behavior",
              impact: "none",
              exploitability: "unlikely",
              confidence: "high",
              recommended_risk: "low",
              technical_explanation:
                "The credential-like word appears only in explanatory documentation.",
              layman_explanation:
                "This is documentation, not code handling a real credential.",
              developer_action: "none",
              locations: [{ path: "README.md", line_start: 1, line_end: 1 }],
            },
          ],
          observations: [],
        }),
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
      contextualReview: "passed",
    });

    expect(fetchImpl).toHaveBeenCalledOnce();
    const request = fetchImpl.mock.calls[0]!;
    expect(request[1]?.headers).toMatchObject({
      Authorization: "Bearer test-key",
    });
    const body = JSON.parse(String(request[1]?.body));
    expect(body).not.toHaveProperty("response_format");
    expect(body.messages[1].content).toContain(candidateId);
  });

  test("rejects an incomplete local assessment schema without returning model text", async () => {
    const fetchImpl = vi
      .fn<typeof fetch>()
      .mockResolvedValueOnce(compatibleResponse('{"status":"complete"}'));

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
  });
});
