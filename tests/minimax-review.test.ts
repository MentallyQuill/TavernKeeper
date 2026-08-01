import { describe, expect, test, vi } from "vitest";

import { FindingSchema } from "../src/contracts/reports.js";
import { reviewEvidence } from "../src/model/minimax-review.js";

const file = {
  path: "src/index.ts",
  bytes: 120,
  sha256: "a".repeat(64),
  kind: "text" as const,
  content:
    'const key = "ghp_abcdefghijklmnopqrstuvwxyz1234567890";\nfetch("https://example.invalid");',
};

describe("MiniMax evidence review", () => {
  test("does not call the provider when model review is disabled", async () => {
    const fetchImpl = vi.fn();
    const result = await reviewEvidence({
      enabled: false,
      apiKey: null,
      baseUrl: "https://api.minimax.io/v1",
      model: "MiniMax-M3",
      mode: "standard",
      files: [file],
      deterministicFindings: [],
      maxFiles: 10,
      maxCharsPerFile: 10_000,
      maxInputChars: 50_000,
      maxOutputTokens: 1_000,
      fetchImpl,
    });

    expect(result).toEqual({
      ok: true,
      value: {
        status: "disabled",
        provider: null,
        model: null,
        findings: [],
      },
    });
    expect(fetchImpl).not.toHaveBeenCalled();
  });

  test("sends bounded redacted evidence and validates structured findings", async () => {
    const fetchImpl = vi.fn(
      async (_url: string | URL | Request, init?: RequestInit) => {
        if (!init) throw new Error("Expected request options.");
        const body = JSON.parse(String(init.body)) as Record<string, unknown>;
        expect(JSON.stringify(body)).not.toContain(
          "ghp_abcdefghijklmnopqrstuvwxyz1234567890",
        );
        expect(body).toMatchObject({
          model: "MiniMax-M3",
          temperature: 0,
          max_completion_tokens: 1_000,
        });
        return new Response(
          JSON.stringify({
            choices: [
              {
                message: {
                  content: JSON.stringify({
                    findings: [
                      {
                        rule_id: "suspicious-network",
                        category: "network-exfiltration",
                        severity: "medium",
                        confidence: "medium",
                        path: "src/index.ts",
                        line_start: 2,
                        line_end: 2,
                        title: "Suspicious network destination",
                        explanation: "Outbound request deserves manual review.",
                      },
                    ],
                  }),
                },
              },
            ],
          }),
          { status: 200, headers: { "content-type": "application/json" } },
        );
      },
    );

    const result = await reviewEvidence({
      enabled: true,
      apiKey: "model-secret",
      baseUrl: "https://api.minimax.io/v1/",
      model: "MiniMax-M3",
      mode: "deep",
      files: [file],
      deterministicFindings: [],
      maxFiles: 10,
      maxCharsPerFile: 10_000,
      maxInputChars: 50_000,
      maxOutputTokens: 1_000,
      fetchImpl,
    });

    expect(result).toMatchObject({
      ok: true,
      value: {
        status: "completed",
        provider: "minimax",
        model: "MiniMax-M3",
        findings: [
          {
            origin: "model:minimax",
            rule_id: "suspicious-network",
            path: "src/index.ts",
          },
        ],
      },
    });
    expect(
      result.ok &&
        result.value.findings.every(
          (finding) => FindingSchema.safeParse(finding).success,
        ),
    ).toBe(true);
  });

  test("rejects malformed provider output", async () => {
    const result = await reviewEvidence({
      enabled: true,
      apiKey: "model-secret",
      baseUrl: "https://api.minimax.io/v1",
      model: "MiniMax-M3",
      mode: "standard",
      files: [file],
      deterministicFindings: [],
      maxFiles: 1,
      maxCharsPerFile: 1_000,
      maxInputChars: 2_000,
      maxOutputTokens: 100,
      fetchImpl: async () =>
        new Response(
          JSON.stringify({ choices: [{ message: { content: "no" } }] }),
        ),
    });

    expect(result).toMatchObject({
      ok: false,
      error: { code: "INVALID_RESPONSE" },
    });
  });
});
