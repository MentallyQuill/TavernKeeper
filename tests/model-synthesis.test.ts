import { describe, expect, test } from "vitest";

import type { Finding } from "../src/contracts/reports.js";
import { synthesizeFindings } from "../src/model/synthesis.js";

function finding(origin: string, fingerprint: string): Finding {
  return {
    origin,
    rule_id: "credential-flow",
    category: "credential-theft",
    severity: "high",
    confidence: "high",
    path: "src/index.ts",
    line_start: 1,
    line_end: 2,
    evidence_sha: null,
    title: "Credential flow",
    explanation: "Original explanation.",
    fingerprint,
    disposition: "active",
  };
}

describe("final model synthesis", () => {
  test("can annotate findings but cannot remove or rewrite deterministic evidence", async () => {
    const deterministic = finding("opengrep", "a".repeat(64));
    const model = finding("model:nano-gpt-com", "b".repeat(64));
    const result = await synthesizeFindings({
      deterministicFindings: [deterministic],
      modelFindings: [model],
      relationships: [
        { from: "src/index.ts", to: "src/net.ts", kind: "imports" },
      ],
      requestCompletion: async () => ({
        completionId: "synthesis-1",
        endpointOrigin: "https://nano-gpt.com",
        provider: "nano-gpt.com",
        content: JSON.stringify({
          annotations: [
            {
              fingerprint: deterministic.fingerprint,
              explanation: "The deterministic evidence remains review-worthy.",
            },
          ],
        }),
        usage: {
          inputTokens: 10,
          outputTokens: 2,
          cacheReadTokens: 0,
          reasoningTokens: 0,
        },
      }),
      request: {
        endpoint: "https://nano-gpt.com/api/v1/chat/completions",
        apiKey: "test-key",
        model: "deepseek/deepseek-v4-flash",
        maxOutputTokens: 100,
      },
    });

    expect(result.findings).toHaveLength(2);
    expect(result.findings[0]).toMatchObject({
      origin: deterministic.origin,
      severity: deterministic.severity,
      confidence: deterministic.confidence,
      path: deterministic.path,
      line_start: deterministic.line_start,
      fingerprint: deterministic.fingerprint,
      explanation: "The deterministic evidence remains review-worthy.",
    });
    expect(result.usage.inputTokens).toBe(10);
  });
});
