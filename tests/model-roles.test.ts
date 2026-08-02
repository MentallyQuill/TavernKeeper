import { describe, expect, test, vi } from "vitest";

import type { Finding } from "../src/contracts/reports.js";
import { InMemoryModelChunkCache } from "../src/model/chunk-cache.js";
import type { ModelChunk } from "../src/model/chunker.js";
import type { StructuredCompletionRequest } from "../src/model/openai-compatible-client.js";
import { reviewWithConfiguredModel } from "../src/model/model-review.js";

const targetSha = "a".repeat(40);
const content = "const endpoint = 'https://example.test';\n";
const chunk: ModelChunk = {
  id: "b".repeat(64),
  bytes: Buffer.byteLength(content),
  content_hashes: ["c".repeat(64)],
  segments: [
    {
      path: "src/index.ts",
      line_start: 1,
      line_end: 1,
      content,
      bytes: Buffer.byteLength(content),
      overlap_bytes: 0,
      content_hash: "c".repeat(64),
      source_sha256: "d".repeat(64),
    },
  ],
};
const deterministicFinding: Finding = {
  origin: "opengrep",
  rule_id: "credential-exfiltration",
  category: "credential-theft",
  severity: "high",
  confidence: "high",
  path: "src/index.ts",
  line_start: 1,
  line_end: 1,
  evidence_sha: null,
  title: "Credential access followed by a network request",
  explanation: "A deterministic rule matched this data flow.",
  fingerprint: "e".repeat(64),
  disposition: "active",
};

function spec(
  requestCompletion: (request: StructuredCompletionRequest) => Promise<any>,
) {
  return {
    endpoint: "https://provider.example/v1/chat/completions",
    apiKey: "test-api-key",
    model: "vendor/model-test",
    targetSha,
    projectKinds: ["extension"] as const,
    chunks: [chunk],
    deterministicFindings: [deterministicFinding],
    relationships: [],
    promptPolicyVersion: "2",
    scannerPolicyVersion: "1",
    rolePolicies: {
      analyzer: "analyzer-v1",
      challenger: "challenger-v1",
      arbiter: "arbiter-v1",
    },
    maxOutputTokensPerRole: 8_192,
    cache: new InMemoryModelChunkCache(),
    requestCompletion,
  };
}

describe("automated model roles", () => {
  test("runs analyzer, challenger, and arbiter with isolated bounded inputs", async () => {
    const calls: StructuredCompletionRequest[] = [];
    const provider = vi.fn(async (request: StructuredCompletionRequest) => {
      calls.push(request);
      const input = JSON.parse(request.userContent) as any;
      const payload = request.schemaName.endsWith("analyzer")
        ? {
            assessments: input.deterministic_findings.map((finding: any) => ({
              fingerprint: finding.fingerprint,
              evidence: finding.evidence,
              assessment: "concerning",
              rationale:
                "The deterministic signal warrants adversarial review.",
            })),
            discoveries: [],
          }
        : request.schemaName.endsWith("challenger")
          ? {
              challenges: input.claims.map((claim: any) => ({
                fingerprint: claim.fingerprint,
                evidence: claim.evidence,
                position: "disputes",
                rationale: "The cited line is only a constant declaration.",
              })),
            }
          : {
              decisions: input.claims.map((claim: any) => ({
                fingerprint: claim.fingerprint,
                evidence: claim.evidence,
                disposition: "not-supported",
                rationale: "The evidence does not support malicious behavior.",
              })),
            };
      return {
        completionId: `completion-${calls.length}`,
        endpointOrigin: "https://provider.example",
        provider: "provider.example",
        content: JSON.stringify(payload),
        usage: {
          inputTokens: 100,
          outputTokens: 20,
          cacheReadTokens: 10,
          reasoningTokens: 5,
        },
      };
    });

    const result = await reviewWithConfiguredModel(spec(provider));

    expect(calls.map(({ schemaName }) => schemaName)).toEqual([
      "tavernkeeper_analyzer",
      "tavernkeeper_challenger",
      "tavernkeeper_arbiter",
    ]);
    expect(result.findings).toMatchObject([
      {
        fingerprint: deterministicFinding.fingerprint,
        disposition: "not-supported",
        automated_review: {
          analyzer_policy: "analyzer-v1",
          challenger_policy: "challenger-v1",
          arbiter_policy: "arbiter-v1",
        },
      },
    ]);
    expect(result.roleCompletion).toEqual({
      analyzer: { required: 1, completed: 1 },
      challenger: { required: 1, completed: 1 },
      arbiter: { required: 1, completed: 1 },
    });
    expect(result.usage).toEqual({
      inputTokens: 300,
      outputTokens: 60,
      cacheReadTokens: 30,
      reasoningTokens: 15,
    });
    expect(
      calls.every((call) => !call.userContent.includes("test-api-key")),
    ).toBe(true);
    expect(
      calls.slice(1).every((call) => !call.userContent.includes(content)),
    ).toBe(true);
  });

  test("uses the preset threat policy without changing deterministic coverage", async () => {
    const systems: string[] = [];
    const provider = vi.fn(async (request: StructuredCompletionRequest) => {
      systems.push(request.systemContent);
      const input = JSON.parse(request.userContent) as any;
      const payload = request.schemaName.endsWith("analyzer")
        ? {
            assessments: input.deterministic_findings.map((finding: any) => ({
              fingerprint: finding.fingerprint,
              evidence: finding.evidence,
              assessment: "not-supported",
              rationale: "No malicious behavior is supported.",
            })),
            discoveries: [],
          }
        : request.schemaName.endsWith("challenger")
          ? {
              challenges: input.claims.map((claim: any) => ({
                fingerprint: claim.fingerprint,
                evidence: claim.evidence,
                position: "supports",
                rationale: "The not-supported assessment is well grounded.",
              })),
            }
          : {
              decisions: input.claims.map((claim: any) => ({
                fingerprint: claim.fingerprint,
                evidence: claim.evidence,
                disposition: "not-supported",
                rationale: "The evidence is benign.",
              })),
            };
      return {
        completionId: "completion-1",
        endpointOrigin: "https://provider.example",
        provider: "provider.example",
        content: JSON.stringify(payload),
        usage: {
          inputTokens: 1,
          outputTokens: 1,
          cacheReadTokens: 0,
          reasoningTokens: 0,
        },
      };
    });

    await reviewWithConfiguredModel({
      ...spec(provider),
      projectKinds: ["preset"],
    });

    expect(systems[0]).toMatch(
      /endpoints.*headers.*request bodies.*prompt manipulation.*regex.*obfuscation.*external downloads.*bundled executables/iu,
    );
  });

  test("fails closed when the analyzer omits deterministic evidence", async () => {
    const provider = vi.fn(async () => ({
      completionId: "completion-1",
      endpointOrigin: "https://provider.example",
      provider: "provider.example",
      content: JSON.stringify({ assessments: [], discoveries: [] }),
      usage: {
        inputTokens: 1,
        outputTokens: 1,
        cacheReadTokens: 0,
        reasoningTokens: 0,
      },
    }));

    await expect(
      reviewWithConfiguredModel(spec(provider)),
    ).rejects.toMatchObject({
      code: "MODEL_INVALID_RESPONSE",
      scope: "repository",
      diagnostic: "role_schema_analyzer",
    });
    expect(provider).toHaveBeenCalledTimes(1);
  });

  test("identifies review-level inconclusive findings without exposing model content", async () => {
    const provider = vi.fn(async (request: StructuredCompletionRequest) => {
      const input = JSON.parse(request.userContent) as any;
      const payload = request.schemaName.endsWith("analyzer")
        ? {
            assessments: input.deterministic_findings.map((finding: any) => ({
              fingerprint: finding.fingerprint,
              evidence: finding.evidence,
              assessment: "concerning",
              rationale: "The deterministic signal requires review.",
            })),
            discoveries: [],
          }
        : request.schemaName.endsWith("challenger")
          ? {
              challenges: input.claims.map((claim: any) => ({
                fingerprint: claim.fingerprint,
                evidence: claim.evidence,
                position: "disputes",
                rationale: "The evidence is ambiguous.",
              })),
            }
          : {
              decisions: input.claims.map((claim: any) => ({
                fingerprint: claim.fingerprint,
                evidence: claim.evidence,
                disposition: "inconclusive",
                rationale: "The available evidence cannot resolve the claim.",
              })),
            };
      return {
        completionId: `completion-${provider.mock.calls.length}`,
        endpointOrigin: "https://provider.example",
        provider: "provider.example",
        content: JSON.stringify(payload),
        usage: {
          inputTokens: 1,
          outputTokens: 1,
          cacheReadTokens: 0,
          reasoningTokens: 0,
        },
      };
    });

    await expect(
      reviewWithConfiguredModel(spec(provider)),
    ).rejects.toMatchObject({
      code: "MODEL_INVALID_RESPONSE",
      scope: "repository",
      diagnostic: "review_inconclusive",
    });
  });

  test("identifies duplicate final findings without exposing model content", async () => {
    const secondChunk: ModelChunk = {
      ...chunk,
      id: "f".repeat(64),
    };
    const provider = vi.fn(async (request: StructuredCompletionRequest) => {
      const input = JSON.parse(request.userContent) as any;
      const payload = request.schemaName.endsWith("analyzer")
        ? {
            assessments: [],
            discoveries: [
              {
                rule_id: "duplicate-discovery",
                category: "credential-theft",
                severity: "high",
                confidence: "high",
                title: "Repeated normalized discovery",
                explanation: "The same normalized finding appears twice.",
                remediation: null,
                evidence: {
                  path: input.segments[0].path,
                  line_start: input.segments[0].line_start,
                  line_end: input.segments[0].line_end,
                  segment_id: input.segments[0].segment_id,
                  content_digest: input.segments[0].content_digest,
                  target_sha: input.target_sha,
                },
                assessment: "not-supported",
                rationale: "The discovery is not supported.",
              },
            ],
          }
        : request.schemaName.endsWith("challenger")
          ? {
              challenges: input.claims.map((claim: any) => ({
                fingerprint: claim.fingerprint,
                evidence: claim.evidence,
                position: "supports",
                rationale: "The assessment is grounded.",
              })),
            }
          : {
              decisions: input.claims.map((claim: any) => ({
                fingerprint: claim.fingerprint,
                evidence: claim.evidence,
                disposition: "not-supported",
                rationale: "The evidence is benign.",
              })),
            };
      return {
        completionId: `completion-${provider.mock.calls.length}`,
        endpointOrigin: "https://provider.example",
        provider: "provider.example",
        content: JSON.stringify(payload),
        usage: {
          inputTokens: 1,
          outputTokens: 1,
          cacheReadTokens: 0,
          reasoningTokens: 0,
        },
      };
    });

    await expect(
      reviewWithConfiguredModel({
        ...spec(provider),
        chunks: [chunk, secondChunk],
        deterministicFindings: [],
      }),
    ).rejects.toMatchObject({
      code: "MODEL_INVALID_RESPONSE",
      scope: "repository",
      diagnostic: "review_duplicate_findings",
    });
  });

  test("resumes from sanitized role cache without repeating provider calls", async () => {
    const cache = new InMemoryModelChunkCache();
    const provider = vi.fn(async (request: StructuredCompletionRequest) => {
      const input = JSON.parse(request.userContent) as any;
      const payload = request.schemaName.endsWith("analyzer")
        ? {
            assessments: input.deterministic_findings.map((finding: any) => ({
              fingerprint: finding.fingerprint,
              evidence: finding.evidence,
              assessment: "not-supported",
              rationale:
                "The signal is not supported by the submitted context.",
            })),
            discoveries: [],
          }
        : request.schemaName.endsWith("challenger")
          ? {
              challenges: input.claims.map((claim: any) => ({
                fingerprint: claim.fingerprint,
                evidence: claim.evidence,
                position: "supports",
                rationale: "The analyzer assessment is grounded.",
              })),
            }
          : {
              decisions: input.claims.map((claim: any) => ({
                fingerprint: claim.fingerprint,
                evidence: claim.evidence,
                disposition: "not-supported",
                rationale: "The evidence is not concerning.",
              })),
            };
      return {
        completionId: `completion-${provider.mock.calls.length}`,
        endpointOrigin: "https://provider.example",
        provider: "provider.example",
        content: JSON.stringify(payload),
        usage: {
          inputTokens: 10,
          outputTokens: 2,
          cacheReadTokens: 0,
          reasoningTokens: 0,
        },
      };
    });

    await reviewWithConfiguredModel({ ...spec(provider), cache });
    const secondProvider = vi.fn();
    const resumed = await reviewWithConfiguredModel({
      ...spec(secondProvider),
      cache,
    });

    expect(provider).toHaveBeenCalledTimes(3);
    expect(secondProvider).not.toHaveBeenCalled();
    expect(resumed).toMatchObject({
      cacheHits: 3,
      cacheMisses: 0,
      usage: {
        inputTokens: 0,
        outputTokens: 0,
        cacheReadTokens: 0,
        reasoningTokens: 0,
      },
    });
  });
});
