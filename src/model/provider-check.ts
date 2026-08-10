import { createHash } from "node:crypto";

import { z } from "zod";

import { EvidenceContextGroupSchema } from "../context/evidence-context.js";
import { reviewEvidenceGroups } from "./contextual-review.js";
import {
  ModelRequestError,
  requestTextCompletion,
  type ProviderConnectivityRequest,
} from "./openai-compatible-client.js";

const candidateIds = ["c", "d", "e", "f"].map((value) => value.repeat(64));
const source = [
  "The setting is named apiKey; never paste a real credential here.",
  "The word fetch describes how an extension may contact its configured model.",
  "The word eval appears here only as an example of behavior to avoid.",
  "The phrase install script appears in this documentation compatibility fixture.",
  "",
].join("\n");
const fixtureCandidates = [
  {
    origin: "gitleaks",
    rule_id: "documentation-credential-keyword",
    category: "credential-exposure",
    title: "Credential keyword in documentation",
  },
  {
    origin: "opengrep",
    rule_id: "documentation-network-keyword",
    category: "network-access",
    title: "Network keyword in documentation",
  },
  {
    origin: "opengrep",
    rule_id: "documentation-eval-keyword",
    category: "dynamic-execution",
    title: "Dynamic-execution keyword in documentation",
  },
  {
    origin: "malcontent",
    rule_id: "documentation-install-keyword",
    category: "install-hook",
    title: "Install-hook keyword in documentation",
  },
] as const;

export async function checkModelProviderCompatibility(
  request: ProviderConnectivityRequest,
) {
  const baseline = await requestTextCompletion({
    ...request,
    maxOutputTokens: 128,
    systemContent: "Return only the requested strict JSON object.",
    userContent: 'Return {"status":"ok"}.',
    responseJsonSchema: {
      name: "tavernkeeper_provider_baseline",
      schema: {
        type: "object",
        properties: { status: { type: "string", enum: ["ok"] } },
        required: ["status"],
        additionalProperties: false,
      },
    },
  });
  let baselineContent: unknown;
  try {
    baselineContent = JSON.parse(baseline.content);
  } catch {
    throw new ModelRequestError(
      "MODEL_INVALID_RESPONSE",
      "system",
      "Provider baseline returned malformed JSON.",
      "response_json",
    );
  }
  if (
    !z.strictObject({ status: z.literal("ok") }).safeParse(baselineContent)
      .success
  )
    throw new ModelRequestError(
      "MODEL_INVALID_RESPONSE",
      "system",
      "Provider baseline violated its strict JSON contract.",
      "response_json",
    );

  const group = EvidenceContextGroupSchema.parse({
    group_id: "b".repeat(64),
    repository: "tavernkeeper/provider-compatibility",
    project_kinds: ["extension"],
    path: "README.md",
    file_role: "documentation",
    target_sha: "0".repeat(40),
    evidence_sha: "0".repeat(40),
    source_kind: "text",
    source_bytes: Buffer.byteLength(source),
    source_sha256: createHash("sha256").update(source).digest("hex"),
    ecosystem_context_version: "sillytavern-community-v1",
    ecosystem_context: "Trusted ecosystem context.",
    candidates: fixtureCandidates.map((candidate, index) => {
      const candidateId = candidateIds[index]!;
      return {
        candidate_id: candidateId,
        evidence_id: candidateId,
        origin: candidate.origin,
        rule_id: candidate.rule_id,
        category: candidate.category,
        scanner_severity: "low",
        scanner_confidence: "low",
        title: candidate.title,
        explanation:
          "A security-related keyword appears in explanatory documentation.",
        line_start: index + 1,
        line_end: index + 1,
      };
    }),
    context: {
      imports: "",
      source: source
        .trimEnd()
        .split("\n")
        .map((line, index) => `${String(index + 1).padStart(6)} | ${line}`)
        .join("\n"),
      expansions: [
        source
          .trimEnd()
          .split("\n")
          .map((line, index) => `${String(index + 1).padStart(6)} | ${line}`)
          .join("\n"),
      ],
      representations: [
        {
          stage: "raw",
          sha256: createHash("sha256").update(source).digest("hex"),
          transform_depth: 0,
        },
      ],
      project_purpose:
        "A benign compatibility fixture for TavernKeeper contextual review.",
    },
  });
  const runCompatibilityReview = async (maxImmediateAttempts: number) => {
    try {
      return await reviewEvidenceGroups({
        groups: [group],
        provider: {
          endpoint: request.endpoint,
          apiKey: request.apiKey,
          model: request.model,
          ...(request.fetchImpl === undefined
            ? {}
            : { fetchImpl: request.fetchImpl }),
          ...(request.resolveAddresses === undefined
            ? {}
            : { resolveAddresses: request.resolveAddresses }),
        },
        policy: {
          version: "4",
          promptVersion: "contextual-review-v7",
          schemaVersion: "contextual-assessment-v2",
          maxImmediateAttempts,
          maxOutputTokens: 8_192,
          maxResponseBytes: 1_000_000,
          timeoutMs: request.timeoutMs ?? 60_000,
          maxBatchGroups: 5,
          maxBatchInputTokens: 64_000,
        },
      });
    } catch (error) {
      if (
        error instanceof ModelRequestError &&
        error.code === "MODEL_PROVIDER" &&
        error.scope === "system"
      )
        throw new ModelRequestError(
          error.code,
          error.scope,
          "Provider rejected the contextual review contract.",
          "provider_contextual_contract_rejected",
          error.httpStatus,
          error.usage,
        );
      throw error;
    }
  };
  const reviews = [
    await runCompatibilityReview(2),
    await runCompatibilityReview(1),
  ];
  if (
    reviews.some(
      (review) =>
        review.coverage.required !== candidateIds.length ||
        review.coverage.completed !== candidateIds.length,
    )
  )
    throw new Error("Provider compatibility review coverage is incomplete.");
  return {
    status: "passed" as const,
    authMode: "bearer" as const,
    contextualReview: "passed" as const,
  };
}
