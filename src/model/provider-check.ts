import { createHash } from "node:crypto";

import { EvidenceContextGroupSchema } from "../context/evidence-context.js";
import { reviewEvidenceGroups } from "./contextual-review.js";
import type { ProviderConnectivityRequest } from "./openai-compatible-client.js";

const candidateId = "c".repeat(64);
const source =
  "The setting is named apiKey; never paste a real credential here.\n";

export async function checkModelProviderCompatibility(
  request: ProviderConnectivityRequest,
) {
  const group = EvidenceContextGroupSchema.parse({
    group_id: "b".repeat(64),
    repository: "tavernkeeper/provider-compatibility",
    project_kinds: ["extension"],
    path: "README.md",
    file_role: "documentation",
    target_sha: "0".repeat(40),
    evidence_sha: "0".repeat(40),
    source_bytes: Buffer.byteLength(source),
    source_sha256: createHash("sha256").update(source).digest("hex"),
    ecosystem_context_version: "sillytavern-community-v1",
    ecosystem_context: "Trusted ecosystem context.",
    candidates: [
      {
        candidate_id: candidateId,
        evidence_id: candidateId,
        origin: "gitleaks",
        rule_id: "documentation-credential-keyword",
        category: "credential-exposure",
        scanner_severity: "low",
        scanner_confidence: "low",
        title: "Credential keyword in documentation",
        explanation:
          "A credential-related keyword appears in explanatory documentation.",
        line_start: 1,
        line_end: 1,
      },
    ],
    context: {
      imports: "",
      source: `     1 | ${source.trimEnd()}`,
      project_purpose:
        "A benign compatibility fixture for TavernKeeper contextual review.",
    },
  });
  const review = await reviewEvidenceGroups({
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
      version: "1",
      promptVersion: "contextual-review-v1",
      schemaVersion: "contextual-assessment-v1",
      maxImmediateAttempts: 1,
      maxOutputTokens: 8_192,
      maxResponseBytes: 1_000_000,
      timeoutMs: request.timeoutMs ?? 60_000,
    },
  });
  if (review.coverage.required !== 1 || review.coverage.completed !== 1)
    throw new Error("Provider compatibility review coverage is incomplete.");
  return {
    status: "passed" as const,
    authMode: "bearer" as const,
    contextualReview: "passed" as const,
  };
}
