import { createHash } from "node:crypto";

import {
  chunkReviewSystemPrompt,
  chunkReviewUserContent,
} from "./chunk-review.js";
import type { ModelChunk } from "./chunker.js";
import { buildEvidenceManifest } from "./evidence-manifest.js";
import {
  checkModelProviderConnectivity,
  ModelRequestError,
  requestStructuredCompletion,
  requestTextCompletion,
  type ProviderConnectivityRequest,
} from "./openai-compatible-client.js";
import {
  repositorySynthesisInput,
  repositorySynthesisJsonSchema,
  repositorySynthesisSystemPrompt,
  validateRepositorySynthesis,
} from "./repository-synthesis.js";
import { sanitizePrivateChunkReview } from "./review-contracts.js";

const targetSha = "0".repeat(40);
const source = "export const compatibilityValue = 1;\n";
const sourceDigest = createHash("sha256").update(source).digest("hex");
const chunk: ModelChunk = {
  id: createHash("sha256")
    .update(`provider-check:${sourceDigest}`)
    .digest("hex"),
  bytes: Buffer.byteLength(source),
  content_hashes: [sourceDigest],
  segments: [
    {
      path: "src/provider-compatibility.ts",
      line_start: 1,
      line_end: 1,
      content: source,
      bytes: Buffer.byteLength(source),
      overlap_bytes: 0,
      content_hash: sourceDigest,
      source_sha256: sourceDigest,
    },
  ],
};

function transport(request: ProviderConnectivityRequest) {
  return {
    ...(request.fetchImpl === undefined
      ? {}
      : { fetchImpl: request.fetchImpl }),
    ...(request.resolveAddresses === undefined
      ? {}
      : { resolveAddresses: request.resolveAddresses }),
    ...(request.timeoutMs === undefined
      ? {}
      : { timeoutMs: request.timeoutMs }),
  };
}

export async function checkModelProviderCompatibility(
  request: ProviderConnectivityRequest,
) {
  const connectivity = await checkModelProviderConnectivity(request);
  const evidenceManifest = buildEvidenceManifest([chunk], [], targetSha);
  const textCompletion = await requestTextCompletion({
    ...request,
    ...transport(request),
    systemContent: chunkReviewSystemPrompt(["extension"], "chunk-review-v2"),
    userContent: chunkReviewUserContent({
      targetSha,
      projectKinds: ["extension"],
      chunkId: chunk.id,
      evidenceManifest,
    }),
    maxOutputTokens: 8_192,
  });
  if (textCompletion.content.trim() === "")
    throw new ModelRequestError(
      "MODEL_INVALID_RESPONSE",
      "repository",
      "Configured model returned an empty compatibility chunk review.",
      "chunk_review_empty",
    );
  const recap = sanitizePrivateChunkReview(
    textCompletion.content,
    chunk.segments,
    12_000,
  );
  const synthesisInput = repositorySynthesisInput({
    targetSha,
    projectKinds: ["extension"],
    tools: [],
    evidenceManifest,
    completedChunkReviews: [
      {
        chunkId: chunk.id,
        recap,
        completionId: textCompletion.completionId,
        usage: textCompletion.usage,
        cached: false,
      },
    ],
  });
  const synthesisCompletion = await requestStructuredCompletion({
    ...request,
    ...transport(request),
    systemContent: repositorySynthesisSystemPrompt("repository-synthesis-v2"),
    userContent: JSON.stringify(synthesisInput),
    maxOutputTokens: 8_192,
    schemaName: "tavernkeeper_repository_synthesis",
    jsonSchema: repositorySynthesisJsonSchema,
  });
  const synthesis = validateRepositorySynthesis(
    synthesisCompletion.content,
    evidenceManifest,
  );
  if (
    synthesis.validated.assessment !== "no_concerning_evidence" ||
    synthesis.validated.concerns.length !== 0
  )
    throw new ModelRequestError(
      "MODEL_INVALID_RESPONSE",
      "repository",
      "Configured model returned an invalid compatibility synthesis conclusion.",
      "synthesis_schema",
    );
  return {
    ...connectivity,
    textReview: "passed" as const,
    structuredOutput: "passed" as const,
  };
}
