import { createHash } from "node:crypto";

import type { Finding, FindingV2 } from "../contracts/reports.js";
import { FullShaSchema } from "../contracts/targets.js";
import {
  analyzerSystemPrompt,
  analyzerUserContent,
  deterministicEvidenceDigest,
  parseAnalyzerResult,
  type DeterministicEvidence,
} from "./analyzer.js";
import {
  arbiterSystemPrompt,
  arbiterUserContent,
  parseArbiterResult,
} from "./arbiter.js";
import {
  challengerSystemPrompt,
  challengerUserContent,
  parseChallengerResult,
} from "./challenger.js";
import type { ModelChunk } from "./chunker.js";
import { modelChunkCacheKey, type ModelChunkCache } from "./chunk-cache.js";
import {
  automatedReviewMetadata,
  validateArbiterDecision,
  type EvidenceMap,
} from "./evidence-validator.js";
import {
  ModelRequestError,
  requestStructuredCompletion,
  validateModelEndpoint,
  type ModelUsage,
  type RequestStructuredCompletion,
  type StructuredCompletionResult,
} from "./openai-compatible-client.js";
import {
  roleJsonSchemas,
  sanitizeRolePayload,
  type ModelRole,
  type ModelRelationship,
  type RolePolicies,
} from "./role-contracts.js";

export interface ConfiguredModelReviewSpec {
  endpoint: string;
  apiKey: string | null;
  model: string;
  targetSha: string;
  projectKinds: readonly ("extension" | "frontend" | "preset")[];
  chunks: ModelChunk[];
  deterministicFindings: Finding[];
  relationships: ModelRelationship[];
  promptPolicyVersion: string;
  scannerPolicyVersion: string;
  rolePolicies: RolePolicies;
  maxOutputTokensPerRole: number;
  cache: ModelChunkCache;
  requestCompletion?: RequestStructuredCompletion;
}

interface AnalysisUnit {
  chunk: ModelChunk;
  deterministic: DeterministicEvidence[];
}

function configuredOrigin(endpoint: string) {
  const url = validateModelEndpoint(endpoint);
  return { origin: url.origin, provider: url.hostname };
}

function validateSpec(spec: ConfiguredModelReviewSpec) {
  const endpoint = configuredOrigin(spec.endpoint);
  const policies = Object.values(spec.rolePolicies);
  if (
    spec.apiKey === null ||
    spec.apiKey.trim() === "" ||
    spec.model.trim() === "" ||
    !FullShaSchema.safeParse(spec.targetSha).success ||
    spec.projectKinds.length === 0 ||
    spec.promptPolicyVersion.trim() === "" ||
    spec.scannerPolicyVersion.trim() === "" ||
    policies.some((policy) => policy.trim() === "") ||
    !Number.isInteger(spec.maxOutputTokensPerRole) ||
    spec.maxOutputTokensPerRole < 1 ||
    new Set(spec.chunks.map(({ id }) => id)).size !== spec.chunks.length
  ) {
    throw new ModelRequestError(
      "MODEL_CONFIGURATION",
      "system",
      "Configured model review is incomplete or invalid.",
    );
  }
  return { ...endpoint, apiKey: spec.apiKey };
}

export function addModelUsage(left: ModelUsage, right: ModelUsage): ModelUsage {
  return {
    inputTokens: left.inputTokens + right.inputTokens,
    outputTokens: left.outputTokens + right.outputTokens,
    cacheReadTokens: left.cacheReadTokens + right.cacheReadTokens,
    reasoningTokens: left.reasoningTokens + right.reasoningTokens,
  };
}

function zeroUsage(): ModelUsage {
  return {
    inputTokens: 0,
    outputTokens: 0,
    cacheReadTokens: 0,
    reasoningTokens: 0,
  };
}

function assertExpectedProvider(
  completion: Pick<StructuredCompletionResult, "endpointOrigin" | "provider">,
  expectedOrigin: string,
  expectedProvider: string,
) {
  if (
    completion.endpointOrigin !== expectedOrigin ||
    completion.provider !== expectedProvider
  ) {
    throw new ModelRequestError(
      "MODEL_INVALID_RESPONSE",
      "system",
      "Configured model response reported an unexpected endpoint identity.",
    );
  }
}

function evidenceWithinChunk(
  finding: Finding,
  chunk: ModelChunk,
  targetSha: string,
): DeterministicEvidence | null {
  const segment = chunk.segments.find((candidate) => {
    if (candidate.path !== finding.path) return false;
    if (finding.line_start === null) return finding.line_end === null;
    const end = finding.line_end ?? finding.line_start;
    return (
      finding.line_start >= candidate.line_start && end <= candidate.line_end
    );
  });
  if (segment === undefined) return null;
  return {
    finding,
    evidence: {
      path: finding.path,
      line_start: finding.line_start,
      line_end: finding.line_end,
      segment_id: chunk.id,
      content_digest: segment.content_hash,
      target_sha: targetSha,
    },
  };
}

function syntheticChunk(targetSha: string): ModelChunk {
  return {
    id: createHash("sha256")
      .update(JSON.stringify({ target_sha: targetSha, kind: "evidence-only" }))
      .digest("hex"),
    bytes: 0,
    content_hashes: [],
    segments: [],
  };
}

function analysisUnits(spec: ConfiguredModelReviewSpec): AnalysisUnit[] {
  const chunks =
    spec.chunks.length === 0 ? [syntheticChunk(spec.targetSha)] : spec.chunks;
  const units = chunks.map((chunk) => ({
    chunk,
    deterministic: [] as DeterministicEvidence[],
  }));
  for (const finding of spec.deterministicFindings) {
    let assigned = false;
    for (const unit of units) {
      const evidence = evidenceWithinChunk(finding, unit.chunk, spec.targetSha);
      if (evidence !== null) {
        unit.deterministic.push(evidence);
        assigned = true;
        break;
      }
    }
    if (!assigned) {
      units[0]!.deterministic.push({
        finding,
        evidence: {
          path: finding.path,
          line_start: finding.line_start,
          line_end: finding.line_end,
          segment_id: null,
          content_digest: deterministicEvidenceDigest(finding),
          target_sha: spec.targetSha,
        },
      });
    }
  }
  return units;
}

function relationshipsForUnit(
  relationships: readonly ModelRelationship[],
  chunk: ModelChunk,
) {
  const paths = new Set(chunk.segments.map(({ path }) => path));
  return relationships
    .filter(({ from, to }) => paths.has(from) || paths.has(to))
    .slice(0, 100_000);
}

async function requestRole({
  role,
  systemContent,
  userContent,
  spec,
  requestCompletion,
  segments,
}: {
  role: ModelRole;
  systemContent: string;
  userContent: string;
  spec: ConfiguredModelReviewSpec;
  requestCompletion: RequestStructuredCompletion;
  segments: ModelChunk["segments"];
}) {
  const inputDigest = createHash("sha256").update(userContent).digest("hex");
  const rolePromptDigest = createHash("sha256")
    .update(systemContent)
    .digest("hex");
  const key = modelChunkCacheKey({
    role,
    rolePromptDigest,
    endpointOrigin: new URL(spec.endpoint).origin,
    modelIdentifier: spec.model,
    promptPolicyVersion: spec.promptPolicyVersion,
    scannerPolicyVersion: spec.scannerPolicyVersion,
    inputDigest,
  });
  const cached = await spec.cache.load(key);
  if (cached !== null) {
    if (
      cached.role !== role ||
      cached.inputDigest !== inputDigest ||
      cached.payload.role !== role
    ) {
      throw new ModelRequestError(
        "MODEL_INVALID_RESPONSE",
        "system",
        "Model cache role identity does not match.",
      );
    }
    return {
      content: JSON.stringify(cached.payload.result),
      completionId: cached.completionId,
      endpointOrigin: new URL(spec.endpoint).origin,
      provider: new URL(spec.endpoint).hostname,
      usage: zeroUsage(),
      cached: true,
      commit: async () => {},
    };
  }
  const completion = await requestCompletion({
    endpoint: spec.endpoint,
    apiKey: spec.apiKey ?? "",
    model: spec.model,
    maxOutputTokens: spec.maxOutputTokensPerRole,
    schemaName: `tavernkeeper_${role}`,
    jsonSchema: roleJsonSchemas[role],
    systemContent,
    userContent,
  });
  let payload;
  try {
    payload = sanitizeRolePayload(role, completion.content, segments);
  } catch {
    throw new ModelRequestError(
      "MODEL_INVALID_RESPONSE",
      "repository",
      `The ${role} returned malformed structured output.`,
      `role_schema_${role}`,
    );
  }
  return {
    ...completion,
    content: JSON.stringify(payload.result),
    cached: false,
    commit: () =>
      spec.cache.save(key, {
        role,
        inputDigest,
        completionId: completion.completionId,
        payload,
        usage: completion.usage,
      }),
  };
}

export async function reviewWithConfiguredModel(
  spec: ConfiguredModelReviewSpec,
) {
  const configured = validateSpec(spec);
  const requestCompletion =
    spec.requestCompletion ?? requestStructuredCompletion;
  let usage = zeroUsage();
  const findings: FindingV2[] = [];
  const units = analysisUnits(spec);
  const roleCompletion = {
    analyzer: { required: units.length, completed: 0 },
    challenger: { required: units.length, completed: 0 },
    arbiter: { required: units.length, completed: 0 },
  };
  let cacheHits = 0;
  let cacheMisses = 0;

  for (const unit of units) {
    const analyzer = await requestRole({
      role: "analyzer",
      systemContent: analyzerSystemPrompt(spec.projectKinds),
      userContent: analyzerUserContent({
        chunk: unit.chunk,
        deterministic: unit.deterministic,
        relationships: relationshipsForUnit(spec.relationships, unit.chunk),
        targetSha: spec.targetSha,
      }),
      spec,
      requestCompletion,
      segments: unit.chunk.segments,
    });
    assertExpectedProvider(analyzer, configured.origin, configured.provider);
    const claims = parseAnalyzerResult({
      content: analyzer.content,
      chunk: unit.chunk,
      deterministic: unit.deterministic,
      provider: configured.provider,
      targetSha: spec.targetSha,
    });
    await analyzer.commit();
    if (analyzer.cached) cacheHits += 1;
    else cacheMisses += 1;
    roleCompletion.analyzer.completed += 1;
    usage = addModelUsage(usage, analyzer.usage);

    const challenger = await requestRole({
      role: "challenger",
      systemContent: challengerSystemPrompt,
      userContent: challengerUserContent(claims),
      spec,
      requestCompletion,
      segments: unit.chunk.segments,
    });
    assertExpectedProvider(challenger, configured.origin, configured.provider);
    const challenges = parseChallengerResult({
      content: challenger.content,
      claims,
      segments: unit.chunk.segments,
    });
    await challenger.commit();
    if (challenger.cached) cacheHits += 1;
    else cacheMisses += 1;
    roleCompletion.challenger.completed += 1;
    usage = addModelUsage(usage, challenger.usage);

    const arbiter = await requestRole({
      role: "arbiter",
      systemContent: arbiterSystemPrompt,
      userContent: arbiterUserContent(claims, challenges),
      spec,
      requestCompletion,
      segments: unit.chunk.segments,
    });
    assertExpectedProvider(arbiter, configured.origin, configured.provider);
    const decisions = parseArbiterResult({
      content: arbiter.content,
      claims,
      segments: unit.chunk.segments,
    });
    await arbiter.commit();
    if (arbiter.cached) cacheHits += 1;
    else cacheMisses += 1;
    roleCompletion.arbiter.completed += 1;
    usage = addModelUsage(usage, arbiter.usage);

    const evidenceMap: EvidenceMap = new Map(
      claims.map((claim) => [
        claim.finding.fingerprint,
        {
          finding: claim.finding,
          evidence: claim.evidence,
          automatedReview: automatedReviewMetadata(spec.rolePolicies),
        },
      ]),
    );
    findings.push(
      ...decisions.map((decision) =>
        validateArbiterDecision(decision, evidenceMap, spec.targetSha),
      ),
    );
  }

  if (
    findings.some(
      (finding) =>
        finding.disposition === "inconclusive" &&
        ["critical", "high", "medium"].includes(finding.severity) &&
        ["high", "medium"].includes(finding.confidence),
    )
  ) {
    throw new ModelRequestError(
      "MODEL_INVALID_RESPONSE",
      "repository",
      "A review-level model claim remained inconclusive.",
    );
  }
  const fingerprints = findings.map(({ fingerprint }) => fingerprint);
  if (new Set(fingerprints).size !== fingerprints.length) {
    throw new ModelRequestError(
      "MODEL_INVALID_RESPONSE",
      "repository",
      "Automated review returned duplicate findings.",
    );
  }

  return {
    endpointOrigin: configured.origin,
    provider: configured.provider,
    model: spec.model,
    findings: findings.sort((left, right) =>
      left.fingerprint.localeCompare(right.fingerprint),
    ),
    completedChunkIds: spec.chunks.map(({ id }) => id),
    roleCompletion,
    usage,
    cacheHits,
    cacheMisses,
  };
}
