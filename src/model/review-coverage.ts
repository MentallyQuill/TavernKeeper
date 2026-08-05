import { createHash } from "node:crypto";

import type { EvidenceContextGroup } from "../context/evidence-context.js";
import {
  type ContextualAssessment,
  type ContextualObservation,
  type ContextualReviewResponse,
} from "./contextual-review-contract.js";
import { ModelRequestError } from "./openai-compatible-client.js";

type CompletedResponse = Extract<
  ContextualReviewResponse,
  { status: "complete" }
>;

function evidenceError(message: string): never {
  throw new ModelRequestError("MODEL_EVIDENCE_INVALID", "repository", message);
}

function suppliedLines(group: EvidenceContextGroup) {
  const lines = new Set<number>();
  for (const context of [group.context.imports, group.context.source]) {
    for (const line of context.split("\n")) {
      const match = /^\s*([1-9][0-9]*)\s+\|/u.exec(line);
      if (match?.[1]) lines.add(Number.parseInt(match[1], 10));
    }
  }
  return lines;
}

function validateLocations(
  group: EvidenceContextGroup,
  locations: readonly {
    path: string;
    line_start: number;
    line_end: number;
  }[],
) {
  const lines = suppliedLines(group);
  for (const location of locations) {
    if (location.path !== group.path)
      evidenceError("Contextual review cited an unsupplied file path.");
    for (let line = location.line_start; line <= location.line_end; line += 1)
      if (!lines.has(line))
        evidenceError("Contextual review cited an unsupplied source line.");
  }
}

function canonicalCandidateLocation(
  group: EvidenceContextGroup,
  candidate: EvidenceContextGroup["candidates"][number],
) {
  const supplied = [...suppliedLines(group)].sort(
    (left, right) => left - right,
  );
  const suppliedSet = new Set(supplied);
  const fallback = supplied[0] ?? 1;
  const requestedStart = candidate.line_start ?? fallback;
  const requestedEnd = candidate.line_end ?? requestedStart;
  const rangeLength = requestedEnd - requestedStart + 1;
  let rangeIsSupplied = rangeLength > 0 && rangeLength <= suppliedSet.size;
  for (
    let line = requestedStart;
    rangeIsSupplied && line <= requestedEnd;
    line += 1
  )
    rangeIsSupplied = suppliedSet.has(line);
  const lineStart = rangeIsSupplied ? requestedStart : fallback;
  const lineEnd = rangeIsSupplied ? requestedEnd : fallback;
  return [{ path: group.path, line_start: lineStart, line_end: lineEnd }];
}

function escapeRegularExpression(value: string) {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}

function redactKnownRepositoryPaths(
  value: string,
  repositoryPaths: readonly string[],
) {
  return [...new Set(repositoryPaths)]
    .sort((left, right) => right.length - left.length)
    .reduce((redacted, path) => {
      const pattern = new RegExp(
        `(^|[^\\p{L}\\p{N}._/-])${escapeRegularExpression(path)}(?=$|[^\\p{L}\\p{N}._/-])`,
        "giu",
      );
      const replacement = path.length >= 4 ? "file" : "x";
      return redacted.replace(
        pattern,
        (_match, prefix: string) => `${prefix}${replacement}`,
      );
    }, value);
}

function redactNarrativePaths(
  response: CompletedResponse,
  repositoryPaths: readonly string[],
): CompletedResponse {
  const redact = (value: string) =>
    redactKnownRepositoryPaths(value, repositoryPaths);
  return {
    status: "complete",
    assessments: response.assessments.map((assessment) => ({
      ...assessment,
      technical_explanation: redact(assessment.technical_explanation),
      layman_explanation: redact(assessment.layman_explanation),
      developer_action: redact(assessment.developer_action),
    })),
    observations: response.observations.map((observation) => ({
      ...observation,
      title: redact(observation.title),
      technical_explanation: redact(observation.technical_explanation),
      layman_explanation: redact(observation.layman_explanation),
      developer_action: redact(observation.developer_action),
    })),
  };
}

export function validateCompletedGroupReview(
  group: EvidenceContextGroup,
  response: CompletedResponse,
  repositoryPaths: readonly string[] = [group.path],
): {
  assessments: ContextualAssessment[];
  observations: ContextualObservation[];
} {
  const review = redactNarrativePaths(response, repositoryPaths);
  const candidates = new Map(
    group.candidates.map((candidate) => [candidate.candidate_id, candidate]),
  );
  const evidenceIds = new Set(
    group.candidates.map((candidate) => candidate.evidence_id),
  );
  if (candidates.size !== group.candidates.length)
    evidenceError("Evidence group contains duplicate candidate identities.");
  if (
    review.assessments.length !== candidates.size ||
    review.assessments.some(
      (assessment) => !candidates.has(assessment.candidate_id),
    )
  )
    evidenceError(
      "Contextual review did not assess every supplied candidate exactly once.",
    );
  for (const assessment of review.assessments) {
    const candidate = candidates.get(assessment.candidate_id)!;
    if (
      !assessment.evidence_ids.includes(candidate.evidence_id) ||
      assessment.evidence_ids.some((evidenceId) => !evidenceIds.has(evidenceId))
    )
      evidenceError("Contextual review cited unknown candidate evidence.");
  }
  for (const observation of review.observations) {
    if (
      observation.related_candidate_ids.some(
        (candidateId) => !candidates.has(candidateId),
      ) ||
      observation.evidence_ids.some(
        (evidenceId) => !evidenceIds.has(evidenceId),
      )
    )
      evidenceError("Contextual observation cited unknown evidence.");
    validateLocations(group, observation.locations);
  }
  const assessmentById = new Map(
    review.assessments.map((assessment) => [
      assessment.candidate_id,
      assessment,
    ]),
  );
  return {
    assessments: group.candidates.map((candidate) => ({
      ...assessmentById.get(candidate.candidate_id)!,
      locations: canonicalCandidateLocation(group, candidate),
    })),
    observations: review.observations
      .map((observation) => ({
        observation_id: createHash("sha256")
          .update(
            JSON.stringify([
              group.group_id,
              observation.related_candidate_ids,
              observation.evidence_ids,
              observation.disposition,
              observation.impact,
              observation.exploitability,
              observation.confidence,
              observation.recommended_risk,
              observation.title,
              observation.technical_explanation,
              observation.layman_explanation,
              observation.developer_action,
              observation.locations,
            ]),
          )
          .digest("hex"),
        ...observation,
      }))
      .sort((left, right) =>
        left.observation_id.localeCompare(right.observation_id),
      ),
  };
}
