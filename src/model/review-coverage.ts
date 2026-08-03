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

export function validateCompletedGroupReview(
  group: EvidenceContextGroup,
  response: CompletedResponse,
): {
  assessments: ContextualAssessment[];
  observations: ContextualObservation[];
} {
  const candidates = new Map(
    group.candidates.map((candidate) => [candidate.candidate_id, candidate]),
  );
  const evidenceIds = new Set(
    group.candidates.map((candidate) => candidate.evidence_id),
  );
  if (candidates.size !== group.candidates.length)
    evidenceError("Evidence group contains duplicate candidate identities.");
  if (
    response.assessments.length !== candidates.size ||
    response.assessments.some(
      (assessment) => !candidates.has(assessment.candidate_id),
    )
  )
    evidenceError(
      "Contextual review did not assess every supplied candidate exactly once.",
    );
  for (const assessment of response.assessments) {
    const candidate = candidates.get(assessment.candidate_id)!;
    if (
      !assessment.evidence_ids.includes(candidate.evidence_id) ||
      assessment.evidence_ids.some((evidenceId) => !evidenceIds.has(evidenceId))
    )
      evidenceError("Contextual review cited unknown candidate evidence.");
    validateLocations(group, assessment.locations);
  }
  for (const observation of response.observations) {
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
    response.assessments.map((assessment) => [
      assessment.candidate_id,
      assessment,
    ]),
  );
  return {
    assessments: group.candidates.map((candidate) =>
      assessmentById.get(candidate.candidate_id)!,
    ),
    observations: response.observations
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
