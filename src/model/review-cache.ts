import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { join } from "node:path";

import { z } from "zod";

import type { EvidenceContextGroup } from "../context/evidence-context.js";
import type { ScanReportV5 } from "../contracts/reports-v5.js";
import { sanitizeReportV5 } from "../publish/sanitize.js";
import { reportPath } from "../publish/report-path.js";
import {
  ContextualReviewResponseSchema,
  type ContextualReviewResponse,
} from "./contextual-review-contract.js";
import { validateCompletedGroupReview } from "./review-coverage.js";

const VersionSchema = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,199}$/u);
const ProviderSchema = z.string().regex(/^[A-Za-z0-9.-]{1,253}$/u);
const DigestSchema = z.string().regex(/^[0-9a-f]{64}$/u);
const FullShaSchema = z.string().regex(/^[0-9a-f]{40}$/u);
const RepositorySchema = z.string().regex(/^[^/\s]+\/[^/\s]+$/u);

export const ReviewIdentitySchema = z.strictObject({
  scanner_version: VersionSchema,
  scanner_policy_version: VersionSchema,
  rule_catalog_version: VersionSchema,
  tools: z
    .array(
      z.strictObject({
        name: z.string().regex(/^[a-z0-9][a-z0-9:_-]{0,79}$/u),
        version: VersionSchema,
      }),
    )
    .min(1)
    .max(32),
  contextual_policy_version: VersionSchema,
  prompt_version: VersionSchema,
  assessment_schema_version: VersionSchema,
  provider: ProviderSchema,
  endpoint_origin: z.url(),
  model: z.string().trim().min(1).max(200),
});

export type ReviewIdentity = z.infer<typeof ReviewIdentitySchema>;

export const ReviewCacheManifestSchema = z
  .strictObject({
    schema_version: z.literal(1),
    repository_id: z.number().int().positive(),
    repository: RepositorySchema,
    source_report: z.strictObject({
      report_id: DigestSchema,
      target_sha: FullShaSchema,
      scanner_policy_version: VersionSchema,
    }),
    review_identity: ReviewIdentitySchema.optional(),
    entries: z
      .array(
        z.strictObject({
          review_input_digest: DigestSchema,
          candidate_ids: z.array(DigestSchema).min(1).max(64),
        }),
      )
      .max(10_000),
  })
  .superRefine((manifest, context) => {
    if (manifest.entries.length > 0 && manifest.review_identity === undefined)
      context.addIssue({
        code: "custom",
        path: ["review_identity"],
        message: "Reusable entries require a contextual review identity.",
      });
    const digests = manifest.entries.map(
      ({ review_input_digest }) => review_input_digest,
    );
    if (new Set(digests).size !== digests.length)
      context.addIssue({
        code: "custom",
        path: ["entries"],
        message: "Review cache digests must be unique.",
      });
    for (const [index, entry] of manifest.entries.entries()) {
      const sorted = [...entry.candidate_ids].sort();
      if (
        new Set(entry.candidate_ids).size !== entry.candidate_ids.length ||
        sorted.some(
          (value, candidateIndex) =>
            value !== entry.candidate_ids[candidateIndex],
        )
      )
        context.addIssue({
          code: "custom",
          path: ["entries", index, "candidate_ids"],
          message: "Review cache candidate IDs must be unique and sorted.",
        });
    }
  });

export type ReviewCacheManifest = z.infer<typeof ReviewCacheManifestSchema>;

type CompletedResponse = Extract<
  ContextualReviewResponse,
  { status: "complete" }
>;

export interface ReusableReviewGroup {
  review_input_digest: string;
  origin_report_id: string;
  response: CompletedResponse;
}

export function canonicalReviewInput(group: EvidenceContextGroup) {
  return {
    repository: group.repository,
    project_kinds: [...group.project_kinds].sort(),
    path: group.path,
    file_role: group.file_role,
    execution_scope: group.execution_scope,
    source_kind: group.source_kind,
    ecosystem_context_version: group.ecosystem_context_version,
    ecosystem_context: group.ecosystem_context,
    candidates: [...group.candidates].sort((left, right) =>
      left.candidate_id.localeCompare(right.candidate_id),
    ),
    context: {
      imports: group.context.imports,
      source: group.context.source,
      expansions: [...group.context.expansions],
      representations: group.context.representations
        .map(({ stage, transform_depth }) => ({ stage, transform_depth }))
        .sort((left, right) =>
          (String(left.transform_depth) + ":" + left.stage).localeCompare(
            String(right.transform_depth) + ":" + right.stage,
          ),
        ),
      project_purpose: group.context.project_purpose,
    },
  };
}

export function canonicalReviewIdentity(identity: ReviewIdentity) {
  const parsed = ReviewIdentitySchema.parse(identity);
  return {
    ...parsed,
    tools: [...parsed.tools].sort((left, right) =>
      (left.name + ":" + left.version).localeCompare(
        right.name + ":" + right.version,
      ),
    ),
  };
}

export function reviewInputDigest(
  group: EvidenceContextGroup,
  identity: ReviewIdentity,
) {
  return createHash("sha256")
    .update(
      JSON.stringify({
        input: canonicalReviewInput(group),
        identity: canonicalReviewIdentity(identity),
      }),
    )
    .digest("hex");
}

export function reviewInputBoundary(group: EvidenceContextGroup) {
  return createHash("sha256")
    .update(JSON.stringify(canonicalReviewInput(group)))
    .digest("hex");
}

export function reviewCachePath(repositoryId: number) {
  const parsed = z.number().int().positive().parse(repositoryId);
  return ["reports", "github", String(parsed), "review-cache.json"].join("/");
}

function sameIdentity(left: ReviewIdentity, right: ReviewIdentity) {
  return (
    JSON.stringify(canonicalReviewIdentity(left)) ===
    JSON.stringify(canonicalReviewIdentity(right))
  );
}

function reportMatchesManifest(
  report: ReturnType<typeof sanitizeReportV5>,
  manifest: ReviewCacheManifest,
  identity: ReviewIdentity,
) {
  const reportTools = report.coverage.tools.map(({ name, version }) => ({
    name,
    version,
  }));
  return (
    report.repository_id === manifest.repository_id &&
    report.repository === manifest.repository &&
    report.report_id === manifest.source_report.report_id &&
    report.target_sha === manifest.source_report.target_sha &&
    report.scanner_policy_version ===
      manifest.source_report.scanner_policy_version &&
    report.scanner_version === identity.scanner_version &&
    report.scanner_policy_version === identity.scanner_policy_version &&
    report.rule_catalog_version === identity.rule_catalog_version &&
    report.contextual_review_policy_version ===
      identity.contextual_policy_version &&
    report.prompt_version === identity.prompt_version &&
    report.assessment_schema_version === identity.assessment_schema_version &&
    report.contextual_reviewer !== undefined &&
    report.contextual_reviewer.provider === identity.provider &&
    report.contextual_reviewer.model === identity.model &&
    JSON.stringify(
      [...reportTools].sort((left, right) =>
        (left.name + ":" + left.version).localeCompare(
          right.name + ":" + right.version,
        ),
      ),
    ) === JSON.stringify(canonicalReviewIdentity(identity).tools)
  );
}

function responseForCandidates(
  report: ReturnType<typeof sanitizeReportV5>,
  candidateIds: readonly string[],
): CompletedResponse | undefined {
  const candidateSet = new Set(candidateIds);
  const assessments = report.assessments
    .filter(({ candidate_id }) => candidateSet.has(candidate_id))
    .map((published) => {
      const { locations: _locations, ...assessment } = published;
      if ("assessment_source" in assessment) {
        const {
          assessment_source: _assessmentSource,
          triage_reason_code: _triageReasonCode,
          ...contextual
        } = assessment;
        return contextual;
      }
      return assessment;
    });
  const observations = report.observations
    .filter(
      ({ related_candidate_ids }) =>
        related_candidate_ids.length > 0 &&
        related_candidate_ids.every((candidateId) =>
          candidateSet.has(candidateId),
        ),
    )
    .map(({ observation_id: _observationId, ...observation }) => observation);
  const parsed = ContextualReviewResponseSchema.safeParse({
    status: "complete",
    assessments,
    observations,
  });
  return parsed.success && parsed.data.status === "complete"
    ? parsed.data
    : undefined;
}

function reusableResponse(response: CompletedResponse) {
  return [...response.assessments, ...response.observations].every(
    (item) =>
      item.recommended_risk === "low" &&
      item.risk_exposure === "not_demonstrated",
  );
}

export async function loadReusableReviewGroups(input: {
  repositoryRoot: string;
  repositoryId: number;
  repository: string;
  groups: readonly EvidenceContextGroup[];
  reviewIdentity: ReviewIdentity;
}): Promise<Map<string, ReusableReviewGroup>> {
  try {
    const identity = ReviewIdentitySchema.parse(input.reviewIdentity);
    const manifest = ReviewCacheManifestSchema.parse(
      JSON.parse(
        await readFile(
          join(input.repositoryRoot, reviewCachePath(input.repositoryId)),
          "utf8",
        ),
      ),
    );
    if (
      manifest.repository_id !== input.repositoryId ||
      manifest.repository !== input.repository ||
      manifest.review_identity === undefined ||
      !sameIdentity(manifest.review_identity, identity)
    )
      return new Map();
    const report = sanitizeReportV5(
      JSON.parse(
        await readFile(
          join(
            input.repositoryRoot,
            reportPath({
              schema_version: 5,
              provider: "github",
              repository_id: manifest.repository_id,
              target_sha: manifest.source_report.target_sha,
              scanner_policy_version:
                manifest.source_report.scanner_policy_version,
              report_id: manifest.source_report.report_id,
            }),
            "report.json",
          ),
          "utf8",
        ),
      ),
    );
    if (!reportMatchesManifest(report, manifest, identity)) return new Map();
    const entryByDigest = new Map(
      manifest.entries.map((entry) => [entry.review_input_digest, entry]),
    );
    const hits = new Map<string, ReusableReviewGroup>();
    const repositoryPaths = report.candidates.map(({ path }) => path);
    for (const group of input.groups) {
      try {
        const digest = reviewInputDigest(group, identity);
        const entry = entryByDigest.get(digest);
        if (entry === undefined) continue;
        const currentCandidateIds = group.candidates
          .map(({ candidate_id }) => candidate_id)
          .sort();
        if (
          currentCandidateIds.length !== entry.candidate_ids.length ||
          currentCandidateIds.some(
            (candidateId, index) => candidateId !== entry.candidate_ids[index],
          )
        )
          continue;
        const response = responseForCandidates(report, currentCandidateIds);
        if (response === undefined || !reusableResponse(response)) continue;
        validateCompletedGroupReview(group, response, repositoryPaths);
        hits.set(group.group_id, {
          review_input_digest: digest,
          origin_report_id: report.report_id,
          response,
        });
      } catch {
        continue;
      }
    }
    return hits;
  } catch {
    return new Map();
  }
}

export function buildReviewCacheManifest(input: {
  report: ScanReportV5;
  reviewIdentity?: ReviewIdentity | undefined;
  reviewUnits: readonly {
    review_input_digest: string;
    candidate_ids: readonly string[];
  }[];
}) {
  const report = sanitizeReportV5(input.report);
  const identity =
    input.reviewIdentity === undefined
      ? undefined
      : ReviewIdentitySchema.parse(input.reviewIdentity);
  if (input.reviewUnits.length > 0 && identity === undefined)
    throw new Error("Contextual review units require a review identity.");
  const assessmentByCandidate = new Map(
    report.assessments.map((assessment) => [
      assessment.candidate_id,
      assessment,
    ]),
  );
  const entries = input.reviewUnits
    .filter((unit) => {
      const candidateSet = new Set(unit.candidate_ids);
      const assessments = unit.candidate_ids.map((candidateId) =>
        assessmentByCandidate.get(candidateId),
      );
      const observations = report.observations.filter(
        ({ related_candidate_ids }) =>
          related_candidate_ids.length > 0 &&
          related_candidate_ids.every((candidateId) =>
            candidateSet.has(candidateId),
          ),
      );
      return (
        assessments.every(
          (assessment) =>
            assessment !== undefined &&
            (report.contextual_review_policy_version !== "5" ||
              ("assessment_source" in assessment &&
                assessment.assessment_source === "contextual-model")) &&
            "risk_exposure" in assessment &&
            assessment.recommended_risk === "low" &&
            assessment.risk_exposure === "not_demonstrated",
        ) &&
        observations.every(
          (observation) =>
            "risk_exposure" in observation &&
            observation.recommended_risk === "low" &&
            observation.risk_exposure === "not_demonstrated",
        )
      );
    })
    .map((unit) => ({
      review_input_digest: unit.review_input_digest,
      candidate_ids: [...unit.candidate_ids].sort(),
    }))
    .sort((left, right) =>
      left.review_input_digest.localeCompare(right.review_input_digest),
    );
  return ReviewCacheManifestSchema.parse({
    schema_version: 1,
    repository_id: report.repository_id,
    repository: report.repository,
    source_report: {
      report_id: report.report_id,
      target_sha: report.target_sha,
      scanner_policy_version: report.scanner_policy_version,
    },
    ...(identity === undefined ? {} : { review_identity: identity }),
    entries,
  });
}
