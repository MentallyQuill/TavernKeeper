import { createHash } from "node:crypto";
import { access, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { basename, join, resolve } from "node:path";

import { z } from "zod";

import { ContextualReviewProgressSchema } from "../model/contextual-review.js";
import {
  decryptTransport,
  encryptTransport,
} from "../publish/encrypted-transport.js";
import { CompletedReviewV5Schema } from "../report/contextual-report.js";
import { validatePreparedSessionEvidence } from "../orchestrator/session.js";
import { ScanRequestSchema } from "../cli/staff-request.js";

const DigestSchema = z.string().regex(/^[0-9a-f]{64}$/u);

export const ReviewCheckpointIdentitySchema = z.strictObject({
  contextual_policy_version: z.literal("5"),
  prompt_version: z.literal("contextual-review-v7"),
  assessment_schema_version: z.literal("contextual-assessment-v2"),
  provider: z.string().regex(/^[A-Za-z0-9.-]{1,253}$/u),
  endpoint_origin: z.url(),
  model: z.string().trim().min(1).max(200),
});

const ReviewProgressBundleSchema = z.strictObject({
  schema_version: z.literal(1),
  session_id: DigestSchema,
  evidence_digest: DigestSchema,
  progress: ContextualReviewProgressSchema,
});

const ReviewBundleSchema = z.strictObject({
  schema_version: z.literal(1),
  session_id: DigestSchema,
  evidence_digest: DigestSchema,
  review: CompletedReviewV5Schema,
});

const ReviewCheckpointPayloadSchema = z
  .strictObject({
    schema_version: z.literal(1),
    review_protocol_version: z.literal(2),
    phase: z.enum(["prepared", "reviewing", "reviewed"]),
    created_at: z.iso.datetime(),
    expires_at: z.iso.datetime(),
    request: ScanRequestSchema,
    review_identity: ReviewCheckpointIdentitySchema,
    session_id: DigestSchema,
    evidence_digest: DigestSchema,
    files: z.strictObject({
      prepared: z.unknown(),
      evidence_context: z.unknown(),
      review_progress: z.unknown().nullable(),
      review: z.unknown().nullable(),
    }),
  })
  .superRefine((payload, context) => {
    if (Date.parse(payload.expires_at) <= Date.parse(payload.created_at))
      context.addIssue({
        code: "custom",
        path: ["expires_at"],
        message: "Review checkpoint expiry must follow its creation time.",
      });
    if (
      (payload.phase === "prepared" &&
        (payload.files.review_progress !== null ||
          payload.files.review !== null)) ||
      (payload.phase === "reviewing" &&
        (payload.files.review_progress === null ||
          payload.files.review !== null)) ||
      (payload.phase === "reviewed" && payload.files.review === null)
    )
      context.addIssue({
        code: "custom",
        path: ["files"],
        message: "Review checkpoint files do not match its phase.",
      });
  });

export type ReviewCheckpointIdentity = z.infer<
  typeof ReviewCheckpointIdentitySchema
>;

function digest(value: Buffer | string) {
  return createHash("sha256").update(value).digest("hex");
}

async function exists(path: string) {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

function checkpointContext(request: unknown, identity: unknown) {
  return JSON.stringify({
    review_protocol_version: 2,
    request: ScanRequestSchema.parse(request),
    review_identity: ReviewCheckpointIdentitySchema.parse(identity),
  });
}

function safeSessionRoot(input: string) {
  const root = resolve(input);
  if (!basename(root).startsWith("tavernkeeper-session-"))
    throw new Error("Review checkpoint session directory name is unsafe.");
  return root;
}

function validatePayloadFiles(
  payload: z.infer<typeof ReviewCheckpointPayloadSchema>,
) {
  const { prepared, evidence } = validatePreparedSessionEvidence(
    payload.files.prepared,
    payload.files.evidence_context,
  );
  if (
    prepared.session_id !== payload.session_id ||
    evidence.evidence_digest !== payload.evidence_digest
  )
    throw new Error("Review checkpoint session identity does not match.");
  if (
    JSON.stringify(prepared.target) !==
      JSON.stringify({
        source_id: payload.request.source_id,
        provider: payload.request.provider,
        repository_id: payload.request.repository_id,
        repository: payload.request.repository,
        target_sha: payload.request.target_sha,
        canonical_url: payload.request.canonical_url,
      }) ||
    JSON.stringify(prepared.project_kinds) !==
      JSON.stringify(payload.request.project_kinds) ||
    prepared.report_version !== payload.request.report_version ||
    prepared.supersedes_report_id !== payload.request.supersedes_report_id
  )
    throw new Error("Review checkpoint request does not match its session.");
  if (payload.files.review_progress !== null) {
    const progress = ReviewProgressBundleSchema.parse(
      payload.files.review_progress,
    );
    if (
      progress.session_id !== payload.session_id ||
      progress.evidence_digest !== payload.evidence_digest
    )
      throw new Error("Review checkpoint progress identity does not match.");
  }
  if (payload.files.review !== null) {
    const review = ReviewBundleSchema.parse(payload.files.review);
    if (
      review.session_id !== payload.session_id ||
      review.evidence_digest !== payload.evidence_digest
    )
      throw new Error(
        "Review checkpoint completed review identity does not match.",
      );
    const reviewer = review.review.reviewer;
    if (
      reviewer !== undefined &&
      (reviewer.provider !== payload.review_identity.provider ||
        reviewer.endpoint_origin !== payload.review_identity.endpoint_origin ||
        reviewer.model !== payload.review_identity.model)
    )
      throw new Error("Review checkpoint reviewer identity does not match.");
  }
  return { prepared, evidence };
}

async function readJson(path: string) {
  return JSON.parse(await readFile(path, "utf8")) as unknown;
}

export async function createReviewCheckpoint({
  sessionRoot: sessionRootInput,
  request: requestInput,
  reviewIdentity: identityInput,
  key,
  createdAt,
  expiresAt,
}: {
  sessionRoot: string;
  request: unknown;
  reviewIdentity: unknown;
  key: Buffer;
  createdAt: string;
  expiresAt: string;
}) {
  const sessionRoot = safeSessionRoot(sessionRootInput);
  const request = ScanRequestSchema.parse(requestInput);
  const reviewIdentity = ReviewCheckpointIdentitySchema.parse(identityInput);
  const prepared = await readJson(join(sessionRoot, "prepared.json"));
  const evidenceContext = await readJson(
    join(sessionRoot, "evidence-context.json"),
  );
  const reviewPath = join(sessionRoot, "review.json");
  const progressPath = join(sessionRoot, "review-progress.json");
  const review = (await exists(reviewPath)) ? await readJson(reviewPath) : null;
  const reviewProgress =
    review === null && (await exists(progressPath))
      ? await readJson(progressPath)
      : null;
  const validated = validatePreparedSessionEvidence(prepared, evidenceContext);
  const phase =
    review !== null
      ? ("reviewed" as const)
      : reviewProgress !== null
        ? ("reviewing" as const)
        : ("prepared" as const);
  const payload = ReviewCheckpointPayloadSchema.parse({
    schema_version: 1,
    review_protocol_version: 2,
    phase,
    created_at: createdAt,
    expires_at: expiresAt,
    request,
    review_identity: reviewIdentity,
    session_id: validated.prepared.session_id,
    evidence_digest: validated.evidence.evidence_digest,
    files: {
      prepared,
      evidence_context: evidenceContext,
      review_progress: reviewProgress,
      review,
    },
  });
  validatePayloadFiles(payload);
  const encrypted = encryptTransport(
    payload,
    key,
    checkpointContext(request, reviewIdentity),
  );
  return {
    encrypted,
    phase,
    session_id: payload.session_id,
    evidence_digest: payload.evidence_digest,
    ciphertext_sha256: digest(encrypted),
    created_at: payload.created_at,
    expires_at: payload.expires_at,
  };
}

export async function restoreReviewCheckpoint({
  encrypted,
  sessionRoot: sessionRootInput,
  expectedRequest: requestInput,
  expectedReviewIdentity: identityInput,
  key,
  now,
}: {
  encrypted: Buffer;
  sessionRoot: string;
  expectedRequest: unknown;
  expectedReviewIdentity: unknown;
  key: Buffer;
  now: string;
}) {
  const request = ScanRequestSchema.parse(requestInput);
  const reviewIdentity = ReviewCheckpointIdentitySchema.parse(identityInput);
  const payload = ReviewCheckpointPayloadSchema.parse(
    decryptTransport(
      encrypted,
      key,
      checkpointContext(request, reviewIdentity),
    ),
  );
  if (
    JSON.stringify(payload.request) !== JSON.stringify(request) ||
    JSON.stringify(payload.review_identity) !== JSON.stringify(reviewIdentity)
  )
    throw new Error("Review checkpoint expected identity does not match.");
  if (Date.parse(now) >= Date.parse(payload.expires_at))
    throw new Error("Review checkpoint has expired.");
  validatePayloadFiles(payload);
  const sessionRoot = safeSessionRoot(sessionRootInput);
  if (await exists(sessionRoot))
    throw new Error("Review checkpoint session directory must be absent.");
  let created = false;
  try {
    await mkdir(sessionRoot, { recursive: true });
    created = true;
    await writeFile(
      join(sessionRoot, "prepared.json"),
      `${JSON.stringify(payload.files.prepared, null, 2)}\n`,
      { flag: "wx" },
    );
    await writeFile(
      join(sessionRoot, "evidence-context.json"),
      `${JSON.stringify(payload.files.evidence_context, null, 2)}\n`,
      { flag: "wx" },
    );
    if (payload.files.review_progress !== null)
      await writeFile(
        join(sessionRoot, "review-progress.json"),
        `${JSON.stringify(payload.files.review_progress, null, 2)}\n`,
        { flag: "wx" },
      );
    if (payload.files.review !== null)
      await writeFile(
        join(sessionRoot, "review.json"),
        `${JSON.stringify(payload.files.review, null, 2)}\n`,
        { flag: "wx" },
      );
  } catch (error) {
    if (created) await rm(sessionRoot, { recursive: true, force: true });
    throw error;
  }
  return {
    phase: payload.phase,
    session_id: payload.session_id,
    evidence_digest: payload.evidence_digest,
    ciphertext_sha256: digest(encrypted),
    created_at: payload.created_at,
    expires_at: payload.expires_at,
  };
}
