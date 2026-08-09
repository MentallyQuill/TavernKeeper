import { createHash } from "node:crypto";
import {
  access,
  mkdir,
  readFile,
  readdir,
  rm,
  stat,
  writeFile,
} from "node:fs/promises";
import { basename, join, resolve } from "node:path";

import { z } from "zod";

import {
  EvidenceContextBundleSchema,
  validatePreparedSessionEvidence,
} from "../orchestrator/session.js";
import { FailureDescriptorSchema } from "../operations/failure.js";
import { ScanRequestSchema, type ScanRequest } from "../cli/staff-request.js";
import {
  assertPreparedEvidenceArtifactSize,
  MAX_PREPARED_EVIDENCE_BYTES,
  MAX_PREPARED_MANIFEST_BYTES,
} from "./prepared-evidence-limits.js";

export {
  assertPreparedEvidenceArtifactSize,
  MAX_PREPARED_EVIDENCE_BYTES,
} from "./prepared-evidence-limits.js";

const DigestSchema = z.string().regex(/^[0-9a-f]{64}$/u);
const ByteCountSchema = z.number().int().nonnegative();
const FileDescriptorSchema = z.strictObject({
  bytes: ByteCountSchema,
  sha256: DigestSchema,
});

const PreparedArtifactManifestSchema = z.strictObject({
  schema_version: z.literal(1),
  request: ScanRequestSchema,
  status: z.literal("prepared"),
  session_id: DigestSchema,
  evidence_digest: DigestSchema,
  files: z.strictObject({
    prepared: FileDescriptorSchema,
    evidence_context: FileDescriptorSchema,
  }),
});

const FailedArtifactManifestSchema = z.strictObject({
  schema_version: z.literal(1),
  request: ScanRequestSchema,
  status: z.literal("failed"),
  failure: FailureDescriptorSchema,
});

export const PreparedEvidenceArtifactManifestSchema = z.discriminatedUnion(
  "status",
  [PreparedArtifactManifestSchema, FailedArtifactManifestSchema],
);

function digest(value: string | Buffer) {
  return createHash("sha256").update(value).digest("hex");
}

function sameRequest(left: ScanRequest, right: ScanRequest) {
  return JSON.stringify(left) === JSON.stringify(right);
}

async function pathExists(path: string) {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

async function readBounded(path: string, maximumBytes: number) {
  const metadata = await stat(path);
  if (!metadata.isFile() || metadata.size > maximumBytes)
    throw new Error("Prepared evidence artifact exceeded its size ceiling.");
  return readFile(path);
}

function requireSessionRoot(path: string) {
  const root = resolve(path);
  if (!basename(root).startsWith("tavernkeeper-session-"))
    throw new Error("Ephemeral session directory name is unsafe.");
  return root;
}

function requestTarget(request: ScanRequest) {
  return {
    source_id: request.source_id,
    provider: request.provider,
    repository_id: request.repository_id,
    repository: request.repository,
    target_sha: request.target_sha,
    canonical_url: request.canonical_url,
  };
}

async function requireEmptyArtifactRoot(artifactRootInput: string) {
  const artifactRoot = resolve(artifactRootInput);
  if (await pathExists(artifactRoot)) {
    if ((await readdir(artifactRoot)).length !== 0)
      throw new Error("Prepared evidence artifact directory is not empty.");
  } else {
    await mkdir(artifactRoot, { recursive: true });
  }
  return artifactRoot;
}

export async function createPreparedEvidenceArtifact({
  request: requestInput,
  sessionRoot: sessionRootInput,
  artifactRoot: artifactRootInput,
  maximumBytes = MAX_PREPARED_EVIDENCE_BYTES,
}: {
  request: unknown;
  sessionRoot: string;
  artifactRoot: string;
  maximumBytes?: number;
}) {
  const request = ScanRequestSchema.parse(requestInput);
  const sessionRoot = requireSessionRoot(sessionRootInput);
  const preparedBytes = await readBounded(
    join(sessionRoot, "prepared.json"),
    maximumBytes,
  );
  const remaining = maximumBytes - preparedBytes.byteLength;
  assertPreparedEvidenceArtifactSize(preparedBytes.byteLength, maximumBytes);
  const evidenceBytes = await readBounded(
    join(sessionRoot, "evidence-context.json"),
    remaining,
  );
  const { prepared, evidence } = validatePreparedSessionEvidence(
    JSON.parse(preparedBytes.toString("utf8")),
    JSON.parse(evidenceBytes.toString("utf8")),
  );
  if (
    JSON.stringify(prepared.target) !==
      JSON.stringify(requestTarget(request)) ||
    JSON.stringify(prepared.project_kinds) !==
      JSON.stringify(request.project_kinds) ||
    prepared.report_version !== request.report_version ||
    prepared.supersedes_report_id !== request.supersedes_report_id
  )
    throw new Error("Prepared evidence artifact does not match its request.");
  const manifest = PreparedArtifactManifestSchema.parse({
    schema_version: 1,
    request,
    status: "prepared",
    session_id: prepared.session_id,
    evidence_digest: evidence.evidence_digest,
    files: {
      prepared: {
        bytes: preparedBytes.byteLength,
        sha256: digest(preparedBytes),
      },
      evidence_context: {
        bytes: evidenceBytes.byteLength,
        sha256: digest(evidenceBytes),
      },
    },
  });
  const manifestBytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`);
  assertPreparedEvidenceArtifactSize(
    manifestBytes.byteLength +
      preparedBytes.byteLength +
      evidenceBytes.byteLength,
    maximumBytes,
  );
  const artifactRoot = await requireEmptyArtifactRoot(artifactRootInput);
  await writeFile(join(artifactRoot, "prepared.json"), preparedBytes, {
    flag: "wx",
  });
  await writeFile(join(artifactRoot, "evidence-context.json"), evidenceBytes, {
    flag: "wx",
  });
  await writeFile(join(artifactRoot, "manifest.json"), manifestBytes, {
    flag: "wx",
  });
  return manifest;
}

export async function createFailedPreparedEvidenceArtifact({
  request: requestInput,
  failure: failureInput,
  artifactRoot: artifactRootInput,
}: {
  request: unknown;
  failure: unknown;
  artifactRoot: string;
}) {
  const manifest = FailedArtifactManifestSchema.parse({
    schema_version: 1,
    request: ScanRequestSchema.parse(requestInput),
    status: "failed",
    failure: FailureDescriptorSchema.parse(failureInput),
  });
  const bytes = Buffer.from(`${JSON.stringify(manifest, null, 2)}\n`);
  assertPreparedEvidenceArtifactSize(bytes.byteLength);
  const artifactRoot = await requireEmptyArtifactRoot(artifactRootInput);
  await writeFile(join(artifactRoot, "manifest.json"), bytes, { flag: "wx" });
  return manifest;
}

export async function restorePreparedEvidenceArtifact({
  artifactRoot: artifactRootInput,
  sessionRoot: sessionRootInput,
  expectedRequest: expectedRequestInput,
  failureOutput,
  maximumBytes = MAX_PREPARED_EVIDENCE_BYTES,
}: {
  artifactRoot: string;
  sessionRoot: string;
  expectedRequest: unknown;
  failureOutput?: string;
  maximumBytes?: number;
}) {
  const artifactRoot = resolve(artifactRootInput);
  const expectedRequest = ScanRequestSchema.parse(expectedRequestInput);
  const manifestBytes = await readBounded(
    join(artifactRoot, "manifest.json"),
    Math.min(MAX_PREPARED_MANIFEST_BYTES, maximumBytes),
  );
  const manifest = PreparedEvidenceArtifactManifestSchema.parse(
    JSON.parse(manifestBytes.toString("utf8")),
  );
  if (!sameRequest(manifest.request, expectedRequest))
    throw new Error("Prepared evidence artifact request does not match.");
  if (manifest.status === "failed") {
    const names = (await readdir(artifactRoot)).sort();
    if (JSON.stringify(names) !== JSON.stringify(["manifest.json"]))
      throw new Error("Failed prepared artifact contains unexpected files.");
    if (failureOutput !== undefined)
      await writeFile(
        failureOutput,
        `${JSON.stringify(manifest.failure, null, 2)}\n`,
        { flag: "wx" },
      );
    return { status: "failed" as const, failure: manifest.failure };
  }
  const names = (await readdir(artifactRoot)).sort();
  if (
    JSON.stringify(names) !==
    JSON.stringify(["evidence-context.json", "manifest.json", "prepared.json"])
  )
    throw new Error("Prepared evidence artifact contains unexpected files.");
  const preparedBytes = await readBounded(
    join(artifactRoot, "prepared.json"),
    maximumBytes,
  );
  const evidenceBytes = await readBounded(
    join(artifactRoot, "evidence-context.json"),
    maximumBytes,
  );
  assertPreparedEvidenceArtifactSize(
    manifestBytes.byteLength +
      preparedBytes.byteLength +
      evidenceBytes.byteLength,
    maximumBytes,
  );
  if (
    preparedBytes.byteLength !== manifest.files.prepared.bytes ||
    digest(preparedBytes) !== manifest.files.prepared.sha256 ||
    evidenceBytes.byteLength !== manifest.files.evidence_context.bytes ||
    digest(evidenceBytes) !== manifest.files.evidence_context.sha256
  )
    throw new Error("Prepared evidence artifact file digest does not match.");
  const { prepared, evidence } = validatePreparedSessionEvidence(
    JSON.parse(preparedBytes.toString("utf8")),
    JSON.parse(evidenceBytes.toString("utf8")),
  );
  if (
    prepared.session_id !== manifest.session_id ||
    evidence.evidence_digest !== manifest.evidence_digest ||
    JSON.stringify(prepared.target) !==
      JSON.stringify(requestTarget(expectedRequest))
  )
    throw new Error("Prepared evidence artifact identity does not match.");
  const sessionRoot = requireSessionRoot(sessionRootInput);
  if (await pathExists(sessionRoot))
    throw new Error("Ephemeral session directory must be absent.");
  let created = false;
  try {
    await mkdir(sessionRoot, { recursive: true });
    created = true;
    await writeFile(join(sessionRoot, "prepared.json"), preparedBytes, {
      flag: "wx",
    });
    await writeFile(join(sessionRoot, "evidence-context.json"), evidenceBytes, {
      flag: "wx",
    });
    return {
      status: "prepared" as const,
      session_id: prepared.session_id,
      evidence_digest: evidence.evidence_digest,
    };
  } catch (error) {
    if (created) await rm(sessionRoot, { recursive: true, force: true });
    throw error;
  }
}
