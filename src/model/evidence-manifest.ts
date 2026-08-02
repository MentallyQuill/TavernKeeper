import type { Finding } from "../contracts/reports.js";
import type { ModelChunk } from "./chunker.js";

export interface SourceEvidenceBinding {
  readonly id: string;
  readonly chunk_id: string;
  readonly segment_index: number;
  readonly path: string;
  readonly line_start: number;
  readonly line_end: number;
  readonly content: string;
  readonly content_digest: string;
  readonly source_sha256: string;
  readonly target_sha: string;
}

export interface ScannerSignalBinding extends Finding {
  readonly id: string;
  readonly target_sha: string;
  readonly source_id: string | null;
}

export interface EvidenceManifest {
  readonly sources: readonly SourceEvidenceBinding[];
  readonly scannerSignals: readonly ScannerSignalBinding[];
}

function compareText(left: string, right: string) {
  return left === right ? 0 : left < right ? -1 : 1;
}

function compareSource(
  left: Omit<SourceEvidenceBinding, "id">,
  right: Omit<SourceEvidenceBinding, "id">,
) {
  return (
    compareText(left.path.toLowerCase(), right.path.toLowerCase()) ||
    compareText(left.path, right.path) ||
    left.line_start - right.line_start ||
    left.line_end - right.line_end ||
    compareText(left.content_digest, right.content_digest) ||
    compareText(left.chunk_id, right.chunk_id) ||
    left.segment_index - right.segment_index
  );
}

function compareFinding(left: Finding, right: Finding) {
  return (
    compareText(left.path.toLowerCase(), right.path.toLowerCase()) ||
    compareText(left.path, right.path) ||
    (left.line_start ?? Number.MAX_SAFE_INTEGER) -
      (right.line_start ?? Number.MAX_SAFE_INTEGER) ||
    (left.line_end ?? Number.MAX_SAFE_INTEGER) -
      (right.line_end ?? Number.MAX_SAFE_INTEGER) ||
    compareText(left.fingerprint, right.fingerprint)
  );
}

export function buildEvidenceManifest(
  chunks: readonly ModelChunk[],
  findings: readonly Finding[],
  targetSha: string,
): EvidenceManifest {
  const sources = chunks
    .flatMap((chunk) =>
      chunk.segments.map((segment, segmentIndex) => ({
        chunk_id: chunk.id,
        segment_index: segmentIndex,
        path: segment.path,
        line_start: segment.line_start,
        line_end: segment.line_end,
        content: segment.content,
        content_digest: segment.content_hash,
        source_sha256: segment.source_sha256,
        target_sha: targetSha,
      })),
    )
    .sort(compareSource)
    .map((source, index) => ({
      id: `source-${String(index + 1).padStart(6, "0")}`,
      ...source,
    }));

  const scannerSignals = [...findings]
    .sort(compareFinding)
    .map((finding, index) => {
      const containingSource =
        finding.line_start !== null && finding.line_end !== null
          ? sources.find(
              (source) =>
                source.path === finding.path &&
                source.line_start <= finding.line_start! &&
                source.line_end >= finding.line_end!,
            )
          : undefined;
      return {
        id: `tool-${String(index + 1).padStart(6, "0")}`,
        ...finding,
        target_sha: targetSha,
        source_id: containingSource?.id ?? null,
      };
    });

  return { sources, scannerSignals };
}

export function sourceEvidenceForChunk(
  manifest: EvidenceManifest,
  chunkId: string,
) {
  return manifest.sources
    .filter(({ chunk_id }) => chunk_id === chunkId)
    .map(
      ({
        source_sha256: _sourceSha256,
        segment_index: _segmentIndex,
        ...source
      }) => source,
    );
}

export function scannerEvidenceForChunk(
  manifest: EvidenceManifest,
  chunkId: string,
) {
  const sourceIds = new Set(
    manifest.sources
      .filter(({ chunk_id }) => chunk_id === chunkId)
      .map(({ id }) => id),
  );
  return manifest.scannerSignals
    .filter(({ source_id }) => source_id !== null && sourceIds.has(source_id))
    .map(
      ({
        fingerprint: _fingerprint,
        evidence_sha: _evidenceSha,
        disposition: _disposition,
        adjudication: _adjudication,
        ...signal
      }) => signal,
    );
}
