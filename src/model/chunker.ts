import { createHash } from "node:crypto";

import { redactSource } from "./redaction.js";
import type { ModelCorpusFile } from "./corpus.js";

export type { ModelCorpusFile } from "./corpus.js";

export interface ChunkPolicy {
  chunkBytes: number;
  overlapBytes: number;
  promptPolicyVersion: string;
  scannerPolicyVersion: string;
}

export interface ModelChunkSegment {
  path: string;
  line_start: number;
  line_end: number;
  content: string;
  bytes: number;
  overlap_bytes: number;
  content_hash: string;
  source_sha256: string;
}

export interface ModelChunk {
  id: string;
  bytes: number;
  content_hashes: string[];
  segments: ModelChunkSegment[];
}

function sha256(value: string) {
  return createHash("sha256").update(value).digest("hex");
}

function byteLength(value: string) {
  return Buffer.byteLength(value, "utf8");
}

function comparePath(left: string, right: string) {
  const leftIdentity = left.toLowerCase();
  const rightIdentity = right.toLowerCase();
  if (leftIdentity !== rightIdentity)
    return leftIdentity < rightIdentity ? -1 : 1;
  return left === right ? 0 : left < right ? -1 : 1;
}

function filePriority(path: string) {
  const name = path.slice(path.lastIndexOf("/") + 1).toLowerCase();
  if (/^(?:package|manifest|extension|pyproject|cargo|composer)\./u.test(name))
    return 0;
  if (/^(?:index|main|app|server|cli)\./u.test(name)) return 1;
  if (/^readme(?:\.|$)/u.test(name)) return 2;
  return 3;
}

function compareFiles(left: ModelCorpusFile, right: ModelCorpusFile) {
  const leftDirectory = left.path.slice(
    0,
    Math.max(0, left.path.lastIndexOf("/")),
  );
  const rightDirectory = right.path.slice(
    0,
    Math.max(0, right.path.lastIndexOf("/")),
  );
  const directoryOrder = comparePath(leftDirectory, rightDirectory);
  if (directoryOrder !== 0) return directoryOrder;
  const priority = filePriority(left.path) - filePriority(right.path);
  return priority === 0 ? comparePath(left.path, right.path) : priority;
}

function prefixWithinBytes(value: string, maximumBytes: number) {
  let usedBytes = 0;
  let usedCharacters = 0;
  let newlineCharacters = 0;
  for (const character of value) {
    const characterBytes = byteLength(character);
    if (usedBytes + characterBytes > maximumBytes) break;
    usedBytes += characterBytes;
    usedCharacters += character.length;
    if (character === "\n") newlineCharacters = usedCharacters;
  }
  if (usedCharacters === 0 && value.length > 0)
    throw new Error("Chunk byte ceiling cannot contain one UTF-8 code point.");
  const end = newlineCharacters > 0 ? newlineCharacters : usedCharacters;
  return value.slice(0, end);
}

function suffixStartWithinBytes(value: string, maximumBytes: number) {
  let start = value.length;
  let usedBytes = 0;
  while (start > 0) {
    let previous = start - 1;
    const code = value.charCodeAt(previous);
    if (code >= 0xdc00 && code <= 0xdfff && previous > 0) previous -= 1;
    const character = value.slice(previous, start);
    const characterBytes = byteLength(character);
    if (usedBytes + characterBytes > maximumBytes) break;
    usedBytes += characterBytes;
    start = previous;
  }
  return start;
}

function newlineOffsets(value: string) {
  const offsets: number[] = [];
  for (
    let index = value.indexOf("\n");
    index >= 0;
    index = value.indexOf("\n", index + 1)
  )
    offsets.push(index);
  return offsets;
}

function lineAt(offsets: number[], characterOffset: number) {
  let low = 0;
  let high = offsets.length;
  while (low < high) {
    const middle = Math.floor((low + high) / 2);
    if (offsets[middle]! < characterOffset) low = middle + 1;
    else high = middle;
  }
  return low + 1;
}

function endLine(startLine: number, content: string) {
  const newlineCount = (content.match(/\n/gu) ?? []).length;
  return startLine + newlineCount - (content.endsWith("\n") ? 1 : 0);
}

function splitFile(
  file: ModelCorpusFile,
  policy: ChunkPolicy,
): ModelChunkSegment[] {
  const content = redactSource(file.content);
  if (content.length === 0)
    return [
      {
        path: file.path,
        line_start: 1,
        line_end: 1,
        content: "",
        bytes: 0,
        overlap_bytes: 0,
        content_hash: sha256(""),
        source_sha256: file.sha256,
      },
    ];

  const segments: ModelChunkSegment[] = [];
  const lines = newlineOffsets(content);
  let primaryStart = 0;
  while (primaryStart < content.length) {
    const overlapStart =
      primaryStart === 0
        ? 0
        : suffixStartWithinBytes(
            content.slice(0, primaryStart),
            policy.overlapBytes,
          );
    const overlap = content.slice(overlapStart, primaryStart);
    const availableBytes = policy.chunkBytes - byteLength(overlap);
    const primary = prefixWithinBytes(
      content.slice(primaryStart),
      availableBytes,
    );
    const segmentContent = overlap + primary;
    const startLine = lineAt(lines, overlapStart);
    segments.push({
      path: file.path,
      line_start: startLine,
      line_end: endLine(startLine, segmentContent),
      content: segmentContent,
      bytes: byteLength(segmentContent),
      overlap_bytes: byteLength(overlap),
      content_hash: sha256(segmentContent),
      source_sha256: file.sha256,
    });
    primaryStart += primary.length;
  }
  return segments;
}

function finalizeChunk(
  segments: ModelChunkSegment[],
  policy: ChunkPolicy,
): ModelChunk {
  const bytes = segments.reduce((total, segment) => total + segment.bytes, 0);
  const identity = {
    prompt_policy: policy.promptPolicyVersion,
    scanner_policy: policy.scannerPolicyVersion,
    segments: segments.map((segment) => ({
      path: segment.path,
      line_start: segment.line_start,
      line_end: segment.line_end,
      content_hash: segment.content_hash,
      source_sha256: segment.source_sha256,
    })),
  };
  return {
    id: sha256(JSON.stringify(identity)),
    bytes,
    content_hashes: segments.map(({ content_hash }) => content_hash),
    segments,
  };
}

export function chunkCorpus(
  files: ModelCorpusFile[],
  policy: ChunkPolicy,
): ModelChunk[] {
  if (
    !Number.isInteger(policy.chunkBytes) ||
    !Number.isInteger(policy.overlapBytes) ||
    policy.chunkBytes < 4 ||
    policy.overlapBytes < 0 ||
    policy.overlapBytes >= policy.chunkBytes
  )
    throw new Error("Model chunk policy is invalid.");
  if (new Set(files.map(({ path }) => path)).size !== files.length)
    throw new Error("Model corpus paths must be unique.");

  const segments = [...files]
    .sort(compareFiles)
    .flatMap((file) => splitFile(file, policy));
  const chunks: ModelChunk[] = [];
  let pending: ModelChunkSegment[] = [];
  let pendingBytes = 0;
  for (const segment of segments) {
    if (
      pending.length > 0 &&
      pendingBytes + segment.bytes > policy.chunkBytes
    ) {
      chunks.push(finalizeChunk(pending, policy));
      pending = [];
      pendingBytes = 0;
    }
    pending.push(segment);
    pendingBytes += segment.bytes;
  }
  if (pending.length > 0) chunks.push(finalizeChunk(pending, policy));

  const selectedPaths = new Set(files.map(({ path }) => path));
  const chunkedPaths = new Set(
    chunks.flatMap(({ segments: values }) => values.map(({ path }) => path)),
  );
  if (
    selectedPaths.size !== chunkedPaths.size ||
    [...selectedPaths].some((path) => !chunkedPaths.has(path)) ||
    chunks.some(({ bytes }) => bytes > policy.chunkBytes)
  )
    throw new Error("Model chunking failed completeness checks.");
  return chunks;
}
