import { describe, expect, test } from "vitest";

import type { ModelChunk } from "../src/model/chunker.js";
import {
  buildEvidenceManifest,
  scannerEvidenceForChunk,
  sourceEvidenceForChunk,
} from "../src/model/evidence-manifest.js";
import { normalizeFinding } from "../src/scanners/types.js";

const targetSha = "a".repeat(40);

function chunk(
  id: string,
  path: string,
  lineStart: number,
  lineEnd: number,
  contentDigest: string,
): ModelChunk {
  return {
    id,
    bytes: 10,
    content_hashes: [contentDigest],
    segments: [
      {
        path,
        line_start: lineStart,
        line_end: lineEnd,
        content: "redacted\n",
        bytes: 9,
        overlap_bytes: 0,
        content_hash: contentDigest,
        source_sha256: "f".repeat(64),
      },
    ],
  };
}

const finding = normalizeFinding({
  origin: "opengrep",
  ruleId: "unsafe-call",
  category: "unsafe-execution",
  severity: "high",
  confidence: "high",
  path: "src/a.ts",
  lineStart: 2,
  lineEnd: 2,
  evidenceSha: null,
  title: "Unsafe call",
  explanation: "An unsafe call was detected.",
});

describe("evidence manifest", () => {
  test("assigns deterministic evidence IDs independent of input order", () => {
    const chunks = [
      chunk("chunk-b", "src/b.ts", 1, 3, "2".repeat(64)),
      chunk("chunk-a", "src/a.ts", 1, 4, "1".repeat(64)),
    ];

    const manifest = buildEvidenceManifest(chunks, [finding], targetSha);
    const reversed = buildEvidenceManifest(
      chunks.toReversed(),
      [finding].toReversed(),
      targetSha,
    );

    expect(manifest).toEqual(reversed);
    expect(manifest.sources.map(({ id }) => id)).toEqual([
      "source-000001",
      "source-000002",
    ]);
    expect(manifest.scannerSignals.map(({ id }) => id)).toEqual([
      "tool-000001",
    ]);
    expect(manifest.sources[0]).toMatchObject({
      id: "source-000001",
      chunk_id: "chunk-a",
      segment_index: 0,
      path: "src/a.ts",
      line_start: 1,
      line_end: 4,
      content_digest: "1".repeat(64),
      source_sha256: "f".repeat(64),
      target_sha: targetSha,
    });
    expect(manifest.scannerSignals[0]).toMatchObject({
      id: "tool-000001",
      fingerprint: finding.fingerprint,
      target_sha: targetSha,
      source_id: "source-000001",
    });
  });

  test("projects chunk source without exposing its inventory hash", () => {
    const manifest = buildEvidenceManifest(
      [chunk("chunk-a", "src/a.ts", 1, 4, "1".repeat(64))],
      [],
      targetSha,
    );

    expect(sourceEvidenceForChunk(manifest, "chunk-a")).toEqual([
      {
        id: "source-000001",
        chunk_id: "chunk-a",
        path: "src/a.ts",
        line_start: 1,
        line_end: 4,
        content: "redacted\n",
        content_digest: "1".repeat(64),
        target_sha: targetSha,
      },
    ]);
  });

  test("projects scanner evidence for its containing chunk without the raw fingerprint", () => {
    const manifest = buildEvidenceManifest(
      [chunk("chunk-a", "src/a.ts", 1, 4, "1".repeat(64))],
      [finding],
      targetSha,
    );

    expect(scannerEvidenceForChunk(manifest, "chunk-a")).toEqual([
      {
        id: "tool-000001",
        source_id: "source-000001",
        target_sha: targetSha,
        origin: "opengrep",
        rule_id: "unsafe-call",
        category: "unsafe-execution",
        severity: "high",
        confidence: "high",
        path: "src/a.ts",
        line_start: 2,
        line_end: 2,
        title: "Unsafe call",
        explanation: "An unsafe call was detected.",
      },
    ]);
  });

  test("keeps repository-wide scanner signals without attaching them to source", () => {
    const repositoryFinding = normalizeFinding({
      origin: "osv-scanner",
      ruleId: "known-vulnerability",
      category: "dependency-risk",
      severity: "medium",
      confidence: "high",
      path: "package-lock.json",
      lineStart: null,
      lineEnd: null,
      evidenceSha: null,
      title: "Known vulnerable dependency",
      explanation: "The dependency graph contains a known vulnerability.",
    });
    const manifest = buildEvidenceManifest(
      [chunk("chunk-a", "src/a.ts", 1, 4, "1".repeat(64))],
      [repositoryFinding],
      targetSha,
    );

    expect(manifest.scannerSignals[0]).toMatchObject({
      fingerprint: repositoryFinding.fingerprint,
      source_id: null,
    });
    expect(scannerEvidenceForChunk(manifest, "chunk-a")).toEqual([]);
  });
});
