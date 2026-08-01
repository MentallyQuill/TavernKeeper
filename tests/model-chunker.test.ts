import { describe, expect, test } from "vitest";

import { chunkCorpus, type ModelCorpusFile } from "../src/model/chunker.js";

function file(path: string, content: string): ModelCorpusFile {
  return {
    path,
    content,
    bytes: Buffer.byteLength(content),
    sha256: "a".repeat(64),
    kind: "text",
  };
}

const policy = {
  chunkBytes: 64,
  overlapBytes: 8,
  modelIdentifier: "deepseek/deepseek-v4-flash",
  promptPolicyVersion: "1",
  scannerPolicyVersion: "1",
};

describe("deterministic model chunking", () => {
  test("is stable across input order and keeps every chunk within its byte ceiling", () => {
    const files = [
      file("src/b.ts", "b();\n".repeat(12)),
      file("package.json", '{"name":"test"}\n'),
      file("src/a.ts", "a();\n".repeat(12)),
    ];

    const first = chunkCorpus(files, policy);
    const second = chunkCorpus([...files].reverse(), policy);

    expect(first).toEqual(second);
    expect(first.every((chunk) => chunk.bytes <= policy.chunkBytes)).toBe(true);
    expect(
      new Set(first.flatMap((chunk) => chunk.segments.map(({ path }) => path))),
    ).toEqual(new Set(files.map(({ path }) => path)));
    expect(first.every((chunk) => /^[0-9a-f]{64}$/u.test(chunk.id))).toBe(true);
  });

  test("splits oversized files on stable ranges with bounded overlap", () => {
    const [source] = chunkCorpus(
      [
        file(
          "src/large.ts",
          "line-01\nline-02\nline-03\nline-04\nline-05\nline-06\n",
        ),
      ],
      { ...policy, chunkBytes: 24, overlapBytes: 8 },
    );
    const chunks = chunkCorpus(
      [
        file(
          "src/large.ts",
          "line-01\nline-02\nline-03\nline-04\nline-05\nline-06\n",
        ),
      ],
      { ...policy, chunkBytes: 24, overlapBytes: 8 },
    );
    const segments = chunks.flatMap((chunk) => chunk.segments);

    expect(source).toBeDefined();
    expect(segments.length).toBeGreaterThan(1);
    expect(segments[0]?.line_start).toBe(1);
    expect(segments.at(-1)?.line_end).toBe(6);
    expect(segments.every((segment) => segment.bytes <= 24)).toBe(true);
    expect(
      segments.slice(1).every((segment) => segment.overlap_bytes <= 8),
    ).toBe(true);
  });
});
