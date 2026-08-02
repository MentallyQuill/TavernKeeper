import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, test } from "vitest";

import { loadScannerPolicy } from "../src/config/policy.js";
import { ScanReportV2Schema } from "../src/contracts/reports.js";
import { InMemoryModelChunkCache } from "../src/model/chunk-cache.js";
import { chunkCorpus } from "../src/model/chunker.js";
import {
  finalizePreparedSession,
  PreparedSessionSchema,
  preparedSessionIdentity,
  reviewPreparedSession,
} from "../src/orchestrator/session.js";

const roots: string[] = [];
const targetSha = "a".repeat(40);

afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

async function preparedSession({
  content = "line\n".repeat(12),
  chunkBytes = 524_288,
  overlapBytes = 8_192,
  findingLine = 1,
}: {
  content?: string;
  chunkBytes?: number;
  overlapBytes?: number;
  findingLine?: number;
} = {}) {
  const root = await mkdtemp(join(tmpdir(), "tavernkeeper-session-"));
  roots.push(root);
  await mkdir(join(root, "chunks"));
  const chunks = chunkCorpus(
    [
      {
        path: "src/index.ts",
        bytes: Buffer.byteLength(content),
        sha256: "d".repeat(64),
        kind: "text",
        content,
      },
    ],
    {
      chunkBytes,
      overlapBytes,
      promptPolicyVersion: "repository-review-v2",
      scannerPolicyVersion: "1",
    },
  );
  await Promise.all(
    chunks.map((chunk, index) =>
      writeFile(
        join(root, "chunks", `${index.toString().padStart(6, "0")}.json`),
        JSON.stringify(chunk),
      ),
    ),
  );
  const base = {
    schema_version: 3 as const,
    target: {
      source_id: "github-42",
      provider: "github" as const,
      repository_id: 42,
      repository: "owner/repo",
      target_sha: targetSha,
      canonical_url: "https://github.com/owner/repo",
    },
    project_kinds: ["extension"] as const,
    prepared_at: "2026-07-31T15:00:00.000Z",
    scanner_version: "1.0.0",
    scanner_policy_version: "1",
    prompt_policy_version: "repository-review-v2",
    report_version: 1,
    supersedes_report_id: null,
    mode: "standard" as const,
    history: { base_sha: null, commits: 20 },
    inventory: {
      files: 1,
      bytes: Buffer.byteLength(content),
      eligible_text_files: 1,
      eligible_text_bytes: Buffer.byteLength(content),
      excluded: {
        dependency_lockfiles: { files: 0, bytes: 0 },
        vendored_dependencies: { files: 0, bytes: 0 },
        generated_bundles: { files: 0, bytes: 0 },
        minified_files: { files: 0, bytes: 0 },
        binaries: { files: 0, bytes: 0 },
        archives: { files: 0, bytes: 0 },
        oversized_files: { files: 0, bytes: 0 },
        unsafe_entries: { files: 0, bytes: 0 },
      },
    },
    tools: [
      { name: "inventory", version: "1.0.0", status: "completed" as const },
      {
        name: "tavernkeeper-static",
        version: "1",
        status: "completed" as const,
      },
    ],
    deterministic_findings: [
      {
        origin: "tavernkeeper",
        rule_id: "credential-exfiltration",
        category: "credential-theft",
        severity: "high" as const,
        confidence: "high" as const,
        path: "src/index.ts",
        line_start: findingLine,
        line_end: findingLine,
        evidence_sha: null,
        title: "Credential access and network transmission in one file",
        explanation:
          "Credential source and outbound network sink appear in the same file.",
        fingerprint: "b".repeat(64),
        disposition: "active" as const,
      },
    ],
    selected_files: [
      {
        path: "src/index.ts",
        bytes: Buffer.byteLength(content),
        sha256: "d".repeat(64),
      },
    ],
    chunks: chunks.map((chunk, index) => ({
      id: chunk.id,
      file: `chunks/${index.toString().padStart(6, "0")}.json`,
      bytes: chunk.bytes,
      content_hashes: chunk.content_hashes,
      paths: ["src/index.ts"],
    })),
  };
  const prepared = PreparedSessionSchema.parse({
    ...base,
    session_id: preparedSessionIdentity(base),
  });
  await writeFile(
    join(root, "prepared.json"),
    `${JSON.stringify(prepared, null, 2)}\n`,
  );
  return { root, prepared, chunks };
}

function completionDoubles(calls: string[]) {
  const complete = (content: string) => ({
    content,
    usage: {
      inputTokens: 10,
      outputTokens: 2,
      cacheReadTokens: 0,
      reasoningTokens: 1,
    },
    completionId: `completion-${calls.length}`,
    endpointOrigin: "https://provider.example",
    provider: "provider.example",
  });
  return {
    text: async () => {
      calls.push("text");
      return complete("No review-level concern appears in this chunk.");
    },
    structured: async () => {
      calls.push("synthesis");
      return complete(
        JSON.stringify({
          assessment: "no_concerning_evidence",
          recap: "The completed review found no review-level concern.",
          concerns: [],
        }),
      );
    },
  };
}

describe("ephemeral split scan session", () => {
  test("binds a later-file finding to the chunk containing its exact line", async () => {
    const { root, prepared, chunks } = await preparedSession({
      content: Array.from(
        { length: 12 },
        (_, index) => `line-${String(index + 1).padStart(2, "0")}\n`,
      ).join(""),
      chunkBytes: 32,
      overlapBytes: 0,
      findingLine: 10,
    });
    expect(chunks.length).toBeGreaterThan(1);
    const containingChunk = chunks.find((chunk) =>
      chunk.segments.some(
        (segment) => segment.line_start <= 10 && segment.line_end >= 10,
      ),
    );
    expect(containingChunk).toBeDefined();
    const observedEvidence: unknown[] = [];
    const calls: string[] = [];
    const completions = completionDoubles(calls);
    const policy = await loadScannerPolicy(
      fileURLToPath(
        new URL("../config/scanner-policy.v1.json", import.meta.url),
      ),
    );

    await reviewPreparedSession({
      sessionRoot: root,
      manifest: {
        schema_version: 2,
        generated_at: "2026-07-31T15:30:00.000Z",
        repositories: [
          {
            ...prepared.target,
            project_kinds: ["extension"],
            catalog_priority: {
              top_30: false,
              first_cataloged_at: "2026-07-01T00:00:00.000Z",
            },
          },
        ],
      },
      endpoint: "https://provider.example/v1/chat/completions",
      apiKey: "test-key",
      model: "vendor/model-test",
      policy,
      cache: new InMemoryModelChunkCache(),
      requestTextCompletion: (async (request: { userContent: string }) => {
        const input = JSON.parse(request.userContent) as any;
        observedEvidence.push(...input.tool_evidence);
        return completions.text();
      }) as never,
      requestStructuredCompletion: completions.structured as never,
      verifyHead: async () => ({ ok: true, value: targetSha }),
    });

    expect(observedEvidence).toEqual([
      expect.objectContaining({
        path: "src/index.ts",
        line_start: 10,
        line_end: 10,
        id: "tool-000001",
        source_id: expect.stringMatching(/^source-[0-9]{6}$/u),
        target_sha: targetSha,
      }),
    ]);
  });

  test("streams every chunk through model review and finalizes a complete candidate", async () => {
    const { root, prepared } = await preparedSession();
    const calls: string[] = [];
    const completions = completionDoubles(calls);
    const policy = await loadScannerPolicy(
      fileURLToPath(
        new URL("../config/scanner-policy.v1.json", import.meta.url),
      ),
    );
    const review = await reviewPreparedSession({
      sessionRoot: root,
      manifest: {
        schema_version: 2,
        generated_at: "2026-07-31T15:30:00.000Z",
        repositories: [
          {
            ...prepared.target,
            project_kinds: ["extension"],
            catalog_priority: {
              top_30: false,
              first_cataloged_at: "2026-07-01T00:00:00.000Z",
            },
          },
        ],
      },
      endpoint: "https://provider.example/v1/chat/completions",
      apiKey: "test-key",
      model: "vendor/model-test",
      policy,
      cache: new InMemoryModelChunkCache(),
      requestTextCompletion: completions.text as never,
      requestStructuredCompletion: completions.structured as never,
      verifyHead: async () => ({ ok: true, value: targetSha }),
    });

    expect(calls).toEqual(["text", "synthesis"]);
    expect(review).toMatchObject({
      schema_version: 3,
      stage_completion: {
        chunk_review: { required: 1, completed: 1 },
        synthesis: { required: 1, completed: 1 },
      },
    });
    expect(JSON.stringify(review)).not.toMatch(/segments|content|test-key/iu);
    const output = join(root, "..", `candidate-${Date.now()}.json`);
    const finalized = await finalizePreparedSession({
      sessionRoot: root,
      review,
      output,
      completedAt: "2026-07-31T16:00:00.000Z",
    });

    expect(finalized.status).toBe("completed");
    expect(
      finalized.status === "completed" &&
        ScanReportV2Schema.safeParse(finalized.candidate.report).success,
    ).toBe(true);
    await expect(readFile(join(root, "prepared.json"))).rejects.toMatchObject({
      code: "ENOENT",
    });
    await rm(output, { force: true });
  });

  test("finishes the exact prepared SHA when Tavernary has already advanced", async () => {
    const { root, prepared } = await preparedSession();
    const calls: string[] = [];
    const completions = completionDoubles(calls);
    const policy = await loadScannerPolicy(
      fileURLToPath(
        new URL("../config/scanner-policy.v1.json", import.meta.url),
      ),
    );

    const review = await reviewPreparedSession({
      sessionRoot: root,
      manifest: {
        schema_version: 2,
        generated_at: "2026-07-31T15:30:00.000Z",
        repositories: [
          {
            ...prepared.target,
            target_sha: "c".repeat(40),
            project_kinds: ["extension"],
            catalog_priority: {
              top_30: false,
              first_cataloged_at: "2026-07-01T00:00:00.000Z",
            },
          },
        ],
      },
      endpoint: "https://provider.example/v1/chat/completions",
      apiKey: "test-key",
      model: "vendor/model-test",
      policy,
      cache: new InMemoryModelChunkCache(),
      requestTextCompletion: completions.text as never,
      requestStructuredCompletion: completions.structured as never,
      verifyHead: async () => ({ ok: true, value: targetSha }),
    });

    expect(review).toMatchObject({ status: "completed" });
    expect(calls).toEqual(["text", "synthesis"]);
  });
});
