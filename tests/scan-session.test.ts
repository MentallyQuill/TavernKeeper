import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";

import { afterEach, describe, expect, test } from "vitest";

import { loadScannerPolicy } from "../src/config/policy.js";
import { ScanReportSchema } from "../src/contracts/reports.js";
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

async function preparedSession() {
  const root = await mkdtemp(join(tmpdir(), "tavernkeeper-session-"));
  roots.push(root);
  await mkdir(join(root, "chunks"));
  const content = "line\n".repeat(12);
  const [chunk] = chunkCorpus(
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
      chunkBytes: 524_288,
      overlapBytes: 8_192,
      promptPolicyVersion: "1",
      scannerPolicyVersion: "1",
    },
  );
  await writeFile(join(root, "chunks", "000000.json"), JSON.stringify(chunk));
  const base = {
    schema_version: 1 as const,
    target: {
      source_id: "github-42",
      provider: "github" as const,
      repository_id: 42,
      repository: "owner/repo",
      target_sha: targetSha,
      canonical_url: "https://github.com/owner/repo",
    },
    prepared_at: "2026-07-31T15:00:00.000Z",
    scanner_version: "1.0.0",
    scanner_policy_version: "1",
    prompt_policy_version: "1",
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
        line_start: 1,
        line_end: 1,
        evidence_sha: null,
        title: "Credential access and network transmission in one file",
        explanation:
          "Credential source and outbound network sink appear in the same file.",
        fingerprint: "b".repeat(64),
        disposition: "active" as const,
      },
    ],
    relationships: [],
    selected_files: [
      {
        path: "src/index.ts",
        bytes: Buffer.byteLength(content),
        sha256: "d".repeat(64),
      },
    ],
    chunks: [
      {
        id: chunk!.id,
        file: "chunks/000000.json",
        bytes: chunk!.bytes,
        content_hashes: chunk!.content_hashes,
        paths: ["src/index.ts"],
      },
    ],
  };
  const prepared = PreparedSessionSchema.parse({
    ...base,
    session_id: preparedSessionIdentity(base),
  });
  await writeFile(
    join(root, "prepared.json"),
    `${JSON.stringify(prepared, null, 2)}\n`,
  );
  return { root, prepared };
}

function completionDouble(calls: string[]) {
  return async (request: { schemaName: string }) => {
    calls.push(request.schemaName);
    return {
      content:
        request.schemaName === "tavernkeeper_chunk_findings"
          ? '{"findings":[]}'
          : '{"annotations":[]}',
      usage: {
        inputTokens: 10,
        outputTokens: 2,
        cacheReadTokens: 0,
        reasoningTokens: 1,
      },
      completionId: `completion-${calls.length}`,
      endpointOrigin: "https://provider.example",
      provider: "provider.example",
    };
  };
}

describe("ephemeral split scan session", () => {
  test("streams every chunk through model review and finalizes a complete candidate", async () => {
    const { root, prepared } = await preparedSession();
    const calls: string[] = [];
    const policy = await loadScannerPolicy(
      fileURLToPath(
        new URL("../config/scanner-policy.v1.json", import.meta.url),
      ),
    );
    const review = await reviewPreparedSession({
      sessionRoot: root,
      manifest: {
        schema_version: 1,
        generated_at: "2026-07-31T15:30:00.000Z",
        repositories: [prepared.target],
      },
      endpoint: "https://provider.example/v1/chat/completions",
      apiKey: "test-key",
      model: "vendor/model-test",
      policy,
      cache: new InMemoryModelChunkCache(),
      requestCompletion: completionDouble(calls) as never,
      verifyHead: async () => ({ ok: true, value: targetSha }),
    });

    expect(calls).toEqual([
      "tavernkeeper_chunk_findings",
      "tavernkeeper_synthesis",
    ]);
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
        ScanReportSchema.safeParse(finalized.candidate.report).success,
    ).toBe(true);
    await expect(readFile(join(root, "prepared.json"))).rejects.toMatchObject({
      code: "ENOENT",
    });
    await rm(output, { force: true });
  });

  test("spends no model tokens when Tavernary has already advanced the target", async () => {
    const { root, prepared } = await preparedSession();
    const calls: string[] = [];
    const policy = await loadScannerPolicy(
      fileURLToPath(
        new URL("../config/scanner-policy.v1.json", import.meta.url),
      ),
    );

    const review = await reviewPreparedSession({
      sessionRoot: root,
      manifest: {
        schema_version: 1,
        generated_at: "2026-07-31T15:30:00.000Z",
        repositories: [{ ...prepared.target, target_sha: "c".repeat(40) }],
      },
      endpoint: "https://provider.example/v1/chat/completions",
      apiKey: "test-key",
      model: "vendor/model-test",
      policy,
      cache: new InMemoryModelChunkCache(),
      requestCompletion: completionDouble(calls) as never,
      verifyHead: async () => ({ ok: true, value: targetSha }),
    });

    expect(review).toMatchObject({
      status: "obsolete",
      session_id: prepared.session_id,
    });
    expect(calls).toEqual([]);
  });
});
