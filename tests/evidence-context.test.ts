import { createHash } from "node:crypto";
import { mkdtemp, open, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, test } from "vitest";

import {
  buildEvidenceContextGroups,
  EvidenceContextGroupsSchema,
  expandEvidenceContextGroup,
} from "../src/context/evidence-context.js";
import { normalizeFinding } from "../src/scanners/types.js";

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

describe("evidence context builder", () => {
  test("preserves a non-text scanner finding as verified metadata-only evidence", async () => {
    const root = await mkdtemp(join(tmpdir(), "tavernkeeper-binary-context-"));
    roots.push(root);
    const binary = Buffer.from([0, 1, 2, 3]);
    await writeFile(join(root, "payload.bin"), binary);
    const finding = normalizeFinding({
      origin: "malcontent",
      ruleId: "binary-payload",
      category: "malware",
      severity: "high",
      confidence: "medium",
      path: "payload.bin",
      lineStart: null,
      lineEnd: null,
      evidenceSha: null,
      title: "Binary payload",
      explanation: "A scanner identified a binary payload.",
    });

    const groups = await buildEvidenceContextGroups({
      checkoutRoot: root,
      target: {
        source_id: "github-42",
        provider: "github",
        repository_id: 42,
        repository: "owner/repo",
        canonical_url: "https://github.com/owner/repo",
        target_sha: "a".repeat(40),
      },
      projectKinds: ["extension"],
      findings: [finding],
      inventory: {
        root,
        files: [
          {
            path: "payload.bin",
            bytes: binary.byteLength,
            sha256: createHash("sha256").update(binary).digest("hex"),
            kind: "binary",
          },
        ],
        totals: { files: 1, bytes: binary.byteLength },
        totalBytes: binary.byteLength,
      },
    });

    expect(groups).toHaveLength(1);
    expect(groups[0]).toMatchObject({
      path: "payload.bin",
      source_kind: "metadata-only",
      source_bytes: binary.byteLength,
      source_sha256: createHash("sha256").update(binary).digest("hex"),
    });
    expect(groups[0]?.candidates).toHaveLength(1);
    expect(groups[0]?.context.imports).toBe("");
    expect(groups[0]?.context.source).toMatch(/non-text artifact/iu);
    expect(groups[0]?.context.source).toMatch(/raw contents.*not provided/iu);
    expect(groups[0]?.context.source).not.toContain(binary.toString("utf8"));
    expect(groups[0]?.context.expansions).toEqual([
      groups[0]?.context.source,
      groups[0]?.context.source,
    ]);
  });

  test("streams metadata-only verification beyond the prepared-artifact ceiling", async () => {
    const root = await mkdtemp(join(tmpdir(), "tavernkeeper-large-binary-"));
    roots.push(root);
    const bytes = 24 * 1024 * 1024;
    const path = join(root, "large-payload.bin");
    const handle = await open(path, "w");
    await handle.truncate(bytes);
    await handle.close();
    const hash = createHash("sha256");
    const zeroChunk = Buffer.alloc(64 * 1024);
    for (let offset = 0; offset < bytes; offset += zeroChunk.byteLength)
      hash.update(zeroChunk);
    const finding = normalizeFinding({
      origin: "malcontent",
      ruleId: "large-binary-payload",
      category: "malware",
      severity: "high",
      confidence: "medium",
      path: "large-payload.bin",
      lineStart: null,
      lineEnd: null,
      evidenceSha: null,
      title: "Large binary payload",
      explanation: "A scanner identified a large binary payload.",
    });

    const groups = await buildEvidenceContextGroups({
      checkoutRoot: root,
      target: {
        source_id: "github-43",
        provider: "github",
        repository_id: 43,
        repository: "owner/large-binary",
        canonical_url: "https://github.com/owner/large-binary",
        target_sha: "b".repeat(40),
      },
      projectKinds: ["extension"],
      findings: [finding],
      inventory: {
        root,
        files: [
          {
            path: "large-payload.bin",
            bytes,
            sha256: hash.digest("hex"),
            kind: "oversized",
          },
        ],
        totals: { files: 1, bytes },
        totalBytes: bytes,
      },
    });

    expect(groups[0]).toMatchObject({
      source_kind: "metadata-only",
      source_bytes: bytes,
    });
    expect(groups[0]?.context.source.length).toBeLessThan(1_000);
  });

  test("groups findings by file with project and enclosing source context", async () => {
    const root = await mkdtemp(join(tmpdir(), "tavernkeeper-context-"));
    roots.push(root);
    const secret = `sk-nano-${"c".repeat(32)}`;
    const source = [
      'import { getToken } from "./settings.js";',
      `const accidentalSecret = "${secret}";`,
      "export async function sendRequest(url) {",
      "  const token = getToken();",
      "  return fetch(url, { headers: { authorization: token } });",
      "}",
      "",
    ].join("\n");
    const readme =
      "# Lore Helper\n\nSends selected lore to the user's configured model endpoint.\n";
    await writeFile(join(root, "client.ts"), source);
    await writeFile(join(root, "README.md"), readme);
    const findings = [
      normalizeFinding({
        origin: "tavernkeeper",
        ruleId: "credential-transmission",
        category: "credential-theft",
        severity: "high",
        confidence: "medium",
        path: "client.ts",
        lineStart: 4,
        lineEnd: 5,
        evidenceSha: null,
        title: "Credential reaches a request",
        explanation: "A credential-like value reaches a network request.",
      }),
      normalizeFinding({
        origin: "opengrep",
        ruleId: "network-call",
        category: "network-access",
        severity: "medium",
        confidence: "medium",
        path: "client.ts",
        lineStart: 5,
        lineEnd: 5,
        evidenceSha: null,
        title: "Network request",
        explanation: "The file makes a network request.",
      }),
    ];

    const groups = await buildEvidenceContextGroups({
      checkoutRoot: root,
      target: {
        source_id: "github-42",
        provider: "github",
        repository_id: 42,
        repository: "owner/lore-helper",
        canonical_url: "https://github.com/owner/lore-helper",
        target_sha: "a".repeat(40),
      },
      projectKinds: ["extension"],
      findings,
      inventory: {
        root,
        files: [
          {
            path: "client.ts",
            bytes: Buffer.byteLength(source),
            sha256: createHash("sha256").update(source).digest("hex"),
            kind: "text",
          },
          {
            path: "README.md",
            bytes: Buffer.byteLength(readme),
            sha256: createHash("sha256").update(readme).digest("hex"),
            kind: "text",
          },
        ],
        totals: {
          files: 2,
          bytes: Buffer.byteLength(source) + Buffer.byteLength(readme),
        },
        totalBytes: Buffer.byteLength(source) + Buffer.byteLength(readme),
      },
    });

    expect(groups).toHaveLength(1);
    expect(groups[0]).toMatchObject({
      path: "client.ts",
      file_role: "production",
      target_sha: "a".repeat(40),
      source_bytes: Buffer.byteLength(source),
      source_sha256: createHash("sha256").update(source).digest("hex"),
      ecosystem_context_version: "sillytavern-community-v1",
    });
    expect(EvidenceContextGroupsSchema.parse(groups)).toEqual(groups);
    expect(groups[0]?.candidates).toHaveLength(2);
    expect(groups[0]?.context.source).toContain(
      "export async function sendRequest",
    );
    expect(groups[0]?.context.imports).toContain(
      'import { getToken } from "./settings.js";',
    );
    expect(groups[0]?.context.project_purpose).toContain("Lore Helper");
    expect(JSON.stringify(groups[0]?.context)).not.toContain(secret);
    expect(groups[0]?.context.source).toContain("[REDACTED_SECRET:");
  });

  test("expands source context without changing evidence identity", async () => {
    const root = await mkdtemp(join(tmpdir(), "tavernkeeper-expand-context-"));
    roots.push(root);
    const source = Array.from(
      { length: 500 },
      (_, index) => `const value${index + 1} = ${index + 1};`,
    ).join("\n");
    await writeFile(join(root, "large.ts"), source);
    const finding = normalizeFinding({
      origin: "opengrep",
      ruleId: "network-call",
      category: "network-access",
      severity: "medium",
      confidence: "medium",
      path: "large.ts",
      lineStart: 250,
      lineEnd: 250,
      evidenceSha: null,
      title: "Network request",
      explanation: "The file makes a network request.",
    });
    const groups = await buildEvidenceContextGroups({
      checkoutRoot: root,
      target: {
        source_id: "github-44",
        provider: "github",
        repository_id: 44,
        repository: "owner/large-project",
        canonical_url: "https://github.com/owner/large-project",
        target_sha: "d".repeat(40),
      },
      projectKinds: ["extension"],
      findings: [finding],
      inventory: {
        root,
        files: [
          {
            path: "large.ts",
            bytes: Buffer.byteLength(source),
            sha256: createHash("sha256").update(source).digest("hex"),
            kind: "text",
          },
        ],
        totals: { files: 1, bytes: Buffer.byteLength(source) },
        totalBytes: Buffer.byteLength(source),
      },
    });
    const initial = groups[0]!;
    const expanded = expandEvidenceContextGroup(initial, 1);

    expect(expanded.group_id).toBe(initial.group_id);
    expect(expanded.candidates).toEqual(initial.candidates);
    expect(expanded.context.source.length).toBeGreaterThan(
      initial.context.source.length,
    );
  });

  test("bounds a multi-megabyte one-line derived finding by characters", async () => {
    const root = await mkdtemp(join(tmpdir(), "tavernkeeper-one-line-"));
    roots.push(root);
    const signal = "const t=process.env.API_TOKEN;fetch(endpoint,{body:t})";
    const source = `${"a".repeat(1_000_000)}${signal}${"b".repeat(1_000_000)}`;
    await writeFile(join(root, "app.min.js"), source);
    const finding = normalizeFinding({
      origin: "javascript-analysis",
      ruleId: "javascript.credential-to-network",
      category: "credential-theft",
      severity: "high",
      confidence: "medium",
      path: "app.min.js",
      lineStart: 1,
      lineEnd: 1,
      evidenceSha: null,
      title: "Credential and network behavior",
      explanation: "Credential access is correlated with a network sink.",
    });
    const sha256 = createHash("sha256").update(source).digest("hex");

    const groups = await buildEvidenceContextGroups({
      checkoutRoot: root,
      target: {
        source_id: "github-45",
        provider: "github",
        repository_id: 45,
        repository: "owner/one-line",
        canonical_url: "https://github.com/owner/one-line",
        target_sha: "e".repeat(40),
      },
      projectKinds: ["extension"],
      findings: [finding],
      inventory: {
        root,
        files: [
          {
            path: "app.min.js",
            bytes: Buffer.byteLength(source),
            sha256,
            kind: "text",
            likelyMinified: true,
          },
        ],
        totals: { files: 1, bytes: Buffer.byteLength(source) },
        totalBytes: Buffer.byteLength(source),
      },
      javascriptEvidenceHints: [
        {
          finding_fingerprint: finding.fingerprint,
          original_path: finding.path,
          stage: "raw",
          representation_sha256: sha256,
          transform_depth: 0,
          line_start: 1,
          line_end: 1,
          column_start: 1_000_001,
          column_end: 1_000_001 + signal.length,
          source,
        },
      ],
      maxEvidenceCharactersPerFinding: 24_000,
    });

    expect(groups[0]?.context.source.length).toBeLessThanOrEqual(24_000);
    expect(groups[0]?.context.source).toContain("fetch(endpoint");
    expect(groups[0]?.context.expansions).not.toEqual([]);
    expect(groups[0]?.context.representations).toEqual([
      { stage: "raw", sha256, transform_depth: 0 },
    ]);
  });

  test("rejects a JavaScript-analysis finding without bound representation evidence", async () => {
    const root = await mkdtemp(join(tmpdir(), "tavernkeeper-js-hint-"));
    roots.push(root);
    const source = "eval(payload)";
    await writeFile(join(root, "app.js"), source);
    const finding = normalizeFinding({
      origin: "javascript-analysis",
      ruleId: "javascript.xray.unsafe-stmt",
      category: "code-execution",
      severity: "medium",
      confidence: "medium",
      path: "app.js",
      lineStart: 1,
      lineEnd: 1,
      evidenceSha: null,
      title: "Dynamic execution",
      explanation: "A static analyzer found dynamic execution.",
    });

    await expect(
      buildEvidenceContextGroups({
        checkoutRoot: root,
        target: {
          source_id: "github-46",
          provider: "github",
          repository_id: 46,
          repository: "owner/missing-hint",
          canonical_url: "https://github.com/owner/missing-hint",
          target_sha: "f".repeat(40),
        },
        projectKinds: ["extension"],
        findings: [finding],
        inventory: {
          root,
          files: [
            {
              path: "app.js",
              bytes: Buffer.byteLength(source),
              sha256: createHash("sha256").update(source).digest("hex"),
              kind: "text",
            },
          ],
          totals: { files: 1, bytes: Buffer.byteLength(source) },
          totalBytes: Buffer.byteLength(source),
        },
      }),
    ).rejects.toThrow(/representation evidence/iu);
  });

  test("uses supplied historical source for a history finding", async () => {
    const root = await mkdtemp(join(tmpdir(), "tavernkeeper-history-context-"));
    roots.push(root);
    const current = "export function currentBehavior() { return true; }\n";
    const historical = [
      "export function historicalFlow(secret) {",
      '  return fetch("https://example.invalid", { body: secret });',
      "}",
    ].join("\n");
    await writeFile(join(root, "client.ts"), current);
    const evidenceSha = "b".repeat(40);
    const finding = normalizeFinding({
      origin: "gitleaks",
      ruleId: "generic-api-key",
      category: "credential-exposure",
      severity: "high",
      confidence: "high",
      path: "client.ts",
      lineStart: 1,
      lineEnd: 2,
      evidenceSha,
      title: "Potential credential exposure",
      explanation: "A secret pattern appeared in bounded history.",
    });

    const groups = await buildEvidenceContextGroups({
      checkoutRoot: root,
      target: {
        source_id: "github-42",
        provider: "github",
        repository_id: 42,
        repository: "owner/lore-helper",
        canonical_url: "https://github.com/owner/lore-helper",
        target_sha: "a".repeat(40),
      },
      projectKinds: ["extension"],
      findings: [finding],
      inventory: {
        root,
        files: [
          {
            path: "client.ts",
            bytes: Buffer.byteLength(current),
            sha256: createHash("sha256").update(current).digest("hex"),
            kind: "text",
          },
        ],
        totals: { files: 1, bytes: Buffer.byteLength(current) },
        totalBytes: Buffer.byteLength(current),
      },
      historicalSources: [
        {
          path: "client.ts",
          evidence_sha: evidenceSha,
          content: historical,
          bytes: Buffer.byteLength(historical),
          sha256: createHash("sha256").update(historical).digest("hex"),
        },
      ],
    });

    expect(groups[0]?.evidence_sha).toBe(evidenceSha);
    expect(groups[0]?.context.source).toContain("historicalFlow");
    expect(groups[0]?.context.source).not.toContain("currentBehavior");
  });

  test("splits a noisy file into bounded groups without dropping candidates", async () => {
    const root = await mkdtemp(join(tmpdir(), "tavernkeeper-noisy-context-"));
    roots.push(root);
    const source = Array.from(
      { length: 80 },
      (_, index) => `callEndpoint(${index + 1});`,
    ).join("\n");
    await writeFile(join(root, "noisy.ts"), source);
    const findings = Array.from({ length: 17 }, (_, index) =>
      normalizeFinding({
        origin: "opengrep",
        ruleId: "network-call",
        category: "network-access",
        severity: "medium",
        confidence: "medium",
        path: "noisy.ts",
        lineStart: index + 1,
        lineEnd: index + 1,
        evidenceSha: null,
        title: "Network request",
        explanation: "The file makes a network request.",
      }),
    );

    const groups = await buildEvidenceContextGroups({
      checkoutRoot: root,
      target: {
        source_id: "github-43",
        provider: "github",
        repository_id: 43,
        repository: "owner/noisy-project",
        canonical_url: "https://github.com/owner/noisy-project",
        target_sha: "c".repeat(40),
      },
      projectKinds: ["extension"],
      findings,
      inventory: {
        root,
        files: [
          {
            path: "noisy.ts",
            bytes: Buffer.byteLength(source),
            sha256: createHash("sha256").update(source).digest("hex"),
            kind: "text",
          },
        ],
        totals: { files: 1, bytes: Buffer.byteLength(source) },
        totalBytes: Buffer.byteLength(source),
      },
    });

    expect(groups).toHaveLength(3);
    expect(groups.every((item) => item.candidates.length <= 8)).toBe(true);
    expect(groups.flatMap((item) => item.candidates)).toHaveLength(17);
    expect(
      new Set(
        groups.flatMap((item) =>
          item.candidates.map((candidate) => candidate.candidate_id),
        ),
      ).size,
    ).toBe(17);
  });
});
