import { createHash } from "node:crypto";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, test } from "vitest";

import { buildEvidenceContextGroups } from "../src/context/evidence-context.js";
import { normalizeFinding } from "../src/scanners/types.js";

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

describe("evidence context builder", () => {
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
      ecosystem_context_version: "sillytavern-community-v1",
    });
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
});
