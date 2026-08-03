import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, test } from "vitest";

import { ScanReportV4Schema } from "../src/contracts/reports.js";
import {
  finalizePreparedSession,
  PreparedSessionSchema,
  preparedSessionIdentity,
} from "../src/orchestrator/session.js";
import { findingFingerprint } from "../src/scanners/types.js";

const roots: string[] = [];
const targetSha = "a".repeat(40);

afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

async function preparedSession(options: { omitTool?: boolean } = {}) {
  const root = await mkdtemp(join(tmpdir(), "tavernkeeper-session-"));
  roots.push(root);
  const findingIdentity = {
    origin: "tavernkeeper",
    ruleId: "credential-exfiltration",
    path: "src/index.ts",
    lineStart: 1,
    lineEnd: 1,
    evidenceSha: null,
  };
  const tools = [
    { name: "inventory", version: "1.0.0", status: "completed" as const },
    { name: "tavernkeeper-static", version: "2", status: "completed" as const },
    { name: "gitleaks", version: "8.30.1", status: "completed" as const },
    { name: "opengrep", version: "1.26.0", status: "completed" as const },
    {
      name: "osv-scanner",
      version: "2.4.0",
      status: "not-applicable" as const,
    },
    { name: "zizmor", version: "1.28.0", status: "not-applicable" as const },
    {
      name: "malcontent",
      version: "1.25.7",
      status: "not-applicable" as const,
    },
  ];
  const base = {
    schema_version: 4 as const,
    target: {
      source_id: "github-42",
      provider: "github" as const,
      repository_id: 42,
      repository: "owner/repo",
      target_sha: targetSha,
      canonical_url: "https://github.com/owner/repo",
    },
    project_kinds: ["extension"] as const,
    prepared_at: "2026-08-02T15:00:00.000Z",
    scanner_version: "1.0.0",
    scanner_policy_version: "2",
    rule_catalog_version: "1",
    report_version: 1,
    supersedes_report_id: null,
    history: { base_sha: null, commits: 1 },
    inventory: {
      root: "repository",
      totals: { files: 1, bytes: 12 },
      files: [
        {
          path: "src/index.ts",
          bytes: 12,
          sha256: "b".repeat(64),
          kind: "text" as const,
          likely_minified: false,
          executable: false,
        },
      ],
    },
    classification: {
      first_party_text_paths: ["src/index.ts"],
      applicability: { osv: false, zizmor: false, malcontent: false },
      scanner_input_paths: { osv: [], zizmor: [], malcontent: [] },
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
    tools: options.omitTool ? tools.slice(0, -1) : tools,
    findings: [
      {
        origin: "tavernkeeper",
        rule_id: findingIdentity.ruleId,
        category: "credential-theft",
        severity: "high" as const,
        confidence: "high" as const,
        path: findingIdentity.path,
        line_start: 1,
        line_end: 1,
        evidence_sha: null,
        title: "Ignored scanner title",
        explanation: "Ignored scanner prose",
        fingerprint: findingFingerprint(findingIdentity),
      },
    ],
  };
  const prepared = {
    ...base,
    session_id: preparedSessionIdentity(base),
  };
  await writeFile(
    join(root, "prepared.json"),
    `${JSON.stringify(prepared, null, 2)}\n`,
  );
  return { root, prepared };
}

describe("two-phase deterministic scan session", () => {
  test("finalizes complete scanner evidence directly into a V4 candidate", async () => {
    const { root } = await preparedSession();
    const output = join(tmpdir(), `candidate-${Date.now()}.json`);
    roots.push(output);
    const finalized = await finalizePreparedSession({
      sessionRoot: root,
      output,
      completedAt: "2026-08-02T16:00:00.000Z",
      verifyHead: async () => ({ ok: true, value: targetSha }),
    });

    expect(finalized).toMatchObject({
      status: "completed",
      candidate: { report: { schema_version: 4, result: "red" } },
    });
    expect(
      finalized.status === "completed" &&
        ScanReportV4Schema.safeParse(finalized.candidate.report).success,
    ).toBe(true);
    expect(JSON.stringify(finalized)).not.toMatch(/model|prompt|mode/iu);
    expect(JSON.parse(await readFile(output, "utf8"))).toEqual(
      finalized.status === "completed" ? finalized.candidate : null,
    );
  });

  test("publishes the acquired SHA without consulting a newer manifest", async () => {
    const { root } = await preparedSession();
    const output = join(tmpdir(), `advanced-candidate-${Date.now()}.json`);
    roots.push(output);
    const finalized = await finalizePreparedSession({
      sessionRoot: root,
      output,
      completedAt: "2026-08-02T16:00:00.000Z",
      verifyHead: async () => ({ ok: true, value: targetSha }),
    });
    expect(finalized).toMatchObject({
      status: "completed",
      candidate: { report: { target_sha: targetSha } },
    });
  });

  test.each([
    ["head mismatch", false],
    ["missing required tool", true],
  ])("writes no candidate after %s", async (kind, omitTool) => {
    const { root } = await preparedSession({ omitTool });
    const output = join(tmpdir(), `rejected-candidate-${Date.now()}.json`);
    roots.push(output);
    await expect(
      finalizePreparedSession({
        sessionRoot: root,
        output,
        completedAt: "2026-08-02T16:00:00.000Z",
        verifyHead: async () =>
          kind === "head mismatch"
            ? { ok: false as const, error: { code: "HEAD_MISMATCH" } }
            : { ok: true as const, value: targetSha },
      }),
    ).rejects.toThrow();
    await expect(readFile(output)).rejects.toMatchObject({ code: "ENOENT" });
  });

  test("detects prepared-session evidence tampering", async () => {
    const { root, prepared } = await preparedSession();
    const tampered = structuredClone(prepared);
    tampered.findings[0]!.fingerprint = "f".repeat(64);
    tampered.session_id = preparedSessionIdentity(tampered);
    await writeFile(
      join(root, "prepared.json"),
      `${JSON.stringify(tampered, null, 2)}\n`,
    );
    const output = join(tmpdir(), `tampered-candidate-${Date.now()}.json`);
    roots.push(output);
    await expect(
      finalizePreparedSession({
        sessionRoot: root,
        output,
        completedAt: "2026-08-02T16:00:00.000Z",
        verifyHead: async () => ({ ok: true, value: targetSha }),
      }),
    ).rejects.toThrow(/fingerprint/iu);
    await expect(readFile(output)).rejects.toMatchObject({ code: "ENOENT" });
  });

  test("classifies deterministic report finalization failures without exposing evidence", async () => {
    const { root, prepared } = await preparedSession();
    const unsafeRuleId = `github_pat_${"x".repeat(20)}`;
    prepared.findings[0]!.rule_id = unsafeRuleId;
    prepared.findings[0]!.fingerprint = findingFingerprint({
      origin: prepared.findings[0]!.origin,
      ruleId: unsafeRuleId,
      path: prepared.findings[0]!.path,
      lineStart: prepared.findings[0]!.line_start,
      lineEnd: prepared.findings[0]!.line_end,
      evidenceSha: prepared.findings[0]!.evidence_sha,
    });
    prepared.session_id = preparedSessionIdentity(prepared);
    await writeFile(
      join(root, "prepared.json"),
      `${JSON.stringify(prepared, null, 2)}\n`,
    );
    const output = join(tmpdir(), `invalid-report-${Date.now()}.json`);
    roots.push(output);

    await expect(
      finalizePreparedSession({
        sessionRoot: root,
        output,
        completedAt: "2026-08-02T16:00:00.000Z",
        verifyHead: async () => ({ ok: true, value: targetSha }),
      }),
    ).rejects.toMatchObject({
      code: "REPORT_FINALIZATION_FAILED",
      scope: "system",
    });
    await expect(readFile(output)).rejects.toMatchObject({ code: "ENOENT" });
  });

  test("prepared persistence rejects model-era fields", async () => {
    const { prepared } = await preparedSession();
    expect(
      PreparedSessionSchema.safeParse({ ...prepared, unexpected_field: {} })
        .success,
    ).toBe(false);
    expect(
      PreparedSessionSchema.safeParse({
        ...prepared,
        prompt_policy_version: "x",
      }).success,
    ).toBe(false);
  });
});
