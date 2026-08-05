import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, test } from "vitest";

import { ScanReportV5Schema } from "../src/contracts/reports-v5.js";
import {
  finalizePreparedSession,
  evidenceContextIdentity,
  PreparedSessionSchema,
  preparedSessionIdentity,
  reviewPreparedSession,
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
    schema_version: 5 as const,
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
    scanner_policy_version: "3",
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
  const groups = [
    {
      group_id: "c".repeat(64),
      repository: prepared.target.repository,
      project_kinds: [...prepared.project_kinds],
      path: findingIdentity.path,
      file_role: "production" as const,
      target_sha: targetSha,
      evidence_sha: targetSha,
      source_bytes: 12,
      source_sha256: "b".repeat(64),
      ecosystem_context_version: "sillytavern-community-v1" as const,
      ecosystem_context: "Trusted ecosystem context.",
      candidates: [
        {
          candidate_id: prepared.findings[0]!.fingerprint,
          evidence_id: prepared.findings[0]!.fingerprint,
          origin: prepared.findings[0]!.origin,
          rule_id: prepared.findings[0]!.rule_id,
          category: prepared.findings[0]!.category,
          scanner_severity: prepared.findings[0]!.severity,
          scanner_confidence: prepared.findings[0]!.confidence,
          title: prepared.findings[0]!.title,
          explanation: prepared.findings[0]!.explanation,
          line_start: 1,
          line_end: 1,
        },
      ],
      context: {
        imports: "",
        source: "     1 | sendCredential();",
        project_purpose: "An extension fixture.",
      },
    },
  ];
  await writeFile(
    join(root, "evidence-context.json"),
    `${JSON.stringify(
      {
        schema_version: 1,
        session_id: prepared.session_id,
        evidence_digest: evidenceContextIdentity({
          session_id: prepared.session_id,
          groups,
        }),
        groups,
      },
      null,
      2,
    )}\n`,
  );
  return { root, prepared };
}

async function completeReview(root: string) {
  return reviewPreparedSession({
    sessionRoot: root,
    provider: {
      endpoint: "https://provider.example/v1/chat/completions",
      apiKey: "test-key",
      model: "configured/model:thinking",
      resolveAddresses: async () => ["93.184.216.34"],
      requestCompletion: async (request) => {
        const evidence = JSON.parse(
          request.userContent.slice(
            request.userContent.indexOf("{"),
            request.userContent.lastIndexOf("}") + 1,
          ),
        ) as {
          candidates: Array<{ candidate_id: string; evidence_id: string }>;
          path: string;
        };
        return {
          completionId: "completion-session",
          endpointOrigin: "https://provider.example",
          provider: "provider.example",
          content: JSON.stringify({
            review: {
              status: "complete",
              assessments: evidence.candidates.map((candidate) => ({
                candidate_id: candidate.candidate_id,
                evidence_ids: [candidate.evidence_id],
                disposition: "minor_weakness",
                impact: "low",
                exploitability: "unlikely",
                confidence: "medium",
                recommended_risk: "low",
                technical_explanation: "The flow should be hardened.",
                layman_explanation: "This behavior deserves a small caution.",
                developer_action: "Document the destination.",
              })),
              observations: [],
            },
          }),
          usage: {
            inputTokens: 100,
            outputTokens: 50,
            cacheReadTokens: 0,
            reasoningTokens: 10,
          },
        };
      },
    },
    policy: {
      version: "2",
      promptVersion: "contextual-review-v3",
      schemaVersion: "contextual-assessment-v1",
      maxImmediateAttempts: 3,
      maxOutputTokens: 32_768,
      maxResponseBytes: 5_000_000,
      timeoutMs: 900_000,
    },
  });
}

describe("three-phase contextual scan session", () => {
  test("requires validated review before producing one V5 candidate", async () => {
    const { root, prepared } = await preparedSession();
    await completeReview(root);
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
      candidate: {
        report: {
          schema_version: 5,
          assessment_method: "deterministic-evidence-contextual-review",
          review_coverage: { required: 1, completed: 1 },
        },
      },
    });
    expect(
      finalized.status === "completed" &&
        ScanReportV5Schema.safeParse(finalized.candidate.report).success,
    ).toBe(true);
    expect(finalized.candidate.report.contextual_reviewer.model).toBe(
      "configured/model:thinking",
    );
    expect(JSON.stringify(prepared)).not.toMatch(
      /sendCredential|model|prompt/iu,
    );
    expect(JSON.stringify(finalized)).not.toMatch(/completion-session/iu);
    expect(JSON.parse(await readFile(output, "utf8"))).toEqual(
      finalized.status === "completed" ? finalized.candidate : null,
    );
  });

  test("resumes session-bound review progress without repeating completed groups", async () => {
    const { root, prepared } = await preparedSession();
    const evidence = JSON.parse(
      await readFile(join(root, "evidence-context.json"), "utf8"),
    ) as {
      evidence_digest: string;
      groups: Array<{
        group_id: string;
        path: string;
        candidates: Array<{ candidate_id: string; evidence_id: string }>;
      }>;
    };
    const current = evidence.groups[0]!;
    const candidate = current.candidates[0]!;
    await writeFile(
      join(root, "review-progress.json"),
      `${JSON.stringify(
        {
          schema_version: 1,
          session_id: prepared.session_id,
          evidence_digest: evidence.evidence_digest,
          progress: {
            policy_version: "2",
            prompt_version: "contextual-review-v3",
            schema_version: "contextual-assessment-v1",
            model: "configured/model:thinking",
            provider: "provider.example",
            endpoint_origin: "https://provider.example",
            completed_group_ids: [current.group_id],
            assessments: [
              {
                candidate_id: candidate.candidate_id,
                evidence_ids: [candidate.evidence_id],
                disposition: "minor_weakness",
                impact: "low",
                exploitability: "unlikely",
                confidence: "medium",
                recommended_risk: "low",
                technical_explanation: "The flow should be hardened.",
                layman_explanation: "This behavior deserves a small caution.",
                developer_action: "Document the destination.",
                locations: [{ path: current.path, line_start: 1, line_end: 1 }],
              },
            ],
            observations: [],
            usage: {
              inputTokens: 100,
              outputTokens: 50,
              cacheReadTokens: 0,
              reasoningTokens: 10,
            },
            completion_ids: ["completion-session"],
          },
        },
        null,
        2,
      )}\n`,
    );
    const progressBundle = JSON.parse(
      await readFile(join(root, "review-progress.json"), "utf8"),
    ) as Record<string, any>;
    const { completed_group_ids: _completedGroups, ...persistedReview } =
      progressBundle.progress;
    await writeFile(
      join(root, "review.json"),
      `${JSON.stringify(
        {
          schema_version: 1,
          session_id: prepared.session_id,
          evidence_digest: evidence.evidence_digest,
          review: {
            ...persistedReview,
            coverage: { required: 1, completed: 1 },
          },
        },
        null,
        2,
      )}\n`,
    );
    let requests = 0;

    await expect(
      reviewPreparedSession({
        sessionRoot: root,
        provider: {
          endpoint: "https://provider.example/v1/chat/completions",
          apiKey: "test-key",
          model: "configured/model:thinking",
          requestCompletion: async () => {
            requests += 1;
            throw new Error("Completed progress must not be repeated.");
          },
        },
        policy: {
          version: "2",
          promptVersion: "contextual-review-v3",
          schemaVersion: "contextual-assessment-v1",
          maxImmediateAttempts: 3,
          maxOutputTokens: 32_768,
          maxResponseBytes: 5_000_000,
          timeoutMs: 900_000,
        },
      }),
    ).resolves.toMatchObject({ status: "reviewed" });
    expect(requests).toBe(0);
    await expect(
      readFile(join(root, "review-progress.json"), "utf8"),
    ).rejects.toMatchObject({ code: "ENOENT" });
  });

  test("discards an invalid internal checkpoint and restarts the bounded review", async () => {
    const { root, prepared } = await preparedSession();
    const evidence = JSON.parse(
      await readFile(join(root, "evidence-context.json"), "utf8"),
    ) as {
      evidence_digest: string;
      groups: Array<{
        group_id: string;
        candidates: Array<{ candidate_id: string; evidence_id: string }>;
      }>;
    };
    const candidate = evidence.groups[0]!.candidates[0]!;
    await writeFile(
      join(root, "review-progress.json"),
      `${JSON.stringify(
        {
          schema_version: 1,
          session_id: prepared.session_id,
          evidence_digest: evidence.evidence_digest,
          progress: {
            policy_version: "2",
            prompt_version: "contextual-review-v3",
            schema_version: "contextual-assessment-v1",
            model: "configured/model:thinking",
            provider: "provider.example",
            endpoint_origin: "https://provider.example",
            completed_group_ids: [evidence.groups[0]!.group_id],
            assessments: [
              {
                candidate_id: candidate.candidate_id,
                evidence_ids: ["f".repeat(64)],
                disposition: "minor_weakness",
                impact: "low",
                exploitability: "unlikely",
                confidence: "medium",
                recommended_risk: "low",
                technical_explanation: "The flow should be hardened.",
                layman_explanation: "This behavior deserves a small caution.",
                developer_action: "Document the destination.",
              },
            ],
            observations: [],
            usage: {
              inputTokens: 100,
              outputTokens: 50,
              cacheReadTokens: 0,
              reasoningTokens: 10,
            },
            completion_ids: ["completion-stale"],
          },
        },
        null,
        2,
      )}\n`,
    );

    await expect(completeReview(root)).resolves.toMatchObject({
      status: "reviewed",
      review: { coverage: { required: 1, completed: 1 } },
    });
    await expect(
      readFile(join(root, "review-progress.json"), "utf8"),
    ).rejects.toMatchObject({ code: "ENOENT" });
  });

  test("discards a schema-invalid internal checkpoint and restarts the review", async () => {
    const { root, prepared } = await preparedSession();
    const evidence = JSON.parse(
      await readFile(join(root, "evidence-context.json"), "utf8"),
    ) as { evidence_digest: string };
    await writeFile(
      join(root, "review-progress.json"),
      `${JSON.stringify({
        schema_version: 1,
        session_id: prepared.session_id,
        evidence_digest: evidence.evidence_digest,
        progress: {},
      })}\n`,
    );

    await expect(completeReview(root)).resolves.toMatchObject({
      status: "reviewed",
      review: { coverage: { required: 1, completed: 1 } },
    });
    await expect(
      readFile(join(root, "review-progress.json"), "utf8"),
    ).rejects.toMatchObject({ code: "ENOENT" });
  });

  test("publishes the acquired SHA without consulting a newer manifest", async () => {
    const { root } = await preparedSession();
    await completeReview(root);
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
    if (!omitTool) await completeReview(root);
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

  test("writes no candidate when contextual review is missing", async () => {
    const { root } = await preparedSession();
    const output = join(tmpdir(), `missing-review-${Date.now()}.json`);
    roots.push(output);
    await expect(
      finalizePreparedSession({
        sessionRoot: root,
        output,
        completedAt: "2026-08-02T16:00:00.000Z",
        verifyHead: async () => ({ ok: true, value: targetSha }),
      }),
    ).rejects.toThrow();
    await expect(readFile(output)).rejects.toMatchObject({ code: "ENOENT" });
  });

  test("detects prepared-session evidence tampering", async () => {
    const { root, prepared } = await preparedSession();
    await completeReview(root);
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

  test("classifies contextual report finalization failures without exposing evidence", async () => {
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
    const evidence = JSON.parse(
      await readFile(join(root, "evidence-context.json"), "utf8"),
    );
    evidence.session_id = prepared.session_id;
    evidence.groups[0].candidates[0].candidate_id =
      prepared.findings[0]!.fingerprint;
    evidence.groups[0].candidates[0].evidence_id =
      prepared.findings[0]!.fingerprint;
    evidence.groups[0].candidates[0].rule_id = unsafeRuleId;
    evidence.evidence_digest = evidenceContextIdentity({
      session_id: evidence.session_id,
      groups: evidence.groups,
    });
    await writeFile(
      join(root, "evidence-context.json"),
      `${JSON.stringify(evidence, null, 2)}\n`,
    );
    await completeReview(root);
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

  test("prepared persistence remains source-free and rejects review fields", async () => {
    const { prepared } = await preparedSession();
    expect(
      PreparedSessionSchema.safeParse({ ...prepared, unexpected_field: {} })
        .success,
    ).toBe(false);
    expect(
      PreparedSessionSchema.safeParse({
        ...prepared,
        contextual_review: {},
      }).success,
    ).toBe(false);
  });
});
