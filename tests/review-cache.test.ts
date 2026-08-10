import { mkdtemp, mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, test } from "vitest";

import {
  buildContextualCountsV5,
  ScanReportV5Schema,
} from "../src/contracts/reports-v5.js";
import type { EvidenceContextGroup } from "../src/context/evidence-context.js";
import {
  buildReviewCacheManifest,
  canonicalReviewInput,
  loadReusableReviewGroups,
  ReviewCacheManifestSchema,
  reviewCachePath,
  reviewInputDigest,
  type ReviewIdentity,
} from "../src/model/review-cache.js";
import { reportIdentity, reportPath } from "../src/publish/report-path.js";

const group: EvidenceContextGroup = {
  group_id: "a".repeat(64),
  repository: "owner/project",
  project_kinds: ["extension"],
  path: "src/index.ts",
  file_role: "production",
  execution_scope: "runtime",
  target_sha: "b".repeat(40),
  evidence_sha: "b".repeat(40),
  source_kind: "text",
  source_bytes: 123,
  source_sha256: "c".repeat(64),
  ecosystem_context_version: "sillytavern-community-v1",
  ecosystem_context: "Trusted SillyTavern ecosystem context.",
  candidates: [
    {
      candidate_id: "d".repeat(64),
      evidence_id: "d".repeat(64),
      origin: "osv-scanner",
      rule_id: "RUSTSEC-2024-0414:package",
      category: "dependency-advisory",
      scanner_severity: "medium",
      scanner_confidence: "high",
      title: "Dependency advisory applies",
      explanation: "The locked dependency version matches the advisory.",
      line_start: null,
      line_end: null,
    },
  ],
  context: {
    imports: "     1 | use package;",
    source: "    10 | package = 1.2.3",
    expansions: ["     1 | [dependencies]\n    10 | package = 1.2.3"],
    representations: [
      { stage: "raw", sha256: "c".repeat(64), transform_depth: 0 },
    ],
    project_purpose: "A local roleplay extension.",
  },
};

const identity: ReviewIdentity = {
  scanner_version: "1.0.0",
  scanner_policy_version: "4",
  rule_catalog_version: "1",
  tools: [
    { name: "osv-scanner", version: "2.4.0" },
    { name: "zizmor", version: "1.28.0" },
  ],
  contextual_policy_version: "4",
  prompt_version: "contextual-review-v7",
  assessment_schema_version: "contextual-assessment-v2",
  provider: "provider.example",
  endpoint_origin: "https://provider.example",
  model: "configured/model:thinking",
};

describe("contextual review input identity", () => {
  test("ignores commit-only and unseen file metadata", () => {
    const changed: EvidenceContextGroup = {
      ...group,
      group_id: "e".repeat(64),
      target_sha: "f".repeat(40),
      evidence_sha: "1".repeat(40),
      source_bytes: 999,
      source_sha256: "2".repeat(64),
      context: {
        ...group.context,
        representations: [
          { stage: "raw", sha256: "3".repeat(64), transform_depth: 0 },
        ],
      },
    };

    expect(reviewInputDigest(changed, identity)).toBe(
      reviewInputDigest(group, identity),
    );
    expect(JSON.stringify(canonicalReviewInput(group))).not.toMatch(
      new RegExp(
        [
          group.group_id,
          group.target_sha,
          group.evidence_sha,
          String(group.source_bytes),
          group.source_sha256,
          group.context.representations[0]!.sha256,
        ].join("|"),
        "u",
      ),
    );
  });

  test.each([
    ["repository", { ...group, repository: "owner/other" }],
    ["path", { ...group, path: "src/other.ts" }],
    ["file role", { ...group, file_role: "tooling" as const }],
    ["execution scope", { ...group, execution_scope: "tooling-only" as const }],
    [
      "candidate evidence",
      {
        ...group,
        candidates: [
          { ...group.candidates[0]!, explanation: "Different evidence." },
        ],
      },
    ],
    [
      "imports",
      {
        ...group,
        context: { ...group.context, imports: "     1 | use other;" },
      },
    ],
    [
      "source",
      {
        ...group,
        context: { ...group.context, source: "    10 | package = 9.9.9" },
      },
    ],
    [
      "expansions",
      {
        ...group,
        context: { ...group.context, expansions: ["different expansion"] },
      },
    ],
    [
      "representation stage",
      {
        ...group,
        context: {
          ...group.context,
          representations: [
            {
              stage: "decoded" as const,
              sha256: "c".repeat(64),
              transform_depth: 0,
            },
          ],
        },
      },
    ],
    [
      "purpose",
      {
        ...group,
        context: { ...group.context, project_purpose: "A different purpose." },
      },
    ],
    [
      "ecosystem",
      { ...group, ecosystem_context: "Different trusted ecosystem context." },
    ],
  ])("changes when %s changes", (_name, changed) => {
    expect(reviewInputDigest(changed, identity)).not.toBe(
      reviewInputDigest(group, identity),
    );
  });

  test.each([
    ["scanner", { ...identity, scanner_version: "2.0.0" }],
    ["scanner policy", { ...identity, scanner_policy_version: "5" }],
    ["rule catalog", { ...identity, rule_catalog_version: "2" }],
    [
      "toolchain",
      {
        ...identity,
        tools: [{ name: "osv-scanner", version: "2.5.0" }],
      },
    ],
    ["contextual policy", { ...identity, contextual_policy_version: "5" }],
    ["prompt", { ...identity, prompt_version: "contextual-review-v8" }],
    [
      "schema",
      { ...identity, assessment_schema_version: "contextual-assessment-v3" },
    ],
    ["provider", { ...identity, provider: "other.example" }],
    ["origin", { ...identity, endpoint_origin: "https://other.example" }],
    ["model", { ...identity, model: "configured/other:thinking" }],
  ])("changes when %s identity changes", (_name, changed) => {
    expect(reviewInputDigest(group, changed)).not.toBe(
      reviewInputDigest(group, identity),
    );
  });
});

async function cacheFixture() {
  const source = JSON.parse(
    await readFile(
      new URL(
        "../reports/github/1126279204/6d18d6973996f61c0d88a7a71e761ddb191f0c10/4/11f7bea761dfa400588c9c2d89ce40e6ae8949111f86f510056b54dccf5afdc5/report.json",
        import.meta.url,
      ),
      "utf8",
    ),
  ) as any;
  const assessment = source.assessments[0]!;
  const candidate = source.candidates.find(
    (item: any) => item.candidate_id === assessment.candidate_id,
  )!;
  const reportBody = {
    ...source,
    report_id: "0".repeat(64),
    report_digest: "0".repeat(64),
    contextual_review_policy_version: "4",
    prompt_version: "contextual-review-v7",
    assessment_schema_version: "contextual-assessment-v2",
    candidates: [candidate],
    assessments: [assessment],
    observations: [],
    review_coverage: { required: 1, completed: 1 },
    coverage: {
      ...source.coverage,
      evidence_validation: {
        status: "completed",
        validated_candidates: 1,
      },
    },
    counts: buildContextualCountsV5(1, [assessment], []),
  };
  const reportId = reportIdentity(reportBody);
  const report = ScanReportV5Schema.parse({
    ...reportBody,
    report_id: reportId,
    report_digest: reportId,
  });
  const location = assessment.locations[0]!;
  const currentGroup: EvidenceContextGroup = {
    group_id: "9".repeat(64),
    repository: report.repository,
    project_kinds: ["extension"],
    path: candidate.path,
    file_role: candidate.file_role,
    execution_scope: "runtime",
    target_sha: "f".repeat(40),
    evidence_sha: "f".repeat(40),
    source_kind: "text",
    source_bytes: 12,
    source_sha256: "8".repeat(64),
    ecosystem_context_version: "sillytavern-community-v1",
    ecosystem_context: "Trusted SillyTavern ecosystem context.",
    candidates: [
      {
        candidate_id: candidate.candidate_id,
        evidence_id: candidate.evidence_id,
        origin: candidate.origin,
        rule_id: candidate.rule_id,
        category: candidate.category,
        scanner_severity: candidate.scanner_severity,
        scanner_confidence: candidate.scanner_confidence,
        title: candidate.title,
        explanation: candidate.explanation,
        line_start: candidate.line_start,
        line_end: candidate.line_end,
      },
    ],
    context: {
      imports: "",
      source: `    ${location.line_start} | reviewed evidence`,
      expansions: [`    ${location.line_start} | reviewed evidence`],
      representations: [
        { stage: "raw", sha256: "8".repeat(64), transform_depth: 0 },
      ],
      project_purpose: "A local roleplay client.",
    },
  };
  const currentIdentity: ReviewIdentity = {
    scanner_version: report.scanner_version,
    scanner_policy_version: report.scanner_policy_version,
    rule_catalog_version: report.rule_catalog_version,
    tools: report.coverage.tools.map(({ name, version }) => ({
      name,
      version,
    })),
    contextual_policy_version: report.contextual_review_policy_version,
    prompt_version: report.prompt_version,
    assessment_schema_version: report.assessment_schema_version,
    provider: report.contextual_reviewer!.provider,
    endpoint_origin: `https://${report.contextual_reviewer!.provider}`,
    model: report.contextual_reviewer!.model,
  };
  const digest = reviewInputDigest(currentGroup, currentIdentity);
  const manifest = ReviewCacheManifestSchema.parse({
    schema_version: 1,
    repository_id: report.repository_id,
    repository: report.repository,
    source_report: {
      report_id: report.report_id,
      target_sha: report.target_sha,
      scanner_policy_version: report.scanner_policy_version,
    },
    review_identity: currentIdentity,
    entries: [
      {
        review_input_digest: digest,
        candidate_ids: [candidate.candidate_id],
      },
    ],
  });
  const root = await mkdtemp(join(tmpdir(), "tavernkeeper-review-cache-"));
  await mkdir(join(root, reportPath(report)), { recursive: true });
  await writeFile(
    join(root, reportPath(report), "report.json"),
    JSON.stringify(report),
  );
  await mkdir(join(root, "reports", "github", String(report.repository_id)), {
    recursive: true,
  });
  await writeFile(
    join(root, reviewCachePath(report.repository_id)),
    JSON.stringify(manifest),
  );
  return {
    root,
    report,
    group: currentGroup,
    identity: currentIdentity,
    manifest,
  };
}

async function deterministicPolicy5Fixture() {
  const fixture = JSON.parse(
    await readFile(
      new URL(
        "fixtures/contracts/report.v5.policy5.valid.json",
        import.meta.url,
      ),
      "utf8",
    ),
  );
  const body = {
    ...fixture,
    report_id: "0".repeat(64),
    report_digest: "0".repeat(64),
  };
  const id = reportIdentity(body);
  return ScanReportV5Schema.parse({
    ...body,
    report_id: id,
    report_digest: id,
  });
}

describe("contextual review cache validation", () => {
  test("publishes an empty identity-free cache for all-deterministic reports", async () => {
    const report = await deterministicPolicy5Fixture();

    expect(buildReviewCacheManifest({ report, reviewUnits: [] })).toMatchObject(
      { entries: [] },
    );
    expect(
      buildReviewCacheManifest({ report, reviewUnits: [] }),
    ).not.toHaveProperty("review_identity");
  });

  test("never caches deterministic policy assessments as model review", async () => {
    const report = await deterministicPolicy5Fixture();
    const candidateId = report.assessments[0]!.candidate_id;

    expect(
      buildReviewCacheManifest({
        report,
        reviewIdentity: {
          ...identity,
          scanner_policy_version: "5",
          rule_catalog_version: "2",
          contextual_policy_version: "5",
        },
        reviewUnits: [
          {
            review_input_digest: "e".repeat(64),
            candidate_ids: [candidateId],
          },
        ],
      }).entries,
    ).toEqual([]);
  });

  test("loads only an exact low and not-demonstrated review unit", async () => {
    const fixture = await cacheFixture();
    try {
      const hits = await loadReusableReviewGroups({
        repositoryRoot: fixture.root,
        repositoryId: fixture.report.repository_id,
        repository: fixture.report.repository,
        groups: [fixture.group],
        reviewIdentity: fixture.identity,
      });

      expect(hits.get(fixture.group.group_id)).toMatchObject({
        origin_report_id: fixture.report.report_id,
        review_input_digest: reviewInputDigest(fixture.group, fixture.identity),
        response: {
          status: "complete",
          assessments: [
            expect.objectContaining({
              candidate_id: fixture.group.candidates[0]!.candidate_id,
              recommended_risk: "low",
              risk_exposure: "not_demonstrated",
            }),
          ],
          observations: [],
        },
      });
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  });

  test.each([
    ["repository", (value: any) => ({ ...value, repository: "owner/other" })],
    [
      "model",
      (value: any) => ({
        ...value,
        review_identity: { ...value.review_identity, model: "other/model" },
      }),
    ],
    [
      "policy",
      (value: any) => ({
        ...value,
        review_identity: {
          ...value.review_identity,
          contextual_policy_version: "3",
        },
      }),
    ],
    [
      "digest",
      (value: any) => ({
        ...value,
        entries: [{ ...value.entries[0], review_input_digest: "7".repeat(64) }],
      }),
    ],
    [
      "candidate",
      (value: any) => ({
        ...value,
        entries: [{ ...value.entries[0], candidate_ids: ["7".repeat(64)] }],
      }),
    ],
  ])("treats a mismatched %s as a cache miss", async (_name, mutate) => {
    const fixture = await cacheFixture();
    try {
      await writeFile(
        join(fixture.root, reviewCachePath(fixture.report.repository_id)),
        JSON.stringify(mutate(fixture.manifest)),
      );
      const hits = await loadReusableReviewGroups({
        repositoryRoot: fixture.root,
        repositoryId: fixture.report.repository_id,
        repository: fixture.report.repository,
        groups: [fixture.group],
        reviewIdentity: fixture.identity,
      });
      expect(hits.size).toBe(0);
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  });

  test("treats missing and malformed cache files as ordinary misses", async () => {
    const fixture = await cacheFixture();
    try {
      const path = join(
        fixture.root,
        reviewCachePath(fixture.report.repository_id),
      );
      await writeFile(path, "{");
      expect(
        (
          await loadReusableReviewGroups({
            repositoryRoot: fixture.root,
            repositoryId: fixture.report.repository_id,
            repository: fixture.report.repository,
            groups: [fixture.group],
            reviewIdentity: fixture.identity,
          })
        ).size,
      ).toBe(0);
      await rm(path);
      expect(
        (
          await loadReusableReviewGroups({
            repositoryRoot: fixture.root,
            repositoryId: fixture.report.repository_id,
            repository: fixture.report.repository,
            groups: [fixture.group],
            reviewIdentity: fixture.identity,
          })
        ).size,
      ).toBe(0);
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  });

  test("never reuses a demonstrated or material report item", async () => {
    const fixture = await cacheFixture();
    try {
      const assessment = {
        ...fixture.report.assessments[0]!,
        disposition: "material_vulnerability" as const,
        impact: "medium" as const,
        exploitability: "plausible" as const,
        confidence: "high" as const,
        risk_exposure: "demonstrated" as const,
        recommended_risk: "material" as const,
      };
      const body = {
        ...fixture.report,
        report_id: "0".repeat(64),
        report_digest: "0".repeat(64),
        assessments: [assessment],
        counts: buildContextualCountsV5(1, [assessment], []),
      };
      const reportId = reportIdentity(body);
      const report = ScanReportV5Schema.parse({
        ...body,
        report_id: reportId,
        report_digest: reportId,
      });
      await mkdir(join(fixture.root, reportPath(report)), { recursive: true });
      await writeFile(
        join(fixture.root, reportPath(report), "report.json"),
        JSON.stringify(report),
      );
      await writeFile(
        join(fixture.root, reviewCachePath(report.repository_id)),
        JSON.stringify({
          ...fixture.manifest,
          source_report: {
            report_id: report.report_id,
            target_sha: report.target_sha,
            scanner_policy_version: report.scanner_policy_version,
          },
        }),
      );

      expect(
        (
          await loadReusableReviewGroups({
            repositoryRoot: fixture.root,
            repositoryId: report.repository_id,
            repository: report.repository,
            groups: [fixture.group],
            reviewIdentity: fixture.identity,
          })
        ).size,
      ).toBe(0);
    } finally {
      await rm(fixture.root, { recursive: true, force: true });
    }
  });
});
