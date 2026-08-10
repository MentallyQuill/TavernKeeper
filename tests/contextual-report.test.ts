import { describe, expect, test } from "vitest";

import { buildScanPackage } from "../src/contracts/scan-package.js";
import {
  buildContextualCountsV5,
  PUBLIC_JAVASCRIPT_UNRESOLVED_MAX,
  publicJavascriptAnalysisCoverage,
  ScanReportV5Schema,
} from "../src/contracts/reports-v5.js";
import type { EvidenceContextGroup } from "../src/context/evidence-context.js";
import type { CompletedContextualReview } from "../src/model/contextual-review.js";
import {
  reportIdentity,
  reportPath,
  reportUrl,
} from "../src/publish/report-path.js";
import { sanitizeReportV5 } from "../src/publish/sanitize.js";
import { renderReportV5Html } from "../src/publish/render-report.js";
import { buildContextualReport } from "../src/report/contextual-report.js";
import { normalizeFinding } from "../src/scanners/types.js";
import { JAVASCRIPT_ANALYSIS_VERSION } from "../src/scanners/javascript-analysis.js";

const targetSha = "a".repeat(40);
const finding = normalizeFinding({
  origin: "opengrep",
  ruleId: "network-call",
  category: "network-access",
  severity: "medium",
  confidence: "medium",
  path: "src/index.ts",
  lineStart: 2,
  lineEnd: 2,
  evidenceSha: null,
  title: "Network request",
  explanation: "The file makes a network request.",
});
const sourceFile = {
  path: "src/index.ts",
  bytes: 24,
  sha256: "b".repeat(64),
  kind: "text" as const,
};
const scanPackage = buildScanPackage({
  target: {
    source_id: "github-42",
    provider: "github",
    repository_id: 42,
    repository: "owner/repo",
    target_sha: targetSha,
    canonical_url: "https://github.com/owner/repo",
  },
  history: { baseSha: null, commits: 1 },
  scannerVersion: "1.0.0",
  scannerPolicyVersion: "4",
  ruleCatalogVersion: "1",
  inventory: {
    root: "C:/scan/repository",
    files: [sourceFile],
    totals: { files: 1, bytes: 24 },
    totalBytes: 24,
  },
  classification: {
    firstPartyText: [sourceFile],
    applicability: { osv: false, zizmor: false, malcontent: false },
    scannerInputs: { osv: [], zizmor: [], malcontent: [] },
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
    { name: "inventory", version: "1.0.0", status: "completed" },
    { name: "tavernkeeper-static", version: "2", status: "completed" },
    { name: "gitleaks", version: "8.30.1", status: "completed" },
    { name: "opengrep", version: "1.26.0", status: "completed" },
    {
      name: "javascript-analysis",
      version: JAVASCRIPT_ANALYSIS_VERSION,
      status: "completed",
    },
    { name: "osv-scanner", version: "2.4.0", status: "not-applicable" },
    { name: "zizmor", version: "1.28.0", status: "not-applicable" },
    { name: "malcontent", version: "1.25.7", status: "not-applicable" },
  ],
  javascriptAnalysis: {
    status: "complete",
    candidates: 1,
    candidate_bytes: sourceFile.bytes,
    representations: {
      raw: 1,
      decoded: 0,
      normalized: 0,
      bundle_modules: 0,
    },
    stages: {
      raw_signatures: 1,
      raw_ast: 1,
      raw_opengrep: 1,
      derived_signatures: 0,
      derived_ast: 0,
      derived_opengrep: 0,
    },
    unresolved: [],
  },
  findings: [finding],
});
const group: EvidenceContextGroup = {
  group_id: "c".repeat(64),
  repository: "owner/repo",
  project_kinds: ["extension"],
  path: finding.path,
  file_role: "production",
  target_sha: targetSha,
  evidence_sha: targetSha,
  source_kind: "text",
  source_bytes: 24,
  source_sha256: sourceFile.sha256,
  ecosystem_context_version: "sillytavern-community-v1",
  ecosystem_context: "Trusted ecosystem context.",
  candidates: [
    {
      candidate_id: finding.fingerprint,
      evidence_id: finding.fingerprint,
      origin: finding.origin,
      rule_id: finding.rule_id,
      category: finding.category,
      scanner_severity: finding.severity,
      scanner_confidence: finding.confidence,
      title: finding.title,
      explanation: finding.explanation,
      line_start: finding.line_start,
      line_end: finding.line_end,
    },
  ],
  context: {
    imports: "",
    source: "     2 | fetch(endpoint);",
    expansions: [
      "     1 | const endpoint = configuredEndpoint;\n     2 | fetch(endpoint);",
    ],
    representations: [
      { stage: "raw", sha256: sourceFile.sha256, transform_depth: 0 },
    ],
    project_purpose: "A model helper.",
  },
};
const review: CompletedContextualReview = {
  policy_version: "4",
  prompt_version: "contextual-review-v7",
  schema_version: "contextual-assessment-v2",
  model: "deepseek/deepseek-v4-flash-0731:thinking",
  provider: "nano-gpt.com",
  endpoint_origin: "https://nano-gpt.com",
  coverage: { required: 1, completed: 1 },
  assessments: [
    {
      candidate_id: finding.fingerprint,
      evidence_ids: [finding.fingerprint],
      disposition: "expected_behavior",
      impact: "none",
      exploitability: "unlikely",
      confidence: "high",
      risk_exposure: "not_demonstrated",
      recommended_risk: "low",
      technical_explanation:
        "The request matches the documented model-helper purpose.",
      layman_explanation: "This request appears to be expected.",
      developer_action: "none",
      locations: [{ path: finding.path, line_start: 2, line_end: 2 }],
    },
  ],
  observations: [],
  usage: {
    inputTokens: 100,
    outputTokens: 40,
    cacheReadTokens: 0,
    reasoningTokens: 10,
  },
  completion_ids: ["completion-1"],
  review_units: [
    {
      group_id: group.group_id,
      review_input_digest: "d".repeat(64),
      candidate_ids: [finding.fingerprint],
      reused: false,
      origin_report_id: null,
    },
  ],
};

function validReport() {
  return buildContextualReport(
    { scanPackage, review, evidenceGroups: [group] },
    {
      targetSha,
      completedAt: "2026-08-02T12:00:00.000Z",
      reportVersion: 1,
      supersedesReportId: null,
      limitations: [
        "This advisory review cannot prove the absence of unknown behavior.",
      ],
    },
  );
}

test("publishes complete fresh and reused review provenance", () => {
  const fresh = validReport();
  expect(fresh.review_reuse).toEqual({
    groups: { fresh: 1, reused: 0 },
    candidates: { fresh: 1, reused: 0 },
    source_report_ids: [],
  });

  const reusedReview: CompletedContextualReview = {
    ...review,
    review_units: [
      {
        ...review.review_units![0]!,
        reused: true,
        origin_report_id: "e".repeat(64),
      },
    ],
  };
  const reused = buildContextualReport(
    { scanPackage, review: reusedReview, evidenceGroups: [group] },
    {
      targetSha,
      completedAt: "2026-08-02T16:00:00.000Z",
      reportVersion: 1,
      supersedesReportId: null,
      limitations: [
        "This advisory review cannot prove the absence of unknown behavior.",
      ],
    },
  );
  expect(reused.review_reuse).toEqual({
    groups: { fresh: 0, reused: 1 },
    candidates: { fresh: 0, reused: 1 },
    source_report_ids: ["e".repeat(64)],
  });
  expect(
    ScanReportV5Schema.safeParse({
      ...reused,
      review_reuse: {
        ...reused.review_reuse,
        candidates: { fresh: 1, reused: 1 },
      },
    }).success,
  ).toBe(false);
});

test("publishes per-batch token usage and rejects totals that do not reconcile", () => {
  const batchedReview: CompletedContextualReview = {
    ...review,
    review_batches: [
      {
        kind: "contextual_review",
        attempt: 1,
        group_count: 1,
        candidate_count: 1,
        estimated_input_tokens: 120,
        over_budget: false,
        input_tokens: 100,
        output_tokens: 40,
        cache_read_tokens: 0,
        reasoning_tokens: 10,
      },
    ],
  };
  const report = buildContextualReport(
    { scanPackage, review: batchedReview, evidenceGroups: [group] },
    {
      targetSha,
      completedAt: "2026-08-02T16:00:00.000Z",
      reportVersion: 1,
      supersedesReportId: null,
      limitations: [
        "This advisory review cannot prove the absence of unknown behavior.",
      ],
    },
  );

  expect(report.review_batches).toEqual(batchedReview.review_batches);
  expect(
    ScanReportV5Schema.safeParse({
      ...report,
      review_batches: [{ ...report.review_batches![0]!, input_tokens: 99 }],
    }).success,
  ).toBe(false);
});

function legacyImportedTemplateReport() {
  const report = structuredClone(validReport());
  report.contextual_review_policy_version = "2";
  report.prompt_version = "contextual-review-v5";
  report.assessment_schema_version = "contextual-assessment-v1";
  Object.assign(report.candidates[0]!, {
    origin: "opengrep",
    rule_id: "tavernkeeper.dynamic-execution.javascript-eval",
    category: "dynamic-execution",
    file_role: "production",
    title: "Imported preset template executes JavaScript",
  });
  Object.assign(report.assessments[0]!, {
    disposition: "material_vulnerability",
    impact: "high",
    exploitability: "plausible",
    confidence: "high",
    recommended_risk: "material",
    technical_explanation:
      "A user-imported preset supplies JavaScript that is passed directly to new Function and executes with the extension's privileges.",
    layman_explanation:
      "Importing a hostile preset can run its code in the extension.",
    developer_action: "Require confirmation before template use.",
  });
  const assessment = report.assessments[0]!;
  if (!("risk_exposure" in assessment))
    throw new Error("Expected a current assessment fixture.");
  const { risk_exposure: _riskExposure, ...legacyAssessment } = assessment;
  report.assessments = [legacyAssessment];
  report.counts = buildContextualCountsV5(
    report.candidates.length,
    report.assessments,
    report.observations,
  );
  const identity = reportIdentity(report);
  return ScanReportV5Schema.parse({
    ...report,
    report_id: identity,
    report_digest: identity,
  });
}

function legacyMultiCandidateObservationReport(
  reverseCandidates = false,
  unconfirmedSecond = false,
  shippedSecond = false,
) {
  const report = structuredClone(legacyImportedTemplateReport());
  delete report.review_reuse;
  const firstCandidate = report.candidates[0]!;
  const firstAssessment = report.assessments[0]!;
  Object.assign(firstAssessment, {
    disposition: "expected_behavior",
    impact: "none",
    exploitability: "unlikely",
    confidence: "high",
    recommended_risk: "low",
    technical_explanation: "The individual scanner match is expected.",
    layman_explanation: "This individual match is expected.",
    developer_action: "none",
  });
  const secondCandidate = {
    ...firstCandidate,
    candidate_id: "e".repeat(64),
    evidence_id: "e".repeat(64),
    file_role:
      unconfirmedSecond || shippedSecond
        ? ("production" as const)
        : ("fixture" as const),
    path: "test/template-fixture.ts",
    title: "Fixture template execution",
    explanation: unconfirmedSecond
      ? "The runtime path remains unconfirmed in the available evidence."
      : firstCandidate.explanation,
  };
  const secondAssessment = {
    ...firstAssessment,
    candidate_id: secondCandidate.candidate_id,
    evidence_ids: [secondCandidate.evidence_id],
    locations: [{ path: secondCandidate.path, line_start: 2, line_end: 2 }],
  };
  report.candidates = reverseCandidates
    ? [secondCandidate, firstCandidate]
    : [firstCandidate, secondCandidate];
  report.assessments = [firstAssessment, secondAssessment];
  report.observations = [
    {
      observation_id: "d".repeat(64),
      related_candidate_ids: [
        firstCandidate.candidate_id,
        secondCandidate.candidate_id,
      ],
      evidence_ids: [firstCandidate.evidence_id, secondCandidate.evidence_id],
      disposition: "material_vulnerability",
      impact: "high",
      exploitability: "plausible",
      confidence: "high",
      recommended_risk: "material",
      title: "Combined template execution path",
      technical_explanation:
        "The two scanner matches combine into a potentially exploitable execution path.",
      layman_explanation:
        "Together these matches could allow template code execution.",
      developer_action: "Review both cited locations before release.",
      locations: [
        { path: firstCandidate.path, line_start: 2, line_end: 2 },
        { path: secondCandidate.path, line_start: 2, line_end: 2 },
      ],
    },
  ];
  report.review_coverage = { required: 2, completed: 2 };
  report.coverage.evidence_validation = {
    status: "completed",
    validated_candidates: 2,
  };
  report.counts = buildContextualCountsV5(
    report.candidates.length,
    report.assessments,
    report.observations,
  );
  const identity = reportIdentity(report);
  return ScanReportV5Schema.parse({
    ...report,
    report_id: identity,
    report_digest: identity,
  });
}

test("parses immutable policy-2 reports while requiring exposure in policy 4", () => {
  const current = validReport();
  const legacy = structuredClone(current) as unknown as {
    contextual_review_policy_version: string;
    prompt_version: string;
    assessment_schema_version: string;
    assessments: Array<{ risk_exposure?: string }>;
    observations: Array<{ risk_exposure?: string }>;
  };
  legacy.contextual_review_policy_version = "2";
  legacy.prompt_version = "contextual-review-v5";
  legacy.assessment_schema_version = "contextual-assessment-v1";
  for (const assessment of legacy.assessments) delete assessment.risk_exposure;
  for (const observation of legacy.observations)
    delete observation.risk_exposure;

  expect(ScanReportV5Schema.safeParse(legacy).success).toBe(true);
  expect(
    ScanReportV5Schema.safeParse({
      ...legacy,
      contextual_review_policy_version: "4",
      prompt_version: "contextual-review-v7",
      assessment_schema_version: "contextual-assessment-v2",
    }).success,
  ).toBe(false);
});

function reportWithObservation(
  risk: "low" | "material" | "high" = "low",
  candidateRisk: "material" | "high" | null = null,
) {
  const disposition =
    risk === "high"
      ? "credible_malicious_behavior"
      : risk === "material"
        ? "material_vulnerability"
        : "minor_weakness";
  const assessments =
    candidateRisk === null
      ? review.assessments
      : review.assessments.map((assessment) => ({
          ...assessment,
          disposition:
            candidateRisk === "high"
              ? ("credible_malicious_behavior" as const)
              : ("material_vulnerability" as const),
          impact:
            candidateRisk === "high" ? ("high" as const) : ("medium" as const),
          exploitability:
            candidateRisk === "high"
              ? ("readily_exploitable" as const)
              : ("plausible" as const),
          risk_exposure: "demonstrated" as const,
          recommended_risk: candidateRisk,
          technical_explanation: "The candidate requires attention.",
          layman_explanation: "This scanner match requires attention.",
          developer_action: "Review this behavior before release.",
        }));
  return buildContextualReport(
    {
      scanPackage,
      evidenceGroups: [group],
      review: {
        ...review,
        assessments,
        observations: [
          {
            observation_id: "d".repeat(64),
            related_candidate_ids: [finding.fingerprint],
            evidence_ids: [finding.fingerprint],
            disposition,
            impact:
              risk === "high" ? "high" : risk === "material" ? "medium" : "low",
            exploitability:
              risk === "high"
                ? "readily_exploitable"
                : risk === "material"
                  ? "plausible"
                  : "unlikely",
            confidence: risk === "low" ? "medium" : "high",
            risk_exposure: risk === "low" ? "not_demonstrated" : "demonstrated",
            recommended_risk: risk,
            title: "Related request handling",
            technical_explanation:
              "The same request path could expose endpoint details in logs.",
            layman_explanation:
              "Debug logs could reveal a small amount of connection detail.",
            developer_action: "Avoid logging full request details.",
            locations: [{ path: finding.path, line_start: 2, line_end: 2 }],
          },
        ],
      },
    },
    {
      targetSha,
      completedAt: "2026-08-02T12:00:00.000Z",
      reportVersion: 1,
      supersedesReportId: null,
      limitations: [
        "This advisory review cannot prove the absence of unknown behavior.",
      ],
    },
  );
}

describe("contextual V5 reports", () => {
  test("requires JavaScript coverage on policy-4 reports", () => {
    const report = validReport();
    expect(report.coverage).toHaveProperty("javascript_analysis");
    const withoutCoverage = structuredClone(report);
    delete (withoutCoverage.coverage as Record<string, unknown>)
      .javascript_analysis;

    expect(ScanReportV5Schema.safeParse(withoutCoverage).success).toBe(false);
    expect(
      ScanReportV5Schema.safeParse({
        ...withoutCoverage,
        scanner_policy_version: "3",
      }).success,
    ).toBe(true);
  });

  test("publishes bounded incomplete JavaScript coverage and a fixed warning", () => {
    const incompletePackage = structuredClone(scanPackage);
    incompletePackage.javascript_analysis = {
      ...incompletePackage.javascript_analysis!,
      status: "incomplete",
      unresolved: [
        {
          path: "src/index.ts",
          stage: "normalize",
          reason: "timeout",
          recovered: false,
        },
      ],
    };
    incompletePackage.tools.find(
      ({ name }) => name === "javascript-analysis",
    )!.status = "completed-with-limitations";

    const report = buildContextualReport(
      {
        scanPackage: incompletePackage,
        review,
        evidenceGroups: [group],
      },
      {
        targetSha,
        completedAt: "2026-08-02T12:00:00.000Z",
        reportVersion: 1,
        supersedesReportId: null,
        limitations: [
          "This advisory review cannot prove the absence of unknown behavior.",
        ],
      },
    );

    expect(report.coverage).toMatchObject({
      javascript_analysis: {
        status: "incomplete",
        unresolved: [
          {
            path: "src/index.ts",
            stage: "normalize",
            reason: "timeout",
          },
        ],
      },
    });
    expect(report.limitations).toEqual(
      expect.arrayContaining([expect.stringMatching(/no clean conclusion/iu)]),
    );
    const html = renderReportV5Html(report);
    expect(html).toContain(
      'class="assessment-summary surface risk-mark risk-low"',
    );
    expect(html).toContain("JavaScript analysis was incomplete");
  });

  test("publishes metadata-only evidence as incomplete contextual coverage", () => {
    const metadataOnlyGroup: EvidenceContextGroup = {
      ...group,
      source_kind: "metadata-only",
      context: {
        ...group.context,
        imports: "",
        source:
          "Non-text artifact. Raw contents were not provided to the contextual model.",
        expansions: [
          "Non-text artifact. Raw contents were not provided to the contextual model.",
        ],
      },
    };

    const report = buildContextualReport(
      {
        scanPackage,
        review,
        evidenceGroups: [metadataOnlyGroup],
      },
      {
        targetSha,
        completedAt: "2026-08-02T12:00:00.000Z",
        reportVersion: 1,
        supersedesReportId: null,
        limitations: [
          "This advisory review cannot prove the absence of unknown behavior.",
        ],
      },
    );

    expect(report.coverage.evidence_validation).toEqual({
      status: "completed-with-limitations",
      validated_candidates: 1,
      metadata_only_candidates: 1,
    });
    expect(report.limitations).toEqual(
      expect.arrayContaining([
        expect.stringMatching(/non-text artifacts.*raw contents/iu),
      ]),
    );
    const html = renderReportV5Html(report);
    expect(html).toContain(
      'class="assessment-summary surface risk-mark risk-low"',
    );
    expect(html).toContain("non-text artifacts");
  });

  test("sorts, deduplicates, and caps public unresolved JavaScript stages", () => {
    const coverage = structuredClone(scanPackage.javascript_analysis!);
    coverage.status = "incomplete";
    coverage.unresolved = Array.from(
      { length: PUBLIC_JAVASCRIPT_UNRESOLVED_MAX + 2 },
      (_, index) => ({
        path: `src/file-${String(index).padStart(3, "0")}.js`,
        stage: "normalize" as const,
        reason: "timeout" as const,
        recovered: false,
      }),
    ).reverse();
    coverage.unresolved.push(coverage.unresolved[0]!);

    const published = publicJavascriptAnalysisCoverage(coverage);
    expect(published.unresolved).toHaveLength(PUBLIC_JAVASCRIPT_UNRESOLVED_MAX);
    expect(published.unresolved[0]?.path).toBe("src/file-000.js");
    expect(new Set(published.unresolved.map(({ path }) => path)).size).toBe(
      PUBLIC_JAVASCRIPT_UNRESOLVED_MAX,
    );
  });

  test("uses the schema's canonical order for mixed-case unresolved paths", () => {
    const coverage = structuredClone(scanPackage.javascript_analysis!);
    coverage.status = "incomplete";
    coverage.unresolved = [
      {
        path: "src/components/lorebook/ImportLorebookDialog.tsx",
        stage: "raw-ast",
        reason: "parse",
        recovered: false,
      },
      {
        path: "src/components/MarkdownContent.tsx",
        stage: "raw-ast",
        reason: "parse",
        recovered: false,
      },
    ];

    expect(
      publicJavascriptAnalysisCoverage(coverage).unresolved.map(
        ({ path }) => path,
      ),
    ).toEqual([
      "src/components/MarkdownContent.tsx",
      "src/components/lorebook/ImportLorebookDialog.tsx",
    ]);
  });

  test("publishes JavaScript-analysis candidates with their tool version", () => {
    const javascriptFinding = normalizeFinding({
      origin: "javascript-analysis",
      ruleId: "credential-exfiltration",
      category: "credential-theft",
      severity: "high",
      confidence: "high",
      path: finding.path,
      lineStart: finding.line_start,
      lineEnd: finding.line_end,
      evidenceSha: finding.evidence_sha,
      title: "Ignored JavaScript title",
      explanation: "Ignored JavaScript explanation",
    });
    const javascriptPackage = structuredClone(scanPackage);
    javascriptPackage.findings = [javascriptFinding];
    const javascriptGroup = structuredClone(group);
    javascriptGroup.candidates[0] = {
      ...javascriptGroup.candidates[0]!,
      candidate_id: javascriptFinding.fingerprint,
      evidence_id: javascriptFinding.fingerprint,
      origin: javascriptFinding.origin,
      rule_id: javascriptFinding.rule_id,
      category: javascriptFinding.category,
      scanner_severity: javascriptFinding.severity,
      scanner_confidence: javascriptFinding.confidence,
    };
    const javascriptReview = structuredClone(review);
    javascriptReview.assessments[0] = {
      ...javascriptReview.assessments[0]!,
      candidate_id: javascriptFinding.fingerprint,
      evidence_ids: [javascriptFinding.fingerprint],
    };

    const report = buildContextualReport(
      {
        scanPackage: javascriptPackage,
        review: javascriptReview,
        evidenceGroups: [javascriptGroup],
      },
      {
        targetSha,
        completedAt: "2026-08-02T12:00:00.000Z",
        reportVersion: 1,
        supersedesReportId: null,
        limitations: [
          "This advisory review cannot prove the absence of unknown behavior.",
        ],
      },
    );

    expect(report.candidates[0]).toMatchObject({
      origin: "javascript-analysis",
      scanner_version: JAVASCRIPT_ANALYSIS_VERSION,
    });
  });

  test("publishes fixed prose for bounded OpenGrep coverage limitations", () => {
    const limitedPackage = structuredClone(scanPackage);
    const openGrep = limitedPackage.tools.find(
      ({ name }) => name === "opengrep",
    )!;
    openGrep.status = "completed-with-limitations";
    openGrep.limitations = ["parser_syntax", "rule_timeout"];

    const report = buildContextualReport(
      { scanPackage: limitedPackage, review, evidenceGroups: [group] },
      {
        targetSha,
        completedAt: "2026-08-02T12:00:00.000Z",
        reportVersion: 1,
        supersedesReportId: null,
        limitations: [
          "This advisory review cannot prove the absence of unknown behavior.",
        ],
      },
    );

    expect(report.coverage.tools).toEqual(
      expect.arrayContaining([
        { name: "opengrep", version: "1.26.0", status: "completed" },
      ]),
    );
    expect(report.limitations).toEqual(
      expect.arrayContaining([
        "OpenGrep could not parse some source files; findings from successfully analyzed files are included.",
        "OpenGrep timed out on some rule and file combinations; findings from completed analyses are included.",
      ]),
    );
    expect(renderReportV5Html(report)).toContain(
      "OpenGrep could not parse some source files",
    );
  });

  test("binds every scanner candidate to a complete contextual assessment", () => {
    const report = validReport();

    expect(report).toMatchObject({
      schema_version: 5,
      assessment_method: "deterministic-evidence-contextual-review",
      ecosystem_context_version: "sillytavern-community-v1",
      review_coverage: { required: 1, completed: 1 },
      counts: { candidates: 1, assessments: 1 },
    });
    expect(report.candidates[0]).toMatchObject({
      candidate_id: finding.fingerprint,
      file_role: "production",
    });
    expect(report).not.toHaveProperty("result");
    expect(report).not.toHaveProperty("summary");
    expect(report.report_id).toBe(report.report_digest);
    expect(report.report_id).toBe(reportIdentity(report));
    expect(reportPath(report)).toBe(
      `reports/github/42/${targetSha}/4/${report.report_id}`,
    );
    expect(reportUrl(report)).toBe(
      `https://mentallyquill.github.io/TavernKeeper/reports/github/42/${targetSha}/4/${report.report_id}/`,
    );
    expect(ScanReportV5Schema.parse(report)).toEqual(report);
  });

  test("rejects secret-shaped contextual prose even with a recomputed identity", () => {
    const report = validReport();
    const changed = {
      ...report,
      assessments: [
        {
          ...report.assessments[0]!,
          layman_explanation: `The credential was sk-nano-${"z".repeat(32)}.`,
        },
      ],
    };
    const identity = reportIdentity(changed);

    expect(() =>
      sanitizeReportV5({
        ...changed,
        report_id: identity,
        report_digest: identity,
      }),
    ).toThrow(/secret-shaped/iu);
  });

  test("rejects generic secret assignments with a recomputed identity", () => {
    const report = validReport();
    const changed = {
      ...report,
      assessments: [
        {
          ...report.assessments[0]!,
          layman_explanation:
            "The fixture contains token: fixturetoken123 for test coverage.",
        },
      ],
    };
    const identity = reportIdentity(changed);

    expect(() =>
      sanitizeReportV5({
        ...changed,
        report_id: identity,
        report_digest: identity,
      }),
    ).toThrow(/secret-shaped/iu);
  });

  test("renders approachable contextual findings with exact source links", () => {
    const report = reportWithObservation();
    const html = renderReportV5Html(report);

    expect(html).toContain("What this review found");
    expect(html).toContain("This request appears to be expected.");
    expect(html).toContain("Expected scanner matches");
    expect(html).toContain("Related contextual observations");
    expect(html.indexOf("Related contextual observations")).toBeLessThan(
      html.indexOf("Related request handling"),
    );
    expect(html).toContain(
      `https://github.com/owner/repo/blob/${targetSha}/src/index.ts#L2`,
    );
    expect(
      html.match(new RegExp(`${targetSha}/src/index\\.ts#L2`, "gu")),
    ).toHaveLength(2);
    expect(html).toContain("default-src &#39;none&#39;");
    expect(html).not.toMatch(/<script\b/iu);
    expect(html).not.toMatch(/safety certification/iu);
  });

  test("renders a legacy shipped imported-template vulnerability as material", () => {
    const html = renderReportV5Html(legacyImportedTemplateReport());

    expect(html).toContain("1 material concern identified.");
    expect(html).toContain("<strong>Material concern</strong>");
    expect(html).not.toContain(
      "<p>No material or immediate-danger item was identified.</p>",
    );
  });

  test("keeps a downgraded legacy non-production finding visible as a minor caution", () => {
    const report = structuredClone(legacyImportedTemplateReport());
    report.candidates[0]!.file_role = "fixture";
    const identity = reportIdentity(report);
    const html = renderReportV5Html({
      ...report,
      report_id: identity,
      report_digest: identity,
    });

    expect(html).toContain("No material or immediate-danger concern");
    expect(html).toContain("Imported preset template executes JavaScript");
    expect(html).toContain("<strong>Minor caution</strong>");
  });

  test("uses non-OSV candidate uncertainty when rendering a legacy dependency finding", () => {
    const report = structuredClone(legacyImportedTemplateReport());
    Object.assign(report.candidates[0]!, {
      origin: "javascript-analysis",
      rule_id: "javascript.xray.unsafe-stmt",
      category: "dependency-vulnerability",
      explanation:
        "The affected package version remains unknown in the supplied evidence.",
    });
    const identity = reportIdentity(report);
    const html = renderReportV5Html({
      ...report,
      report_id: identity,
      report_digest: identity,
    });

    expect(html).toContain(
      'class="assessment-summary surface risk-mark risk-low"',
    );
    expect(html).toContain("<strong>Minor caution</strong>");
  });

  test("requires every related legacy observation candidate to be shipped regardless of order", () => {
    for (const report of [
      legacyMultiCandidateObservationReport(),
      legacyMultiCandidateObservationReport(true),
    ]) {
      const html = renderReportV5Html(report);
      expect(html).toContain(
        'class="assessment-summary surface risk-mark risk-low"',
      );
      expect(html).toContain("Combined template execution path");
      expect(html).not.toContain("1 material concern identified.");
    }
  });

  test("uses unconfirmed evidence from every related legacy observation candidate", () => {
    for (const report of [
      legacyMultiCandidateObservationReport(false, true),
      legacyMultiCandidateObservationReport(true, true),
    ]) {
      const html = renderReportV5Html(report);
      expect(html).toContain(
        'class="assessment-summary surface risk-mark risk-low"',
      );
      expect(html).not.toContain("1 material concern identified.");
    }
  });

  test("keeps a fully shipped supported legacy observation yellow regardless of order", () => {
    for (const report of [
      legacyMultiCandidateObservationReport(false, false, true),
      legacyMultiCandidateObservationReport(true, false, true),
    ]) {
      const html = renderReportV5Html(report);
      expect(html).toContain(
        'class="assessment-summary surface risk-mark risk-material"',
      );
      expect(html).toContain("1 material concern identified.");
    }
  });

  test.each(["material", "high"] as const)(
    "surfaces a %s observation in the primary findings without a contradictory all-clear",
    (risk) => {
      const html = renderReportV5Html(reportWithObservation(risk));

      expect(html).not.toContain(
        "<p>No material or immediate-danger item was identified.</p>",
      );
      expect(html.indexOf("What this review found")).toBeLessThan(
        html.indexOf("Related request handling"),
      );
      if (risk === "high") {
        expect(html).toContain("<strong>Immediate danger");
        expect(html).toContain("Malicious or compromised behavior");
      } else {
        expect(html).toContain("<strong>material risk</strong>");
      }
      expect(html).not.toContain("Related contextual observations");
    },
  );

  test("orders high observations before material candidate findings", () => {
    const html = renderReportV5Html(reportWithObservation("high", "material"));

    expect(html.indexOf("Related request handling")).toBeLessThan(
      html.indexOf("OpenGrep reported network-call"),
    );
  });

  test("rejects contextual observations linked to an unknown candidate", () => {
    const report = reportWithObservation();
    const invalid = {
      ...report,
      observations: [
        {
          ...report.observations[0]!,
          related_candidate_ids: ["e".repeat(64)],
        },
      ],
    };

    expect(ScanReportV5Schema.safeParse(invalid).success).toBe(false);
  });
});
