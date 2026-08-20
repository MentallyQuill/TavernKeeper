import { describe, expect, test } from "vitest";

import {
  ReportIndexEntryV5Schema,
  ReportIndexV5Schema,
  buildContextualCountsV5,
  type CandidateV5,
  type ReportIndexEntryV5,
  type ScanReportV5,
} from "../src/contracts/reports-v5.js";
import { analyzeReviewOpportunities } from "../src/analysis/review-opportunities.js";
import {
  fixturePolicy5ReportV5,
  fixtureReportV5,
} from "./helpers/v5-report.js";

type Outcome = {
  disposition:
    | "expected_behavior"
    | "minor_weakness"
    | "material_vulnerability"
    | "credible_malicious_behavior";
  impact: "none" | "low" | "medium" | "high" | "critical";
  exploitability: "unlikely" | "plausible" | "readily_exploitable";
  confidence: "low" | "medium" | "high";
  risk_exposure: "not_demonstrated" | "demonstrated";
  recommended_risk: "low" | "material" | "high";
};

const lowOutcome: Outcome = {
  disposition: "expected_behavior",
  impact: "none",
  exploitability: "unlikely",
  confidence: "high",
  risk_exposure: "not_demonstrated",
  recommended_risk: "low",
};

const highOutcome: Outcome = {
  disposition: "credible_malicious_behavior",
  impact: "critical",
  exploitability: "readily_exploitable",
  confidence: "high",
  risk_exposure: "demonstrated",
  recommended_risk: "high",
};

function indexEntry(report: ScanReportV5): ReportIndexEntryV5 {
  return ReportIndexEntryV5Schema.parse({
    report_id: report.report_id,
    report_digest: report.report_digest,
    report_version: report.report_version,
    supersedes_report_id: report.supersedes_report_id,
    scanner_version: report.scanner_version,
    scanner_policy_version: report.scanner_policy_version,
    rule_catalog_version: report.rule_catalog_version,
    package_schema_version: report.package_schema_version,
    contextual_review_policy_version: report.contextual_review_policy_version,
    ecosystem_context_version: report.ecosystem_context_version,
    prompt_version: report.prompt_version,
    assessment_schema_version: report.assessment_schema_version,
    source_id: report.source_id,
    provider: report.provider,
    repository_id: report.repository_id,
    repository: report.repository,
    target_sha: report.target_sha,
    completed_at: report.completed_at,
    assessment_method: report.assessment_method,
    counts: report.counts,
    coverage: {
      history_commits: report.history.commits,
      inventory_files: report.coverage.inventory.files,
      inventory_bytes: report.coverage.inventory.bytes,
      tools_completed: report.coverage.tools.filter(
        ({ status }) => status === "completed",
      ).length,
      tools_not_applicable: report.coverage.tools.filter(
        ({ status }) => status === "not-applicable",
      ).length,
      evidence_validated:
        report.coverage.evidence_validation.validated_candidates,
      metadata_only_candidates:
        report.coverage.evidence_validation.status ===
        "completed-with-limitations"
          ? report.coverage.evidence_validation.metadata_only_candidates
          : 0,
      review_required: report.review_coverage.required,
      review_completed: report.review_coverage.completed,
      javascript_analysis_status:
        report.coverage.javascript_analysis?.status ?? "legacy",
    },
    report_url:
      `https://mentallyquill.github.io/TavernKeeper/reports/github/` +
      `${report.repository_id}/${report.target_sha}/` +
      `${report.scanner_policy_version}/${report.report_id}/`,
    history_url:
      `https://mentallyquill.github.io/TavernKeeper/reports/github/` +
      `${report.repository_id}/history/`,
  });
}

function reportIndex(reports: readonly ScanReportV5[]) {
  return ReportIndexV5Schema.parse({
    schema_version: 5,
    generated_at: "2026-08-20T00:00:00.000Z",
    reports: reports.map(indexEntry),
  });
}

async function contextualReport(input: {
  repositoryId: number;
  repository: string;
  candidateSeed: string;
  ruleId?: string;
  outcome?: Outcome;
  usage?: {
    input_tokens: number;
    output_tokens: number;
    cache_read_tokens: number;
    reasoning_tokens: number;
  };
  reuse?: boolean;
  reviewer?: { provider: string; model: string };
}) {
  const base = await fixturePolicy5ReportV5();
  const candidateId = input.candidateSeed.repeat(64);
  const evidenceId =
    input.candidateSeed === "a" ? "b".repeat(64) : "a".repeat(64);
  const candidate: CandidateV5 = {
    ...base.candidates[0]!,
    candidate_id: candidateId,
    evidence_id: evidenceId,
    origin: "zizmor",
    scanner_version: "1.28.0",
    rule_id: input.ruleId ?? "artipacked",
    category: "workflow-security",
    path: ".github/workflows/release.yml",
    execution_scope: "automation",
    title: "Workflow artifact persistence",
    explanation: "The workflow persists Git credentials in an artifact.",
  };
  const outcome = input.outcome ?? lowOutcome;
  const assessment = {
    candidate_id: candidateId,
    evidence_ids: [evidenceId],
    ...outcome,
    technical_explanation: "The workflow behavior requires review.",
    layman_explanation: "The workflow may expose repository credentials.",
    developer_action: "Inspect artifact contents and credential cleanup.",
    locations: [
      {
        path: candidate.path,
        line_start: 1,
        line_end: 1,
      },
    ],
    assessment_source: "contextual-model" as const,
    triage_reason_code: "unknown-rule",
  };
  const usage = input.usage ?? {
    input_tokens: 100,
    output_tokens: 10,
    cache_read_tokens: 20,
    reasoning_tokens: 3,
  };
  return fixturePolicy5ReportV5({
    source_id: `github-${input.repositoryId}`,
    repository_id: input.repositoryId,
    repository: input.repository,
    canonical_url: `https://github.com/${input.repository}`,
    target_sha: input.candidateSeed.repeat(40),
    contextual_reviewer: input.reviewer ?? {
      provider: "openrouter.ai",
      model: "zai-org/glm-latest",
    },
    review_usage: usage,
    review_batches: [
      {
        kind: "contextual_review",
        attempt: 1,
        group_count: 1,
        candidate_count: 1,
        estimated_input_tokens: 120,
        over_budget: false,
        ...usage,
      },
    ],
    review_triage: {
      policy_version: "1",
      candidates: {
        total: 1,
        deterministic: 0,
        contextual: 1,
        reused_contextual: input.reuse ? 1 : 0,
      },
      cases: {
        total: 1,
        contextual: 1,
        reused_contextual: input.reuse ? 1 : 0,
      },
      reasons: [{ reason_code: "unknown-rule", count: 1 }],
      model_budget: {
        configured: base.review_triage!.model_budget.configured,
        actual: {
          fresh_behavior_cases: input.reuse ? 0 : 1,
          provider_calls: 1,
          estimated_input_tokens: 120,
          input_tokens: usage.input_tokens,
          output_tokens: usage.output_tokens,
        },
      },
    },
    review_reuse: input.reuse
      ? {
          groups: { fresh: 0, reused: 1 },
          candidates: { fresh: 0, reused: 1 },
          source_report_ids: ["f".repeat(64)],
        }
      : undefined,
    coverage: {
      ...base.coverage,
      tools: base.coverage.tools.map((tool) =>
        tool.name === "zizmor"
          ? { ...tool, status: "completed" as const }
          : tool,
      ),
    },
    candidates: [candidate],
    assessments: [assessment],
    counts: buildContextualCountsV5(1, [assessment], []),
  });
}

function loaderFor(reports: readonly ScanReportV5[]) {
  const byId = new Map(reports.map((report) => [report.report_id, report]));
  const calls: string[] = [];
  return {
    calls,
    loadReport: async (entry: ReportIndexEntryV5) => {
      calls.push(entry.report_id);
      const report = byId.get(entry.report_id);
      if (report === undefined) throw new Error("Unexpected report load.");
      return report;
    },
  };
}

describe("review opportunity analysis", () => {
  test("loads each preferred Policy 5 report once and skips other policies", async () => {
    const current = await contextualReport({
      repositoryId: 101,
      repository: "owner/current",
      candidateSeed: "a",
    });
    const historical = await fixtureReportV5({
      repository_id: 102,
      source_id: "github-102",
      repository: "owner/historical",
      canonical_url: "https://github.com/owner/historical",
      target_sha: "b".repeat(40),
    });
    const loader = loaderFor([current]);

    const result = await analyzeReviewOpportunities({
      index: reportIndex([historical, current]),
      loadReport: loader.loadReport,
    });

    expect(loader.calls).toEqual([current.report_id]);
    expect(result.corpus).toMatchObject({
      indexed_reports: 2,
      loaded_reports: 1,
      skipped_policy_reports: 1,
      contextual_candidates: 1,
      provider_calls: 1,
      usage: {
        input_tokens: 100,
        output_tokens: 10,
        cache_read_tokens: 20,
        reasoning_tokens: 3,
      },
    });
  });

  test("groups exact contextual outcomes while excluding deterministic assessments", async () => {
    const low = await contextualReport({
      repositoryId: 201,
      repository: "owner/low",
      candidateSeed: "a",
      usage: {
        input_tokens: 100,
        output_tokens: 10,
        cache_read_tokens: 20,
        reasoning_tokens: 3,
      },
    });
    const high = await contextualReport({
      repositoryId: 202,
      repository: "owner/high",
      candidateSeed: "b",
      outcome: highOutcome,
      usage: {
        input_tokens: 200,
        output_tokens: 20,
        cache_read_tokens: 40,
        reasoning_tokens: 6,
      },
      reviewer: {
        provider: "openrouter.ai",
        model: "deepseek/deepseek-v4-flash:thinking",
      },
    });
    const deterministic = await fixturePolicy5ReportV5({
      repository_id: 203,
      source_id: "github-203",
      repository: "owner/deterministic",
      canonical_url: "https://github.com/owner/deterministic",
      target_sha: "c".repeat(40),
    });
    const reports = [low, deterministic, high];

    const result = await analyzeReviewOpportunities({
      index: reportIndex(reports),
      loadReport: loaderFor(reports).loadReport,
      maxReferencesPerOpportunity: 1,
    });

    expect(result.corpus.contextual_candidates).toBe(2);
    expect(result.opportunities).toHaveLength(1);
    expect(result.opportunities[0]).toMatchObject({
      key: {
        origin: "zizmor",
        rule_id: "artipacked",
        scanner_version: "1.28.0",
        execution_scope: "automation",
        file_role: "production",
        scanner_confidence: "high",
        triage_reason_code: "unknown-rule",
      },
      candidate_count: 2,
      repository_count: 2,
      outcomes: {
        disposition: {
          expected_behavior: 1,
          minor_weakness: 0,
          material_vulnerability: 0,
          credible_malicious_behavior: 1,
        },
        risk_exposure: { not_demonstrated: 1, demonstrated: 1 },
        recommended_risk: { low: 1, material: 0, high: 1 },
      },
      associated_reports: {
        attribution: "overlapping-non-additive",
        report_count: 2,
        provider_calls: 2,
        usage: {
          input_tokens: 300,
          output_tokens: 30,
          cache_read_tokens: 60,
          reasoning_tokens: 9,
        },
      },
      reviewer_strata: [
        {
          provider: "openrouter.ai",
          model: "deepseek/deepseek-v4-flash:thinking",
          candidate_count: 1,
          report_count: 1,
        },
        {
          provider: "openrouter.ai",
          model: "zai-org/glm-latest",
          candidate_count: 1,
          report_count: 1,
        },
      ],
    });
    expect(result.opportunities[0]!.references).toHaveLength(1);
    expect(result.opportunities[0]!.references[0]!.repository).toBe(
      "owner/high",
    );
  });

  test("deduplicates associated report usage when one report contributes multiple candidates", async () => {
    const report = await contextualReport({
      repositoryId: 301,
      repository: "owner/two-candidates",
      candidateSeed: "a",
    });
    const firstCandidate = report.candidates[0]!;
    const firstAssessment = report.assessments[0]!;
    const secondCandidate = {
      ...firstCandidate,
      candidate_id: "c".repeat(64),
      evidence_id: "d".repeat(64),
      path: ".github/workflows/nightly.yml",
    };
    const secondAssessment = {
      ...firstAssessment,
      candidate_id: secondCandidate.candidate_id,
      evidence_ids: [secondCandidate.evidence_id],
      locations: [{ path: secondCandidate.path, line_start: 1, line_end: 1 }],
    };
    const twoCandidates = await fixturePolicy5ReportV5({
      ...report,
      candidates: [firstCandidate, secondCandidate],
      assessments: [firstAssessment, secondAssessment],
      counts: buildContextualCountsV5(
        2,
        [firstAssessment, secondAssessment],
        [],
      ),
      review_coverage: { required: 2, completed: 2 },
      coverage: {
        ...report.coverage,
        javascript_analysis: {
          ...report.coverage.javascript_analysis!,
          candidates: 2,
          candidate_bytes: 24,
          representations: {
            ...report.coverage.javascript_analysis!.representations,
            raw: 2,
          },
        },
        evidence_validation: { status: "completed", validated_candidates: 2 },
      },
      review_batches: [
        {
          ...report.review_batches![0]!,
          candidate_count: 2,
        },
      ],
      review_triage: {
        ...report.review_triage!,
        candidates: {
          total: 2,
          deterministic: 0,
          contextual: 2,
          reused_contextual: 0,
        },
        reasons: [{ reason_code: "unknown-rule", count: 2 }],
      },
    });
    const loader = loaderFor([twoCandidates]);

    const result = await analyzeReviewOpportunities({
      index: reportIndex([twoCandidates]),
      loadReport: loader.loadReport,
    });

    expect(result.opportunities[0]).toMatchObject({
      candidate_count: 2,
      associated_reports: {
        report_count: 1,
        provider_calls: 1,
        usage: {
          input_tokens: 100,
          output_tokens: 10,
          cache_read_tokens: 20,
          reasoning_tokens: 3,
        },
      },
    });
  });

  test("surfaces contextual reuse that cannot be mapped to individual candidates", async () => {
    const report = await contextualReport({
      repositoryId: 401,
      repository: "owner/reused",
      candidateSeed: "a",
      reuse: true,
    });

    const result = await analyzeReviewOpportunities({
      index: reportIndex([report]),
      loadReport: loaderFor([report]).loadReport,
    });

    expect(result.corpus.reports_with_unmapped_contextual_reuse).toBe(1);
    expect(result.limitations).toContain(
      "Public reports do not map reused contextual assessments to individual candidates.",
    );
  });

  test("sorts equal-frequency opportunities by their stable key", async () => {
    const zRule = await contextualReport({
      repositoryId: 501,
      repository: "owner/z-rule",
      candidateSeed: "a",
      ruleId: "z-rule",
    });
    const aRule = await contextualReport({
      repositoryId: 502,
      repository: "owner/a-rule",
      candidateSeed: "b",
      ruleId: "a-rule",
    });

    const result = await analyzeReviewOpportunities({
      index: reportIndex([zRule, aRule]),
      loadReport: loaderFor([zRule, aRule]).loadReport,
    });
    const reversed = await analyzeReviewOpportunities({
      index: reportIndex([aRule, zRule]),
      loadReport: loaderFor([aRule, zRule]).loadReport,
    });

    expect(result.opportunities.map(({ key }) => key.rule_id)).toEqual([
      "a-rule",
      "z-rule",
    ]);
    expect(reversed).toEqual(result);
  });

  test("uses identity tie-breakers when bounded references look identical", async () => {
    const left = await contextualReport({
      repositoryId: 521,
      repository: "owner/same-name",
      candidateSeed: "a",
    });
    const right = await contextualReport({
      repositoryId: 522,
      repository: "owner/same-name",
      candidateSeed: "a",
    });

    const forward = await analyzeReviewOpportunities({
      index: reportIndex([left, right]),
      loadReport: loaderFor([left, right]).loadReport,
      maxReferencesPerOpportunity: 1,
    });
    const reversed = await analyzeReviewOpportunities({
      index: reportIndex([right, left]),
      loadReport: loaderFor([right, left]).loadReport,
      maxReferencesPerOpportunity: 1,
    });

    expect(reversed).toEqual(forward);
  });

  test("propagates a missing preferred report instead of changing the denominator", async () => {
    const report = await contextualReport({
      repositoryId: 551,
      repository: "owner/missing",
      candidateSeed: "a",
    });

    await expect(
      analyzeReviewOpportunities({
        index: reportIndex([report]),
        loadReport: async () => {
          throw new Error("ENOENT: preferred report is missing");
        },
      }),
    ).rejects.toThrow("ENOENT: preferred report is missing");
  });

  test("rejects a malformed selected report", async () => {
    const report = await contextualReport({
      repositoryId: 601,
      repository: "owner/malformed",
      candidateSeed: "a",
    });

    await expect(
      analyzeReviewOpportunities({
        index: reportIndex([report]),
        loadReport: async () => ({}),
      }),
    ).rejects.toThrow();
  });

  test("rejects a selected report whose identity differs from the index", async () => {
    const report = await contextualReport({
      repositoryId: 701,
      repository: "owner/mismatch",
      candidateSeed: "a",
    });
    const mismatched = { ...report, target_sha: "f".repeat(40) };

    await expect(
      analyzeReviewOpportunities({
        index: reportIndex([report]),
        loadReport: async () => mismatched,
      }),
    ).rejects.toThrow(
      "Report identity does not match its preferred index entry",
    );
  });
});
