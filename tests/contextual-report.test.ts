import { describe, expect, test } from "vitest";

import { buildScanPackage } from "../src/contracts/scan-package.js";
import { ScanReportV5Schema } from "../src/contracts/reports-v5.js";
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
  scannerPolicyVersion: "3",
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
    { name: "osv-scanner", version: "2.4.0", status: "not-applicable" },
    { name: "zizmor", version: "1.28.0", status: "not-applicable" },
    { name: "malcontent", version: "1.25.7", status: "not-applicable" },
  ],
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
    project_purpose: "A model helper.",
  },
};
const review: CompletedContextualReview = {
  policy_version: "2",
  prompt_version: "contextual-review-v2",
  schema_version: "contextual-assessment-v1",
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
            confidence: risk === "high" ? "high" : "medium",
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
      `reports/github/42/${targetSha}/3/${report.report_id}`,
    );
    expect(reportUrl(report)).toBe(
      `https://mentallyquill.github.io/TavernKeeper/reports/github/42/${targetSha}/3/${report.report_id}/`,
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

  test.each(["material", "high"] as const)(
    "surfaces a %s observation in the primary findings without a contradictory all-clear",
    (risk) => {
      const html = renderReportV5Html(reportWithObservation(risk));

      expect(html).not.toContain(
        "<p>No material or high-risk item was identified.</p>",
      );
      expect(html.indexOf("What this review found")).toBeLessThan(
        html.indexOf("Related request handling"),
      );
      expect(html).toContain(`<strong>${risk} risk</strong>`);
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
