import { describe, expect, test } from "vitest";

import { buildScanPackage } from "../src/contracts/scan-package.js";
import { ScanReportV4Schema } from "../src/contracts/reports.js";
import { buildDeterministicReport } from "../src/report/deterministic-report.js";
import { normalizeFinding } from "../src/scanners/types.js";

const targetSha = "a".repeat(40);
const sourceFile = {
  path: "src/index.ts",
  bytes: 12,
  sha256: "b".repeat(64),
  kind: "text" as const,
};
const tools = [
  { name: "inventory", version: "1.0.0", status: "completed" as const },
  {
    name: "tavernkeeper-static",
    version: "2",
    status: "completed" as const,
  },
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

function packageWith(
  findingSpecs: Array<{
    ruleId: string;
    severity: "critical" | "high" | "medium" | "low" | "info";
    confidence: "high" | "medium" | "low";
    category: string;
  }>,
) {
  const findings = findingSpecs.map((finding, index) =>
    normalizeFinding({
      origin: "opengrep",
      ruleId: finding.ruleId,
      category: finding.category,
      severity: finding.severity,
      confidence: finding.confidence,
      path: sourceFile.path,
      lineStart: index + 1,
      lineEnd: index + 1,
      evidenceSha: null,
      title: "Ignored scanner title",
      explanation: "Ignored scanner prose",
    }),
  );
  return buildScanPackage({
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
    scannerPolicyVersion: "2",
    ruleCatalogVersion: "1",
    inventory: {
      root: "C:/scan/repository",
      files: [sourceFile],
      totals: { files: 1, bytes: 12 },
      totalBytes: 12,
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
    tools,
    findings,
  });
}

const reportOptions = {
  targetSha,
  completedAt: "2026-08-02T12:00:00.000Z",
  reportVersion: 1,
  supersedesReportId: null,
};

describe("deterministic V4 reports", () => {
  test("builds exact teal summaries for empty and informational packages", () => {
    const empty = buildDeterministicReport(packageWith([]), reportOptions);
    const informational = buildDeterministicReport(
      packageWith([
        {
          ruleId: "informational-rule",
          severity: "low",
          confidence: "high",
          category: "code-quality",
        },
      ]),
      reportOptions,
    );

    expect(empty.result).toBe("teal");
    expect(empty.summary.headline).toBe("No reportable concerns detected");
    expect(informational.result).toBe("teal");
    expect(informational.finding_counts).toMatchObject({
      total: 1,
      reportable: 0,
      informational: 1,
    });
  });

  test("builds a stable red report from reportable package findings", () => {
    const scanPackage = packageWith([
      {
        ruleId: "credential-flow",
        severity: "high",
        confidence: "high",
        category: "credential-theft",
      },
      {
        ruleId: "dynamic-execution",
        severity: "medium",
        confidence: "medium",
        category: "dynamic-execution",
      },
    ]);
    const red = buildDeterministicReport(scanPackage, reportOptions);

    expect(red.result).toBe("red");
    expect(red.finding_counts.reportable).toBe(2);
    expect(red.summary.detail).toContain("2 reportable concerns");
    expect(red.summary.headline.length).toBeLessThanOrEqual(120);
    expect(red.summary.detail.length).toBeLessThanOrEqual(400);
    expect(red).toEqual(
      buildDeterministicReport(structuredClone(scanPackage), reportOptions),
    );
    expect(JSON.stringify(red)).not.toMatch(
      /model|prompt_policy|mode|disposition|adjudication/iu,
    );
    expect(ScanReportV4Schema.parse(red)).toEqual(red);
  });

  test("rejects wrong targets, unsafe normalized values, and count drift", () => {
    expect(() =>
      buildDeterministicReport(packageWith([]), {
        ...reportOptions,
        targetSha: "f".repeat(40),
      }),
    ).toThrow("target SHA");

    const unsafe = packageWith([
      {
        ruleId: "sk-abcdefghijklmnopqrstuvwxyz123456",
        severity: "high",
        confidence: "high",
        category: "credential-theft",
      },
    ]);
    expect(() => buildDeterministicReport(unsafe, reportOptions)).toThrow(
      /unsafe rule identifier/iu,
    );

    const red = buildDeterministicReport(
      packageWith([
        {
          ruleId: "credential-flow",
          severity: "high",
          confidence: "high",
          category: "credential-theft",
        },
      ]),
      reportOptions,
    );
    expect(
      ScanReportV4Schema.safeParse({
        ...red,
        finding_counts: { ...red.finding_counts, reportable: 0 },
      }).success,
    ).toBe(false);
    expect(
      ScanReportV4Schema.safeParse({ ...red, model_review: {} }).success,
    ).toBe(false);
  });
});
