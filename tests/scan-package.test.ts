import { describe, expect, test } from "vitest";

import {
  buildScanPackage,
  scanPackageDigest,
  ScanPackageV1Schema,
  validateScanPackageEvidence,
} from "../src/contracts/scan-package.js";
import type { InventoryFile } from "../src/inventory/inventory-handler.js";
import { normalizeFinding } from "../src/scanners/types.js";

const targetSha = "a".repeat(40);

const sourceFile: InventoryFile = {
  path: "src/index.ts",
  bytes: 12,
  sha256: "b".repeat(64),
  kind: "text",
};
const manifestFile: InventoryFile = {
  path: "package-lock.json",
  bytes: 24,
  sha256: "c".repeat(64),
  kind: "text",
};

const excluded = {
  dependency_lockfiles: { files: 1, bytes: manifestFile.bytes },
  vendored_dependencies: { files: 0, bytes: 0 },
  generated_bundles: { files: 0, bytes: 0 },
  minified_files: { files: 0, bytes: 0 },
  binaries: { files: 0, bytes: 0 },
  archives: { files: 0, bytes: 0 },
  oversized_files: { files: 0, bytes: 0 },
  unsafe_entries: { files: 0, bytes: 0 },
};

const finding = normalizeFinding({
  origin: "gitleaks",
  ruleId: "generic-api-key",
  category: "credential-exposure",
  severity: "high",
  confidence: "high",
  path: sourceFile.path,
  lineStart: 3,
  lineEnd: 3,
  evidenceSha: targetSha,
  title: "Potential credential committed to repository history",
  explanation: "A deterministic secret rule matched this path and commit.",
});

const toolRuns = [
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
    status: "completed" as const,
  },
  { name: "zizmor", version: "1.28.0", status: "not-applicable" as const },
  {
    name: "malcontent",
    version: "1.25.7",
    status: "not-applicable" as const,
  },
];

function input(reverse = false) {
  const files = reverse
    ? [manifestFile, sourceFile]
    : [sourceFile, manifestFile];
  return {
    target: {
      source_id: "github-42",
      provider: "github" as const,
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
      files,
      totals: { files: 2, bytes: 36 },
      totalBytes: 36,
    },
    classification: {
      firstPartyText: [sourceFile],
      applicability: { osv: true, zizmor: false, malcontent: false },
      scannerInputs: {
        osv: [manifestFile],
        zizmor: [],
        malcontent: [],
      },
      excluded,
    },
    tools: reverse ? [...toolRuns].reverse() : toolRuns,
    findings: [finding],
  };
}

describe("Scan Package V1", () => {
  test("canonicalizes inventory, tools, and findings before stable hashing", () => {
    const left = buildScanPackage(input());
    const right = buildScanPackage(input(true));

    expect(left).toEqual(right);
    expect(left.inventory.files.map(({ path }) => path)).toEqual([
      "package-lock.json",
      "src/index.ts",
    ]);
    expect(scanPackageDigest(left)).toBe(scanPackageDigest(right));
  });

  test("requires complete tool coverage and maps each finding origin", () => {
    expect(() =>
      buildScanPackage({ ...input(), tools: toolRuns.slice(0, -1) }),
    ).toThrow(/required tool/iu);

    expect(() =>
      buildScanPackage({
        ...input(),
        findings: [{ ...finding, origin: "unknown-scanner" }],
      }),
    ).toThrow(/finding origin/iu);
  });

  test("rejects unknown paths, invalid lines, and changed fingerprints", () => {
    const valid = buildScanPackage(input());
    const unknownPath = structuredClone(valid);
    unknownPath.findings[0]!.path = "src/unknown.ts";
    expect(() => validateScanPackageEvidence(unknownPath)).toThrow(
      /finding path/iu,
    );

    const invalidLines = structuredClone(valid);
    invalidLines.findings[0]!.line_end = 0;
    expect(() => validateScanPackageEvidence(invalidLines)).toThrow(
      /line/iu,
    );

    const changedFingerprint = structuredClone(valid);
    changedFingerprint.findings[0]!.fingerprint = "d".repeat(64);
    expect(() => validateScanPackageEvidence(changedFingerprint)).toThrow(
      /fingerprint/iu,
    );
  });

  test("preserves evidence totals and rejects raw-source-like fields", () => {
    const valid = buildScanPackage(input());
    expect(valid.evidence_validation).toEqual({
      findings: 1,
      paths_validated: 1,
      fingerprints_validated: 1,
    });

    const changedCounts = structuredClone(valid);
    changedCounts.evidence_validation.findings = 0;
    expect(() => validateScanPackageEvidence(changedCounts)).toThrow(
      /evidence count/iu,
    );

    expect(() =>
      ScanPackageV1Schema.parse({ ...valid, raw_source: "secret" }),
    ).toThrow();
  });
});
