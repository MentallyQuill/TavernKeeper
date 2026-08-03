import { readFile, readdir } from "node:fs/promises";

import { Ajv } from "ajv";
import { describe, expect, test } from "vitest";

import {
  buildContractSchemas,
  serializeContractSchema,
} from "../scripts/generate-contract-schemas.js";
import {
  buildFindingCountsV4,
  deriveV4Result,
  parseReportIndex,
  ReportIndexV4Schema,
  ScanReportV4Schema,
} from "../src/contracts/reports.js";
import {
  parseTargetManifest,
  requireTargetManifestV2,
  TargetManifestV2Schema,
} from "../src/contracts/targets.js";

async function fixture(name: string) {
  return JSON.parse(
    await readFile(
      new URL(`./fixtures/contracts/${name}`, import.meta.url),
      "utf8",
    ),
  ) as Record<string, unknown>;
}

describe("public TavernKeeper contracts", () => {
  test("accepts the strict deterministic V4 report", async () => {
    const report = await fixture("report.v4.valid.json");
    expect(ScanReportV4Schema.parse(report)).toEqual(report);
    expect(
      ScanReportV4Schema.safeParse({ ...report, unexpected: true }).success,
    ).toBe(false);
    for (const schemaVersion of [1, 2, 3])
      expect(
        ScanReportV4Schema.safeParse({
          ...report,
          schema_version: schemaVersion,
        }).success,
      ).toBe(false);
  });

  test("derives color and counts from the fixed finding policy", () => {
    const findings = [
      {
        origin: "opengrep",
        rule_id: "credential-exfiltration",
        category: "credential-theft",
        severity: "high" as const,
        confidence: "high" as const,
        policy_status: "reportable" as const,
        path: "src/index.ts",
        line_start: 1,
        line_end: 1,
        evidence_sha: null,
        title: "Credential access and network transmission in one file",
        explanation:
          "A credential source and an outbound network operation were detected in the same file.",
        remediation:
          "Review the data flow and remove unintended credential transmission.",
        fingerprint: "b".repeat(64),
      },
      {
        origin: "zizmor",
        rule_id: "workflow-permission",
        category: "workflow-risk",
        severity: "low" as const,
        confidence: "medium" as const,
        policy_status: "informational" as const,
        path: ".github/workflows/ci.yml",
        line_start: 4,
        line_end: 4,
        evidence_sha: null,
        title: "Broad workflow permission",
        explanation: "A workflow permission may be broader than required.",
        remediation: "Reduce the workflow permission to its minimum scope.",
        fingerprint: "c".repeat(64),
      },
    ];
    expect(deriveV4Result(findings)).toBe("red");
    expect(buildFindingCountsV4(findings)).toMatchObject({
      total: 2,
      reportable: 1,
      informational: 1,
      reportable_severity: { critical: 0, high: 1, medium: 0 },
      policy_status: { reportable: 1, informational: 1 },
    });
  });

  test("accepts only the V4 preferred report index", async () => {
    const index = await fixture("index.v4.valid.json");
    expect(ReportIndexV4Schema.parse(index)).toEqual(index);
    expect(parseReportIndex(index)).toEqual(index);
    for (const schemaVersion of [1, 2, 3])
      expect(() =>
        parseReportIndex({ ...index, schema_version: schemaVersion }),
      ).toThrow();
  });

  test("keeps target-manifest V1 parsing separate from the required V2 scan input", async () => {
    const legacy = await fixture("targets.valid.json");
    const current = await fixture("targets.v2.valid.json");
    expect(parseTargetManifest(legacy).schema_version).toBe(1);
    expect(TargetManifestV2Schema.parse(current)).toEqual(current);
    expect(requireTargetManifestV2(parseTargetManifest(current))).toEqual(
      current,
    );
    expect(() => requireTargetManifestV2(parseTargetManifest(legacy))).toThrow(
      /version 2/iu,
    );
  });

  test("ships no pre-V4 report or report-index schemas", async () => {
    const schemas = await readdir(new URL("../schemas/", import.meta.url));
    expect(
      schemas
        .filter((name) => /^(?:scan-report|report-index)\./u.test(name))
        .sort(),
    ).toEqual(["report-index.v4.schema.json", "scan-report.v4.schema.json"]);
  });

  test("tracked current JSON Schemas are byte-equivalent to their Zod contracts", async () => {
    for (const { file, document } of buildContractSchemas()) {
      const tracked = await readFile(
        new URL(`../schemas/${file}`, import.meta.url),
        "utf8",
      );
      await expect(serializeContractSchema(document)).resolves.toBe(tracked);
    }
  });

  test("generated JSON Schemas validate the shared current fixtures", async () => {
    const fixtures = new Map([
      ["tavernary-targets.v2.schema.json", "targets.v2.valid.json"],
      ["scan-report.v4.schema.json", "report.v4.valid.json"],
      ["report-index.v4.schema.json", "index.v4.valid.json"],
    ]);
    const ajv = new Ajv({ allErrors: true, strict: false });
    for (const { file, document } of buildContractSchemas()) {
      const fixtureName = fixtures.get(file);
      expect(fixtureName).toBeDefined();
      const validate = ajv.compile(document);
      const value = await fixture(fixtureName!);
      expect(validate(value), JSON.stringify(validate.errors)).toBe(true);
    }
  });
});
