import { readFile, readdir } from "node:fs/promises";

import { Ajv } from "ajv";
import { describe, expect, test } from "vitest";

import {
  buildContractSchemas,
  serializeContractSchema,
} from "../scripts/generate-contract-schemas.js";
import {
  parseReportIndexV5,
  ReportIndexV5Schema,
  ScanReportV5Schema,
} from "../src/contracts/reports-v5.js";
import {
  parseTargetManifest,
  requireTargetManifestV2,
  TargetManifestV2Schema,
  TargetManifestV3Schema,
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
  test("accepts only the strict contextual V5 report", async () => {
    const report = await fixture("report.v5.valid.json");
    expect(ScanReportV5Schema.parse(report)).toEqual(report);
    expect(
      ScanReportV5Schema.safeParse({ ...report, unexpected: true }).success,
    ).toBe(false);
    expect(
      ScanReportV5Schema.safeParse({ ...report, schema_version: 4 }).success,
    ).toBe(false);
    expect(
      ScanReportV5Schema.safeParse({
        ...report,
        review_coverage: { required: 1, completed: 0 },
      }).success,
    ).toBe(false);
  });

  test("accepts only a complete strict V3 popularity ranking", async () => {
    const current = await fixture("targets.v3.valid.json");
    expect(TargetManifestV3Schema.parse(current)).toEqual(current);
    expect(parseTargetManifest(current).schema_version).toBe(3);
    expect(requireTargetManifestV2(parseTargetManifest(current))).toEqual(
      current,
    );

    const repositories = current.repositories as Array<Record<string, any>>;
    expect(
      TargetManifestV3Schema.safeParse({
        ...current,
        repositories: repositories.map((target, index) => ({
          ...target,
          catalog_priority: {
            ...target.catalog_priority,
            popularity_rank: index,
          },
        })),
      }).success,
    ).toBe(false);
    expect(
      TargetManifestV3Schema.safeParse({
        ...current,
        repositories: repositories.map((target) => ({
          ...target,
          catalog_priority: {
            ...target.catalog_priority,
            popularity_rank: 1,
          },
        })),
      }).success,
    ).toBe(false);
    expect(
      TargetManifestV3Schema.safeParse({
        ...current,
        repositories: repositories.map((target, index) => ({
          ...target,
          catalog_priority: {
            ...target.catalog_priority,
            popularity_rank: index === 0 ? 1 : 3,
          },
        })),
      }).success,
    ).toBe(true);
    expect(
      TargetManifestV3Schema.safeParse({
        ...current,
        repositories: repositories.map((target, index) => ({
          ...target,
          catalog_priority: {
            ...target.catalog_priority,
            top_30: index === 0 ? false : target.catalog_priority.top_30,
          },
        })),
      }).success,
    ).toBe(false);
    const { popularity_rank: _rank, ...missingRank } =
      repositories[0]!.catalog_priority;
    expect(
      TargetManifestV3Schema.safeParse({
        ...current,
        repositories: [
          {
            ...repositories[0],
            catalog_priority: missingRank,
          },
          repositories[1],
        ],
      }).success,
    ).toBe(false);
    expect(
      TargetManifestV3Schema.safeParse({
        ...current,
        unexpected: true,
      }).success,
    ).toBe(false);
  });

  test("accepts only the V5 preferred report index", async () => {
    const index = await fixture("index.v5.valid.json");
    expect(ReportIndexV5Schema.parse(index)).toEqual(index);
    expect(parseReportIndexV5(index)).toEqual(index);
    expect(() => parseReportIndexV5({ ...index, schema_version: 4 })).toThrow();
  });

  test("keeps target-manifest V1 parsing separate from required V2 scan input", async () => {
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

  test("ships only V5 report and report-index schemas", async () => {
    const schemas = await readdir(new URL("../schemas/", import.meta.url));
    expect(
      schemas
        .filter((name) => /^(?:scan-report|report-index)\./u.test(name))
        .sort(),
    ).toEqual(["report-index.v5.schema.json", "scan-report.v5.schema.json"]);
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
      ["tavernary-targets.v3.schema.json", "targets.v3.valid.json"],
      ["scan-report.v5.schema.json", "report.v5.valid.json"],
      ["report-index.v5.schema.json", "index.v5.valid.json"],
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

  test("generated report schema rejects policy-3 items without exposure", async () => {
    const report = await fixture("report.v5.valid.json");
    report.contextual_review_policy_version = "3";
    report.prompt_version = "contextual-review-v6";
    report.assessment_schema_version = "contextual-assessment-v2";
    report.assessments = [
      {
        candidate_id: "d".repeat(64),
        evidence_ids: ["d".repeat(64)],
        disposition: "expected_behavior",
        impact: "none",
        exploitability: "unlikely",
        confidence: "high",
        recommended_risk: "low",
        technical_explanation: "The behavior matches the project purpose.",
        layman_explanation: "This behavior is expected.",
        developer_action: "none",
        locations: [{ path: "src/index.ts", line_start: 1, line_end: 1 }],
      },
    ];
    const document = buildContractSchemas().find(
      ({ file }) => file === "scan-report.v5.schema.json",
    )!.document;
    const validate = new Ajv({ allErrors: true, strict: false }).compile(
      document,
    );

    expect(validate(report)).toBe(false);
    expect(validate.errors).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          keyword: "required",
          params: { missingProperty: "risk_exposure" },
        }),
      ]),
    );
  });

  test.each([
    ["prompt_version", "contextual-review-v5"],
    ["assessment_schema_version", "contextual-assessment-v1"],
  ] as const)(
    "binds policy 3 reports to their %s",
    async (field, staleVersion) => {
      const report = await fixture("report.v5.valid.json");
      const policy3 = {
        ...report,
        contextual_review_policy_version: "3",
        prompt_version: "contextual-review-v6",
        assessment_schema_version: "contextual-assessment-v2",
      };

      expect(ScanReportV5Schema.safeParse(policy3).success).toBe(true);
      expect(
        ScanReportV5Schema.safeParse({
          ...policy3,
          [field]: staleVersion,
        }).success,
      ).toBe(false);
    },
  );
});
