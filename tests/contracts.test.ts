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
});
