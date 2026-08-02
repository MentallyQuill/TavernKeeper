import { readFile } from "node:fs/promises";

import { Ajv } from "ajv";
import { describe, expect, test } from "vitest";

import {
  buildFindingCountsV2,
  deriveV2Result,
  deriveResult,
  parseReportIndex,
  ReportIndexSchema,
  ReportIndexV2Schema,
  ScanReportSchema,
  ScanReportV2Schema,
} from "../src/contracts/reports.js";
import {
  parseTargetManifest,
  requireTargetManifestV2,
  TargetManifestSchema,
  TargetManifestV2Schema,
} from "../src/contracts/targets.js";
import {
  buildContractSchemas,
  serializeContractSchema,
} from "../scripts/generate-contract-schemas.js";

const fullSha = "a".repeat(40);
const validFinding = {
  origin: "opengrep",
  rule_id: "credential-exfiltration",
  category: "credential-theft",
  severity: "high",
  confidence: "high",
  path: "src/index.ts",
  line_start: 7,
  line_end: 9,
  evidence_sha: fullSha,
  title: "Credential read followed by network send",
  explanation:
    "Credential access and an outbound request occur in the same flow.",
  remediation:
    "Remove the credential access or constrain the outbound destination.",
  reference_url:
    "https://mentallyquill.github.io/TavernKeeper/rules/credential-exfiltration/",
  fingerprint: "b".repeat(64),
  disposition: "active",
};
const validReport = {
  schema_version: 1,
  report_id: "c".repeat(64),
  report_version: 1,
  supersedes_report_id: null,
  scanner_version: "1.0.0",
  scanner_policy_version: "1",
  prompt_policy_version: "1",
  source_id: "github-42",
  provider: "github",
  repository_id: 42,
  repository: "owner/repo",
  canonical_url: "https://github.com/owner/repo",
  target_sha: fullSha,
  completed_at: "2026-07-31T12:05:00.000Z",
  mode: "standard",
  history: { base_sha: null, commits: 20 },
  coverage: {
    inventory: {
      files: 3,
      bytes: 120,
      eligible_text_files: 2,
      eligible_text_bytes: 100,
      excluded: {
        dependency_lockfiles: { files: 0, bytes: 0 },
        vendored_dependencies: { files: 0, bytes: 0 },
        generated_bundles: { files: 0, bytes: 0 },
        minified_files: { files: 0, bytes: 0 },
        binaries: { files: 1, bytes: 20 },
        archives: { files: 0, bytes: 0 },
        oversized_files: { files: 0, bytes: 0 },
        unsafe_entries: { files: 0, bytes: 0 },
      },
    },
    tools: [
      { name: "inventory", version: "1.0.0", status: "completed" },
      { name: "gitleaks", version: "8.30.1", status: "completed" },
      {
        name: "osv-scanner",
        version: "2.4.0",
        status: "not-applicable",
      },
    ],
    model: {
      status: "completed",
      endpoint_origin: "https://provider.example",
      provider: "provider.example",
      model: "vendor/model-test",
      input_chunks: 2,
      completed_chunks: 2,
      input_tokens: 1000,
      output_tokens: 100,
      cache_read_tokens: 100,
      reasoning_tokens: 50,
      total_tokens: 1100,
    },
  },
  result: "yellow",
  finding_counts: {
    total: 1,
    actionable: 1,
    severity: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
    confidence: { high: 1, medium: 0, low: 0 },
    disposition: { active: 1, dismissed: 0 },
    categories: [{ category: "credential-theft", count: 1 }],
  },
  findings: [validFinding],
};
const validIndexEntry = {
  report_id: validReport.report_id,
  report_version: validReport.report_version,
  supersedes_report_id: validReport.supersedes_report_id,
  scanner_version: validReport.scanner_version,
  scanner_policy_version: validReport.scanner_policy_version,
  prompt_policy_version: validReport.prompt_policy_version,
  source_id: validReport.source_id,
  provider: validReport.provider,
  repository_id: validReport.repository_id,
  repository: validReport.repository,
  target_sha: validReport.target_sha,
  completed_at: validReport.completed_at,
  mode: validReport.mode,
  result: validReport.result,
  finding_counts: validReport.finding_counts,
  coverage: {
    history_commits: 20,
    inventory_files: 3,
    inventory_bytes: 120,
    tools_completed: 2,
    tools_not_applicable: 1,
    model_chunks: 2,
  },
  report_url: `https://mentallyquill.github.io/TavernKeeper/reports/github/42/${fullSha}/1/standard/1/`,
};
const validFindingV2 = {
  ...validFinding,
  disposition: "confirmed",
  automated_review: {
    analyzer_policy: "analyzer-v1",
    challenger_policy: "challenger-v1",
    arbiter_policy: "arbiter-v1",
  },
};
const validReportV2 = {
  ...validReport,
  schema_version: 2,
  result: "red",
  coverage: {
    ...validReport.coverage,
    model: {
      ...validReport.coverage.model,
      roles: {
        analyzer: { required: 2, completed: 2 },
        challenger: { required: 1, completed: 1 },
        arbiter: { required: 1, completed: 1 },
      },
    },
    evidence_validation: { status: "completed", validated_findings: 1 },
  },
  finding_counts: {
    ...validReport.finding_counts,
    actionable_severity: { critical: 0, high: 1, medium: 0 },
    disposition: { confirmed: 1, not_supported: 0, inconclusive: 0 },
  },
  findings: [validFindingV2],
};
const validIndexEntryV2 = {
  ...validIndexEntry,
  result: validReportV2.result,
  finding_counts: validReportV2.finding_counts,
  history_url:
    "https://mentallyquill.github.io/TavernKeeper/reports/github/42/history/",
};

describe("public contracts", () => {
  test("derives red only from confirmed review-level findings", () => {
    expect(
      deriveV2Result([
        {
          severity: "medium",
          confidence: "medium",
          disposition: "confirmed",
        },
      ]),
    ).toBe("red");
    expect(
      deriveV2Result([
        { severity: "low", confidence: "high", disposition: "confirmed" },
        {
          severity: "critical",
          confidence: "high",
          disposition: "not-supported",
        },
      ]),
    ).toBe("teal");
  });

  test("publishes actionable severity separately from all finding severities", () => {
    expect(
      buildFindingCountsV2([
        {
          ...validFindingV2,
          severity: "critical",
          confidence: "high",
          disposition: "not-supported",
        },
        {
          ...validFindingV2,
          severity: "high",
          confidence: "medium",
          disposition: "confirmed",
        },
        {
          ...validFindingV2,
          severity: "low",
          confidence: "high",
          disposition: "confirmed",
        },
      ]),
    ).toMatchObject({
      actionable: 1,
      severity: { critical: 1, high: 1, medium: 0, low: 1, info: 0 },
      actionable_severity: { critical: 0, high: 1, medium: 0 },
    });
  });

  test("accepts only automated V2 report results and dispositions", () => {
    expect(ScanReportV2Schema.safeParse(validReportV2).success).toBe(true);
    expect(
      ScanReportV2Schema.safeParse({ ...validReportV2, result: "yellow" })
        .success,
    ).toBe(false);
    expect(
      ScanReportV2Schema.safeParse({
        ...validReportV2,
        findings: [{ ...validFindingV2, disposition: "active" }],
      }).success,
    ).toBe(false);
  });

  test("requires immutable repository history URLs in V2 indexes", () => {
    const index = {
      schema_version: 2,
      generated_at: "2026-07-31T12:10:00.000Z",
      reports: [validIndexEntryV2],
    };
    expect(ReportIndexV2Schema.safeParse(index).success).toBe(true);
    const { history_url: _historyUrl, ...withoutHistory } = validIndexEntryV2;
    expect(
      ReportIndexV2Schema.safeParse({ ...index, reports: [withoutHistory] })
        .success,
    ).toBe(false);
  });

  test("parses only frozen V1 or strict V2 report indexes", () => {
    const legacy = {
      schema_version: 1,
      generated_at: "2026-07-31T12:10:00.000Z",
      reports: [],
    };
    const current = {
      schema_version: 2,
      generated_at: "2026-07-31T12:10:00.000Z",
      reports: [validIndexEntryV2],
    };

    expect(parseReportIndex(legacy).schema_version).toBe(1);
    expect(parseReportIndex(current).schema_version).toBe(2);
    expect(() => parseReportIndex({ ...current, schema_version: 3 })).toThrow();
  });

  test("accepts strict V2 target metadata", () => {
    const manifest = {
      schema_version: 2,
      generated_at: "2026-07-31T12:00:00.000Z",
      repositories: [
        {
          source_id: "github-42",
          provider: "github",
          repository_id: 42,
          repository: "owner/repo",
          target_sha: fullSha,
          canonical_url: "https://github.com/owner/repo",
          project_kinds: ["extension", "preset"],
          catalog_priority: {
            top_30: false,
            first_cataloged_at: "2026-07-01T00:00:00.000Z",
          },
        },
      ],
    };

    expect(TargetManifestV2Schema.safeParse(manifest).success).toBe(true);
  });

  test("waits for V2 without inventing migration metadata", () => {
    const legacy = {
      schema_version: 1,
      generated_at: "2026-07-31T12:00:00.000Z",
      repositories: [],
    };
    const parsed = parseTargetManifest(legacy);

    expect(parsed).toEqual(legacy);
    expect(() => requireTargetManifestV2(parsed)).toThrow(/version 2/u);
  });

  test("rejects unsorted V2 project kinds", () => {
    const target = {
      source_id: "github-42",
      provider: "github",
      repository_id: 42,
      repository: "owner/repo",
      target_sha: fullSha,
      canonical_url: "https://github.com/owner/repo",
      project_kinds: ["preset", "extension"],
      catalog_priority: {
        top_30: false,
        first_cataloged_at: "2026-07-01T00:00:00.000Z",
      },
    };

    expect(
      TargetManifestV2Schema.safeParse({
        schema_version: 2,
        generated_at: "2026-07-31T12:00:00.000Z",
        repositories: [target],
      }).success,
    ).toBe(false);
  });

  test("derives yellow only from active review-level findings", () => {
    expect(
      deriveResult([
        { severity: "medium", confidence: "medium", disposition: "active" },
      ]),
    ).toBe("yellow");
    expect(
      deriveResult([
        { severity: "low", confidence: "high", disposition: "active" },
        { severity: "high", confidence: "low", disposition: "active" },
        {
          severity: "critical",
          confidence: "high",
          disposition: "dismissed",
        },
      ]),
    ).toBe("green");
  });

  test("accepts exact-SHA Tavernary targets and rejects branch names", () => {
    const manifest = {
      schema_version: 1,
      generated_at: "2026-07-31T12:00:00.000Z",
      repositories: [
        {
          source_id: "github-42",
          provider: "github",
          repository_id: 42,
          repository: "owner/repo",
          target_sha: fullSha,
          canonical_url: "https://github.com/owner/repo",
        },
      ],
    };

    expect(TargetManifestSchema.safeParse(manifest).success).toBe(true);
    expect(
      TargetManifestSchema.safeParse({
        ...manifest,
        repositories: [{ ...manifest.repositories[0], target_sha: "main" }],
      }).success,
    ).toBe(false);
    expect(
      TargetManifestSchema.safeParse({
        ...manifest,
        repositories: [
          {
            ...manifest.repositories[0],
            canonical_url: "https://github.com/other/repo",
          },
        ],
      }).success,
    ).toBe(false);
  });

  test("rejects mismatched and duplicate target identities", () => {
    const target = {
      source_id: "github-42",
      provider: "github",
      repository_id: 42,
      repository: "owner/repo",
      target_sha: fullSha,
      canonical_url: "https://github.com/owner/repo",
    };
    const manifest = {
      schema_version: 1,
      generated_at: "2026-07-31T12:00:00.000Z",
      repositories: [target],
    };

    expect(
      TargetManifestSchema.safeParse({
        ...manifest,
        repositories: [{ ...target, source_id: "github-7" }],
      }).success,
    ).toBe(false);
    expect(
      TargetManifestSchema.safeParse({
        ...manifest,
        repositories: [
          target,
          {
            ...target,
            repository: "owner/other",
            canonical_url: "https://github.com/owner/other",
          },
        ],
      }).success,
    ).toBe(false);
  });

  test("accepts only complete public scan reports", () => {
    expect(ScanReportSchema.safeParse(validReport).success).toBe(true);
    expect(
      ScanReportSchema.safeParse({ ...validReport, result: "incomplete" })
        .success,
    ).toBe(false);
    expect(
      ScanReportSchema.safeParse({
        ...validReport,
        coverage: {
          ...validReport.coverage,
          tools: [
            { name: "inventory", version: "1.0.0", status: "unavailable" },
          ],
        },
      }).success,
    ).toBe(false);
    expect(
      ScanReportSchema.safeParse({
        ...validReport,
        coverage: {
          ...validReport.coverage,
          model: { ...validReport.coverage.model, status: "disabled" },
        },
      }).success,
    ).toBe(false);
  });

  test("records the configured OpenAI-compatible model without pinning a vendor", () => {
    expect(
      ScanReportSchema.safeParse({
        ...validReport,
        coverage: {
          ...validReport.coverage,
          model: {
            ...validReport.coverage.model,
            provider: "openai-compatible",
            model: "deepseek/deepseek-v4-flash",
          },
        },
      }).success,
    ).toBe(true);
  });

  test("ships a report JSON Schema that accepts configured model identifiers", async () => {
    const schema = JSON.parse(
      await readFile(
        new URL("../schemas/scan-report.v1.schema.json", import.meta.url),
        "utf8",
      ),
    ) as Record<string, unknown>;
    const ajv = new Ajv({
      allErrors: true,
      allowUnionTypes: true,
      formats: { "date-time": true, uri: true },
      strict: true,
    });
    const configuredReport = {
      ...validReport,
      coverage: {
        ...validReport.coverage,
        model: {
          ...validReport.coverage.model,
          provider: "nano-gpt",
          model: "deepseek/deepseek-v4-flash",
        },
      },
    };

    expect(ajv.validate(schema, configuredReport)).toBe(true);
  });

  test("requires staff metadata whenever a runtime finding is dismissed", () => {
    const dismissedWithoutAdjudication = {
      ...validReport,
      result: "green",
      finding_counts: {
        ...validReport.finding_counts,
        actionable: 0,
        disposition: { active: 0, dismissed: 1 },
      },
      findings: [{ ...validFinding, disposition: "dismissed" }],
    };
    expect(
      ScanReportSchema.safeParse(dismissedWithoutAdjudication).success,
    ).toBe(false);
  });

  test("rejects unknown report fields and inconsistent finding totals", () => {
    expect(
      ScanReportSchema.safeParse({ ...validReport, current: true }).success,
    ).toBe(false);
    expect(
      ScanReportSchema.safeParse({
        ...validReport,
        findings: [{ ...validFinding, raw_evidence: "secret source text" }],
      }).success,
    ).toBe(false);
    expect(
      ScanReportSchema.safeParse({
        ...validReport,
        finding_counts: { ...validReport.finding_counts, total: 0 },
      }).success,
    ).toBe(false);
  });

  test("rejects exclusion coverage that omits byte totals", () => {
    const numericExclusions = Object.fromEntries(
      Object.entries(validReport.coverage.inventory.excluded).map(
        ([category, totals]) => [
          category,
          typeof totals === "number" ? totals : totals.files,
        ],
      ),
    );
    expect(
      ScanReportSchema.safeParse({
        ...validReport,
        coverage: {
          ...validReport.coverage,
          inventory: {
            ...validReport.coverage.inventory,
            excluded: numericExclusions,
          },
        },
      }).success,
    ).toBe(false);
  });

  test("requires model endpoint origin and complete usage categories", () => {
    const incompleteModel = { ...validReport.coverage.model } as Record<
      string,
      unknown
    >;
    delete incompleteModel.endpoint_origin;
    delete incompleteModel.cache_read_tokens;
    delete incompleteModel.reasoning_tokens;
    expect(
      ScanReportSchema.safeParse({
        ...validReport,
        coverage: { ...validReport.coverage, model: incompleteModel },
      }).success,
    ).toBe(false);
  });

  test("accepts immutable preferred reports and rejects duplicate report IDs", () => {
    const index = {
      schema_version: 1,
      generated_at: "2026-07-31T12:10:00.000Z",
      reports: [validIndexEntry],
    };
    const otherSha = "d".repeat(40);

    expect(ReportIndexSchema.safeParse(index).success).toBe(true);
    expect(
      ReportIndexSchema.safeParse({
        ...index,
        reports: [
          validIndexEntry,
          {
            ...validIndexEntry,
            target_sha: otherSha,
            report_url: `https://mentallyquill.github.io/TavernKeeper/reports/github/42/${otherSha}/1/standard/1/`,
          },
        ],
      }).success,
    ).toBe(false);
  });

  test("ships strict JSON Schemas with shared valid fixtures", async () => {
    const fixtureNames = ["targets", "report", "index"] as const;
    const fixtures = await Promise.all(
      fixtureNames.map(async (name) =>
        JSON.parse(
          await readFile(
            new URL(`./fixtures/contracts/${name}.valid.json`, import.meta.url),
            "utf8",
          ),
        ),
      ),
    );
    const schemaNames = [
      "tavernary-targets.v1",
      "scan-report.v1",
      "report-index.v1",
    ] as const;
    const schemas = await Promise.all(
      schemaNames.map(
        async (name) =>
          JSON.parse(
            await readFile(
              new URL(`../schemas/${name}.schema.json`, import.meta.url),
              "utf8",
            ),
          ) as Record<string, unknown>,
      ),
    );

    expect(TargetManifestSchema.safeParse(fixtures[0]).success).toBe(true);
    expect(ScanReportSchema.safeParse(fixtures[1]).success).toBe(true);
    expect(ReportIndexSchema.safeParse(fixtures[2]).success).toBe(true);
    const objectSchemas = schemas.flatMap((schema) => {
      const objects: Array<Record<string, unknown>> = [];
      const visit = (value: unknown) => {
        if (Array.isArray(value)) {
          value.forEach(visit);
          return;
        }
        if (!value || typeof value !== "object") return;
        const object = value as Record<string, unknown>;
        if (object.type === "object") objects.push(object);
        Object.values(object).forEach(visit);
      };
      visit(schema);
      return objects;
    });
    expect(
      schemas.every(
        (schema) =>
          schema.$schema === "http://json-schema.org/draft-07/schema#" &&
          schema.additionalProperties === false,
      ),
    ).toBe(true);
    expect(
      objectSchemas.every((schema) => schema.additionalProperties === false),
    ).toBe(true);
    const ajv = new Ajv({
      allErrors: true,
      allowUnionTypes: true,
      formats: { "date-time": true, uri: true },
      strict: true,
    });
    schemas.forEach((schema, index) => {
      expect(ajv.validate(schema, fixtures[index])).toBe(true);
    });
  });

  test("ships strict V2 JSON Schemas with shared valid fixtures", async () => {
    const names = ["targets", "report", "index"] as const;
    const fixtures = await Promise.all(
      names.map(async (name) =>
        JSON.parse(
          await readFile(
            new URL(
              `./fixtures/contracts/${name}.v2.valid.json`,
              import.meta.url,
            ),
            "utf8",
          ),
        ),
      ),
    );
    const schemas = await Promise.all(
      ["tavernary-targets.v2", "scan-report.v2", "report-index.v2"].map(
        async (name) =>
          JSON.parse(
            await readFile(
              new URL(`../schemas/${name}.schema.json`, import.meta.url),
              "utf8",
            ),
          ) as Record<string, unknown>,
      ),
    );
    const ajv = new Ajv({
      allErrors: true,
      allowUnionTypes: true,
      formats: { "date-time": true, uri: true },
      strict: true,
    });

    expect(TargetManifestV2Schema.parse(fixtures[0])).toEqual(fixtures[0]);
    expect(ScanReportV2Schema.parse(fixtures[1])).toEqual(fixtures[1]);
    expect(ReportIndexV2Schema.parse(fixtures[2])).toEqual(fixtures[2]);
    schemas.forEach((schema, index) => {
      expect(schema.$schema).toBe("http://json-schema.org/draft-07/schema#");
      expect(schema.additionalProperties).toBe(false);
      expect(ajv.validate(schema, fixtures[index])).toBe(true);
    });
  });

  test("keeps tracked V2 JSON Schemas byte-equivalent to the Zod contracts", async () => {
    const generated = buildContractSchemas();

    await Promise.all(
      generated.map(async ({ file, document }) => {
        expect(
          await readFile(
            new URL(`../schemas/${file}`, import.meta.url),
            "utf8",
          ),
        ).toBe(await serializeContractSchema(document));
      }),
    );
  });
});
