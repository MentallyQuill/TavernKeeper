import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, test } from "vitest";

import {
  ReportIndexEntryV4Schema,
  type ScanReportV4,
} from "../src/contracts/reports.js";
import {
  initialOperationsState,
  parseOperationsState,
  serializeOperationsState,
} from "../src/operations/state.js";
import {
  projectReportToIndexV4,
  publishCandidates,
} from "../src/publish/publisher.js";
import { reportIdentity, reportPath } from "../src/publish/report-path.js";

const roots: string[] = [];
const generatedAt = "2026-08-02T15:00:00.000Z";

async function fixtureReport(overrides: Partial<ScanReportV4> = {}) {
  const raw = JSON.parse(
    await readFile(
      new URL("./fixtures/contracts/report.v4.valid.json", import.meta.url),
      "utf8",
    ),
  ) as ScanReportV4;
  const report = { ...raw, ...overrides };
  return { ...report, report_id: reportIdentity(report) };
}

async function redReport(overrides: Partial<ScanReportV4> = {}) {
  const raw = await fixtureReport();
  const report = {
    ...raw,
    result: "red" as const,
    summary: {
      headline: "Reportable concerns detected",
      detail:
        "1 reportable concern met TavernKeeper's deterministic threshold.",
    },
    coverage: {
      ...raw.coverage,
      evidence_validation: {
        status: "completed" as const,
        validated_findings: 1,
      },
    },
    finding_counts: {
      total: 1,
      reportable: 1,
      informational: 0,
      reportable_severity: { critical: 0, high: 1, medium: 0 },
      severity: { critical: 0, high: 1, medium: 0, low: 0, info: 0 },
      confidence: { high: 1, medium: 0, low: 0 },
      policy_status: { reportable: 1, informational: 0 },
      categories: [{ category: "credential-theft", count: 1 }],
    },
    findings: [
      {
        origin: "tavernkeeper",
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
          "Review the data flow, remove unintended credential transmission, and restrict any required destination.",
        fingerprint: "b".repeat(64),
      },
    ],
    ...overrides,
  };
  return { ...report, report_id: reportIdentity(report) };
}

async function publicationRoot() {
  const root = await mkdtemp(join(tmpdir(), "tavernkeeper-publisher-"));
  roots.push(root);
  await mkdir(join(root, "reports"), { recursive: true });
  await mkdir(join(root, "operations"), { recursive: true });
  await writeFile(
    join(root, "reports", "index.json"),
    `${JSON.stringify({ schema_version: 4, generated_at: generatedAt, reports: [] }, null, 2)}\n`,
  );
  await writeFile(
    join(root, "operations", "state.json"),
    serializeOperationsState(initialOperationsState(generatedAt)),
  );
  return root;
}

afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

describe("serialized deterministic report publisher", () => {
  test("publishes immutable V4 JSON and HTML with Tavernary's compact index fields", async () => {
    const root = await publicationRoot();
    const report = await fixtureReport();
    const state = parseOperationsState({
      ...initialOperationsState(generatedAt),
      active_scans: [
        {
          source_id: report.source_id,
          repository_id: report.repository_id,
          target_sha: report.target_sha,
          started_at: "2026-08-02T14:00:00.000Z",
          run_id: "batch-1",
        },
      ],
    });
    const published = await publishCandidates({
      root,
      candidates: [report],
      state,
      generatedAt,
    });

    const destination = join(root, ...reportPath(report).split("/"));
    expect(
      JSON.parse(await readFile(join(destination, "report.json"), "utf8")),
    ).toEqual(report);
    expect(await readFile(join(destination, "index.html"), "utf8")).toContain(
      "TavernKeeper Scan Report",
    );
    expect(published.index.schema_version).toBe(4);
    expect(published.index.reports).toHaveLength(1);
    expect(
      ReportIndexEntryV4Schema.parse(projectReportToIndexV4(report)),
    ).toEqual(published.index.reports[0]);
    expect(published.index.reports[0]).not.toHaveProperty("mode");
    expect(published.index.reports[0]!.summary).toEqual(report.summary);
    expect(published.state.active_scans).toEqual([]);
  });

  test("keeps a red forced-scan result in full history after a later teal correction", async () => {
    const root = await publicationRoot();
    const red = await redReport({ completed_at: "2026-08-02T14:00:00.000Z" });
    const teal = await fixtureReport({
      report_version: 2,
      supersedes_report_id: red.report_id,
      completed_at: "2026-08-02T15:00:00.000Z",
    });
    const published = await publishCandidates({
      root,
      candidates: [red, teal],
      state: initialOperationsState(generatedAt),
      generatedAt,
    });

    expect(published.index.reports).toHaveLength(1);
    expect(published.index.reports[0]).toMatchObject({
      report_id: teal.report_id,
      result: "teal",
      report_version: 2,
    });
    const historyRoot = join(root, "reports", "github", "42", "history");
    const history = await readFile(join(historyRoot, "index.html"), "utf8");
    expect(history).toContain("RED");
    expect(history).toContain("TEAL");
    expect(
      JSON.parse(await readFile(join(historyRoot, "history.json"), "utf8")),
    ).toHaveLength(2);
  });

  test("preserves preferred conclusions for older SHAs", async () => {
    const root = await publicationRoot();
    const oldReport = await fixtureReport();
    const current = await fixtureReport({
      target_sha: "f".repeat(40),
      completed_at: "2026-08-02T16:00:00.000Z",
    });
    const published = await publishCandidates({
      root,
      candidates: [oldReport, current],
      state: initialOperationsState(generatedAt),
      generatedAt: "2026-08-02T16:05:00.000Z",
    });
    expect(published.index.reports.map(({ target_sha }) => target_sha)).toEqual(
      [oldReport.target_sha, current.target_sha],
    );
  });

  test("rejects an immutable-path collision", async () => {
    const root = await publicationRoot();
    const report = await fixtureReport();
    const state = initialOperationsState(generatedAt);
    await publishCandidates({ root, candidates: [report], state, generatedAt });
    await expect(
      publishCandidates({ root, candidates: [report], state, generatedAt }),
    ).rejects.toThrow(/immutable report path already exists/iu);
  });

  test("prevalidates a mixed V4 batch before writing any candidate", async () => {
    const root = await publicationRoot();
    const valid = await fixtureReport();
    const unsafeBase = await fixtureReport({ report_version: 2 });
    const unsafe = { ...unsafeBase, model_review: {} };
    await expect(
      publishCandidates({
        root,
        candidates: [valid, unsafe],
        state: initialOperationsState(generatedAt),
        generatedAt,
      }),
    ).rejects.toThrow(/public report rejected/iu);
    await expect(
      readFile(join(root, ...reportPath(valid).split("/"), "report.json")),
    ).rejects.toMatchObject({ code: "ENOENT" });
    const index = JSON.parse(
      await readFile(join(root, "reports", "index.json"), "utf8"),
    ) as { reports: unknown[] };
    expect(index.reports).toEqual([]);
  });
});
