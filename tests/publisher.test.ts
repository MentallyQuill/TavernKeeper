import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, test } from "vitest";

import type { ScanReport } from "../src/contracts/reports.js";
import {
  initialOperationsState,
  parseOperationsState,
  serializeOperationsState,
} from "../src/operations/state.js";
import { publishCandidates } from "../src/publish/publisher.js";
import { reportIdentity, reportPath } from "../src/publish/report-path.js";

const roots: string[] = [];
const generatedAt = "2026-07-31T15:00:00.000Z";

async function fixtureReport(overrides: Record<string, unknown> = {}) {
  const raw = JSON.parse(
    await readFile(
      new URL("./fixtures/contracts/report.valid.json", import.meta.url),
      "utf8",
    ),
  ) as Record<string, unknown>;
  const report = { ...raw, ...overrides };
  return {
    ...report,
    report_id: reportIdentity(report as never),
  } as unknown as ScanReport;
}

async function publicationRoot() {
  const root = await mkdtemp(join(tmpdir(), "tavernkeeper-publisher-"));
  roots.push(root);
  await mkdir(join(root, "reports"), { recursive: true });
  await mkdir(join(root, "operations"), { recursive: true });
  await writeFile(
    join(root, "reports", "index.json"),
    `${JSON.stringify({ schema_version: 1, generated_at: generatedAt, reports: [] }, null, 2)}\n`,
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

describe("serialized report publisher", () => {
  test("publishes immutable JSON and HTML, updates the index, and clears active state", async () => {
    const root = await publicationRoot();
    const report = await fixtureReport();
    const state = parseOperationsState({
      ...initialOperationsState(generatedAt),
      active_scans: [
        {
          source_id: report.source_id,
          repository_id: report.repository_id,
          target_sha: report.target_sha,
          started_at: "2026-07-31T14:00:00.000Z",
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
    expect(published.index.reports).toHaveLength(1);
    expect(published.index.reports[0]).toMatchObject({
      report_id: report.report_id,
      report_url: `https://mentallyquill.github.io/TavernKeeper/${reportPath(report)}/`,
    });
    expect(published.state.active_scans).toEqual([]);
    expect(
      JSON.parse(
        await readFile(join(root, "operations", "state.json"), "utf8"),
      ),
    ).toEqual(published.state);
  });

  test("prefers a higher report version before deep mode", async () => {
    const root = await publicationRoot();
    const standardV1 = await fixtureReport();
    const deepV1 = await fixtureReport({ mode: "deep" });
    const standardV2 = await fixtureReport({
      report_version: 2,
      supersedes_report_id: deepV1.report_id,
    });

    const published = await publishCandidates({
      root,
      candidates: [standardV1, deepV1, standardV2],
      state: initialOperationsState(generatedAt),
      generatedAt,
    });

    expect(published.index.reports).toHaveLength(1);
    expect(published.index.reports[0]).toMatchObject({
      report_version: 2,
      mode: "standard",
      report_id: standardV2.report_id,
    });
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

  test("prevalidates the whole batch before writing any candidate", async () => {
    const root = await publicationRoot();
    const valid = await fixtureReport();
    const unsafeBase = await fixtureReport({ mode: "deep" });
    const findings = structuredClone(unsafeBase.findings) as Array<
      Record<string, unknown>
    >;
    findings[0] = {
      ...findings[0],
      explanation: "Leaked ghp_abcdefghijklmnopqrstuvwxyz1234567890AB",
    };
    const unsafe = { ...unsafeBase, findings };

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
