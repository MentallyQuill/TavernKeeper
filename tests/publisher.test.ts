import { access, mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, test } from "vitest";

import { ReportIndexV5Schema } from "../src/contracts/reports-v5.js";
import { initialOperationsState } from "../src/operations/state.js";
import { publishCandidates } from "../src/publish/publisher.js";
import { historyPath, reportPath } from "../src/publish/report-path.js";
import { reviewCachePath } from "../src/model/review-cache.js";
import { fixtureReportV5, fixtureReviewCache } from "./helpers/v5-report.js";

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

async function root() {
  const value = await mkdtemp(join(tmpdir(), "tavernkeeper-publisher-v5-"));
  roots.push(value);
  return value;
}

describe("atomic V5 publisher", () => {
  test("publishes immutable contextual JSON, HTML, history, and preferred index", async () => {
    const output = await root();
    const report = await fixtureReportV5();
    const generatedAt = "2026-08-02T12:30:00.000Z";

    const published = await publishCandidates({
      root: output,
      candidates: [report],
      reviewCaches: [fixtureReviewCache(report)],
      state: initialOperationsState(generatedAt),
      generatedAt,
    });

    const directory = join(output, ...reportPath(report).split("/"));
    const stored = JSON.parse(
      await readFile(join(directory, "report.json"), "utf8"),
    );
    expect(stored).toEqual(report);
    expect(await readFile(join(directory, "index.html"), "utf8")).toContain(
      "What this review found",
    );
    expect(published.index).toMatchObject({
      schema_version: 5,
      reports: [
        expect.objectContaining({
          report_id: report.report_id,
          report_digest: report.report_digest,
        }),
      ],
    });
    expect(published.index.reports[0]).not.toHaveProperty("result");
    expect(published.index.reports[0]?.coverage).toMatchObject({
      javascript_analysis_status: "legacy",
    });
    expect(ReportIndexV5Schema.parse(published.index)).toEqual(published.index);
    await expect(
      access(join(output, ...historyPath(report).split("/"), "history.json")),
    ).resolves.toBeUndefined();
    await expect(
      readFile(
        join(output, ...reviewCachePath(report.repository_id).split("/")),
        "utf8",
      ),
    ).resolves.toContain(report.report_id);
  });

  test("keeps only the newest report per repository in the preferred index", async () => {
    const output = await root();
    const first = await fixtureReportV5();
    const second = await fixtureReportV5({
      report_version: 2,
      completed_at: "2026-08-03T12:00:00.000Z",
      supersedes_report_id: first.report_id,
    });
    const state = initialOperationsState("2026-08-02T12:30:00.000Z");
    await publishCandidates({
      root: output,
      candidates: [first],
      reviewCaches: [fixtureReviewCache(first)],
      state,
      generatedAt: "2026-08-02T12:30:00.000Z",
    });
    const published = await publishCandidates({
      root: output,
      candidates: [second],
      reviewCaches: [fixtureReviewCache(second)],
      state,
      generatedAt: "2026-08-03T12:30:00.000Z",
    });

    expect(published.index.reports).toEqual([
      expect.objectContaining({
        report_id: second.report_id,
        report_version: 2,
      }),
    ]);
    const history = JSON.parse(
      await readFile(
        join(output, ...historyPath(first).split("/"), "history.json"),
        "utf8",
      ),
    ) as unknown[];
    expect(history).toHaveLength(2);
  });

  test("rejects a report that does not advance the preferred repository lineage", async () => {
    const output = await root();
    const first = await fixtureReportV5();
    const stale = await fixtureReportV5({
      target_sha: "b".repeat(40),
      completed_at: "2026-08-03T12:00:00.000Z",
      report_version: 1,
      supersedes_report_id: null,
    });
    const state = initialOperationsState("2026-08-02T12:30:00.000Z");
    await publishCandidates({
      root: output,
      candidates: [first],
      reviewCaches: [fixtureReviewCache(first)],
      state,
      generatedAt: "2026-08-02T12:30:00.000Z",
    });

    await expect(
      publishCandidates({
        root: output,
        candidates: [stale],
        reviewCaches: [fixtureReviewCache(stale)],
        state,
        generatedAt: "2026-08-03T12:30:00.000Z",
      }),
    ).rejects.toThrow(/lineage/iu);
    await expect(
      access(join(output, ...reportPath(stale).split("/"))),
    ).rejects.toMatchObject({ code: "ENOENT" });
  });

  test("prevalidates a mixed batch before writing any immutable candidate", async () => {
    const output = await root();
    const report = await fixtureReportV5();

    await expect(
      publishCandidates({
        root: output,
        candidates: [report, { ...report, raw_model_response: "hidden" }],
        reviewCaches: [fixtureReviewCache(report), fixtureReviewCache(report)],
        state: initialOperationsState("2026-08-02T12:30:00.000Z"),
        generatedAt: "2026-08-02T12:30:00.000Z",
      }),
    ).rejects.toThrow(/schema/iu);
    await expect(
      access(join(output, ...reportPath(report).split("/"))),
    ).rejects.toMatchObject({ code: "ENOENT" });
  });

  test("rejects a cache that does not belong to its report before publication", async () => {
    const output = await root();
    const report = await fixtureReportV5();
    const cache = fixtureReviewCache(report);

    await expect(
      publishCandidates({
        root: output,
        candidates: [report],
        reviewCaches: [
          {
            ...cache,
            repository: "owner/different-repo",
          },
        ],
        state: initialOperationsState("2026-08-02T12:30:00.000Z"),
        generatedAt: "2026-08-02T12:30:00.000Z",
      }),
    ).rejects.toThrow(/does not match/iu);
    await expect(
      access(join(output, ...reportPath(report).split("/"))),
    ).rejects.toMatchObject({ code: "ENOENT" });
  });
});
