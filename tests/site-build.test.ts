import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, test } from "vitest";

import { projectReportToIndexV5 } from "../src/publish/publisher.js";
import { historyPath, reportPath } from "../src/publish/report-path.js";
import { buildSite } from "../src/site/build-site.js";
import { fixtureReportV5 } from "./helpers/v5-report.js";

const roots: string[] = [];

afterEach(async () => {
  await Promise.all(
    roots.splice(0).map((root) => rm(root, { recursive: true, force: true })),
  );
});

describe("Pages site allowlist", () => {
  test("tracked public output excludes invalid legacy report IDs", async () => {
    const root = join(import.meta.dirname, "..");
    const index = await readFile(join(root, "reports", "index.json"), "utf8");
    const output = await mkdtemp(join(root, ".tavernkeeper-reset-site-"));
    roots.push(output);
    const publishedFiles = await buildSite({
      root,
      output,
    });

    for (const invalidReportId of [
      "2f5195e3ee9ec8ad2cdde525d07f3cba546a4c128f45bcabbae53e2238de679d",
      "7053d5db805d0853b3f5c30b7b1a0f4bad50b64a70fd1b3de474f91d0447237b",
      "42ed790bc16eb4a70965c61918fbd7d611b593f667f4c639f60f6f9b04d9875f",
    ]) {
      expect(index).not.toContain(invalidReportId);
      expect(publishedFiles.files.join("\n")).not.toContain(invalidReportId);
    }
  }, 15_000);

  test("copies only reports, schemas, and public rule documentation", async () => {
    const root = await mkdtemp(join(tmpdir(), "tavernkeeper-site-"));
    roots.push(root);
    await Promise.all(
      [
        "reports",
        "schemas",
        "docs/rules",
        "src/site/assets",
        "config",
        "operations",
      ].map((path) =>
        mkdir(join(root, ...path.split("/")), { recursive: true }),
      ),
    );
    const report = await fixtureReportV5();
    const entry = projectReportToIndexV5(report);
    const legacyEntry = structuredClone(entry);
    delete (legacyEntry.coverage as Record<string, unknown>)
      .metadata_only_candidates;
    const reportDirectory = join(root, ...reportPath(report).split("/"));
    const historyDirectory = join(root, ...historyPath(report).split("/"));
    await Promise.all([
      mkdir(reportDirectory, { recursive: true }),
      mkdir(historyDirectory, { recursive: true }),
    ]);
    await writeFile(
      join(root, "reports", "index.json"),
      `${JSON.stringify({
        schema_version: 5,
        generated_at: "2026-08-03T12:00:00.000Z",
        reports: [legacyEntry],
      })}\n`,
    );
    await writeFile(
      join(reportDirectory, "report.json"),
      `${JSON.stringify(report)}\n`,
    );
    await writeFile(join(reportDirectory, "index.html"), "old report html\n");
    await writeFile(
      join(historyDirectory, "history.json"),
      `${JSON.stringify([entry])}\n`,
    );
    await writeFile(join(historyDirectory, "index.html"), "old history html\n");
    await writeFile(join(root, "schemas", "report.json"), "{}\n");
    await writeFile(join(root, "docs", "rules", "rule.md"), "# Rule\n");
    await writeFile(
      join(root, "src", "site", "assets", "favicon.svg"),
      '<svg viewBox="0 0 24 24" />\n',
    );
    await writeFile(join(root, "src", "secret.ts"), "scanner source\n");
    await writeFile(join(root, "config", "policy.json"), "private config\n");
    await writeFile(join(root, "operations", "state.json"), "private state\n");
    const output = join(root, "_site");

    const result = await buildSite({ root, output });

    expect(result.files).toContain("assets/report-search.js");
    expect(result.files).toContain("assets/favicon.svg");
    expect(result.files).toContain(`${reportPath(report)}/index.html`);
    expect(result.files).toContain(`${historyPath(report)}/index.html`);

    const landing = await readFile(join(output, "index.html"), "utf8");
    expect(landing).toContain(
      "Technical security reports for Tavernary projects",
    );
    expect(landing).toContain('id="reports"');
    expect(landing).toContain('data-report-search="true"');
    expect(landing).toContain(report.repository);
    expect(landing).toContain(
      "No material or immediate-danger concern was identified",
    );
    expect(landing).toContain("bounded candidate context");
    expect(landing).toContain(
      "does not run dependencies, scripts, builds, tests, Actions, or target executables",
    );
    for (const [name, url] of [
      ["Gitleaks", "https://github.com/gitleaks/gitleaks"],
      ["OpenGrep", "https://github.com/opengrep/opengrep"],
      ["OSV-Scanner", "https://github.com/google/osv-scanner"],
      ["zizmor", "https://github.com/zizmorcore/zizmor"],
      ["malcontent", "https://github.com/chainguard-dev/malcontent"],
    ] as const) {
      expect(landing).toContain(name);
      expect(landing).toContain(url);
    }
    expect(landing).toContain("version-pinned");
    expect(landing).toContain("untrusted data");
    expect(landing).toContain("advisory evidence");
    expect(landing).not.toContain("Report ID");

    const reportHtml = await readFile(
      join(output, ...reportPath(report).split("/"), "index.html"),
      "utf8",
    );
    expect(reportHtml).toContain("TavernKeeper Scan Report");
    expect(reportHtml).not.toContain("old report html");
    const historyHtml = await readFile(
      join(output, ...historyPath(report).split("/"), "index.html"),
      "utf8",
    );
    expect(historyHtml).toContain("TavernKeeper Scan History");
    expect(historyHtml).not.toContain("old history html");

    const publishedIndex = JSON.parse(
      await readFile(join(output, "reports", "index.json"), "utf8"),
    );
    expect(publishedIndex).toMatchObject({
      schema_version: 5,
      reports: [
        {
          coverage: { metadata_only_candidates: 0 },
        },
      ],
    });
    await expect(
      readFile(join(output, "src", "secret.ts")),
    ).rejects.toMatchObject({ code: "ENOENT" });
    await expect(
      readFile(join(output, "operations", "state.json")),
    ).rejects.toMatchObject({ code: "ENOENT" });
  });

  test("refuses to overwrite the repository or an allowlisted source tree", async () => {
    const root = await mkdtemp(join(tmpdir(), "tavernkeeper-site-"));
    roots.push(root);
    await mkdir(join(root, "reports"), { recursive: true });

    await expect(buildSite({ root, output: root })).rejects.toThrow(
      /site output path/iu,
    );
    await expect(
      buildSite({ root, output: join(root, "reports") }),
    ).rejects.toThrow(/site output path/iu);
  });
});
