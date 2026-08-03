import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { afterEach, describe, expect, test } from "vitest";

import { buildSite } from "../src/site/build-site.js";

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
    ]) {
      expect(index).not.toContain(invalidReportId);
      expect(publishedFiles.files.join("\n")).not.toContain(invalidReportId);
    }
  });

  test("copies only reports, schemas, and public rule documentation", async () => {
    const root = await mkdtemp(join(tmpdir(), "tavernkeeper-site-"));
    roots.push(root);
    await Promise.all(
      ["reports", "schemas", "docs/rules", "src", "config", "operations"].map(
        (path) => mkdir(join(root, ...path.split("/")), { recursive: true }),
      ),
    );
    await writeFile(join(root, "reports", "index.json"), "{}\n");
    await mkdir(join(root, "reports", "github", "42", "sha", "2", "1"), {
      recursive: true,
    });
    await writeFile(
      join(root, "reports", "github", "42", "sha", "2", "1", "report.json"),
      '{"schema_version":4}\n',
    );
    await writeFile(
      join(root, "reports", "github", "42", "sha", "2", "1", "index.html"),
      "<!doctype html>\n",
    );
    await writeFile(join(root, "schemas", "report.json"), "{}\n");
    await writeFile(join(root, "docs", "rules", "rule.md"), "# Rule\n");
    await writeFile(join(root, "src", "secret.ts"), "scanner source\n");
    await writeFile(join(root, "config", "policy.json"), "private config\n");
    await writeFile(join(root, "operations", "state.json"), "private state\n");
    const output = join(root, "_site");

    const result = await buildSite({ root, output });

    expect(result.files).toEqual([
      ".nojekyll",
      "index.html",
      "reports/github/42/sha/2/1/index.html",
      "reports/github/42/sha/2/1/report.json",
      "reports/index.json",
      "rules/rule.md",
      "schemas/report.json",
    ]);
    expect(await readFile(join(output, "reports", "index.json"), "utf8")).toBe(
      "{}\n",
    );
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
