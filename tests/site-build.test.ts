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
  test("tracked public output excludes invalid development canaries", async () => {
    const root = join(import.meta.dirname, "..");
    const index = await readFile(join(root, "reports", "index.json"), "utf8");
    const output = await mkdtemp(join(root, ".tavernkeeper-reset-site-"));
    roots.push(output);
    const publishedFiles = await buildSite({
      root,
      output,
    });

    for (const invalidIdentity of [
      "1254077407",
      "1285208664",
      "2d4f818c2ad5855b0faff387d88c3f64479865c6",
      "1bce1fa73fe6c0fe8e767c773a832b94bb336720",
    ]) {
      expect(index).not.toContain(invalidIdentity);
      expect(publishedFiles.files.join("\n")).not.toContain(invalidIdentity);
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
