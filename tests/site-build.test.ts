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
  test("copies only reports, schemas, and public rule documentation", async () => {
    const root = await mkdtemp(join(tmpdir(), "tavernkeeper-site-"));
    roots.push(root);
    await Promise.all(
      ["reports", "schemas", "docs/rules", "src", "config", "operations"].map(
        (path) => mkdir(join(root, ...path.split("/")), { recursive: true }),
      ),
    );
    await writeFile(join(root, "reports", "index.json"), "{}\n");
    await mkdir(
      join(root, "reports", "github", "42", "sha", "1", "standard", "1"),
      { recursive: true },
    );
    await writeFile(
      join(
        root,
        "reports",
        "github",
        "42",
        "sha",
        "1",
        "standard",
        "1",
        "report.json",
      ),
      '{"schema_version":3}\n',
    );
    await writeFile(
      join(
        root,
        "reports",
        "github",
        "42",
        "sha",
        "1",
        "standard",
        "1",
        "index.html",
      ),
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
      "reports/github/42/sha/1/standard/1/index.html",
      "reports/github/42/sha/1/standard/1/report.json",
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
