import { readFile, readdir } from "node:fs/promises";

import { parse } from "yaml";
import { describe, expect, test } from "vitest";

describe("non-scanning false-positive appeal", () => {
  test("collects immutable evidence and clearly states its non-operational effect", async () => {
    const text = await readFile(
      new URL("../.github/ISSUE_TEMPLATE/false-positive.yml", import.meta.url),
      "utf8",
    );
    const form = parse(text) as {
      body: Array<{ id?: string; attributes?: { value?: string } }>;
    };
    const ids = form.body.flatMap(({ id }) => (id === undefined ? [] : [id]));

    expect(ids).toEqual(
      expect.arrayContaining([
        "report_url",
        "report_id",
        "finding_fingerprint",
        "maintainer_relationship",
        "explanation",
      ]),
    );
    expect(text).toMatch(/does not trigger a TavernKeeper scan/iu);
    expect(text).toMatch(/does not change Tavernary/iu);
    expect(text).toMatch(/does not hide or dismiss a finding/iu);
    expect(text).toMatch(/global.*policy correction/iu);
    expect(text).not.toMatch(/approve this report|recolor this report/iu);
  });

  test("has no issue-event workflow that can turn an appeal into work", async () => {
    let workflows: string[] = [];
    try {
      workflows = await readdir(
        new URL("../.github/workflows/", import.meta.url),
      );
    } catch {
      workflows = [];
    }
    const texts = await Promise.all(
      workflows.map((name) =>
        readFile(
          new URL(`../.github/workflows/${name}`, import.meta.url),
          "utf8",
        ),
      ),
    );

    expect(texts.join("\n")).not.toMatch(
      /issue_comment|issues:\s*\n|pull_request_target/iu,
    );
  });

  test("exposes no per-report adjudication command", async () => {
    const packageJson = JSON.parse(
      await readFile(new URL("../package.json", import.meta.url), "utf8"),
    ) as { scripts: Record<string, string> };

    expect(packageJson.scripts).not.toHaveProperty("adjudicate");
  });
});
