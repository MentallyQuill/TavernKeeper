import { readFile } from "node:fs/promises";

import { describe, expect, test } from "vitest";

const providerWorkflows = [
  "provider-check.yml",
  "reconcile.yml",
  "scan-and-publish.yml",
];

describe("configured model provider credentials", () => {
  test.each(providerWorkflows)(
    "%s uses the credentials that are present in GitHub",
    async (name) => {
      const source = await readFile(
        new URL(`../.github/workflows/${name}`, import.meta.url),
        "utf8",
      );

      expect(source).toContain(
        "TAVERNKEEPER_API_ENDPOINT: ${{ secrets.TAVERNKEEPER_API_ENDPOINT }}",
      );
      expect(source).toContain(
        "TAVERNKEEPER_API_KEY: ${{ secrets.TAVERNKEEPER_API_KEY }}",
      );
      expect(source).toContain(
        "TAVERNKEEPER_MODEL: ${{ secrets.TAVERNKEEPER_MODEL }}",
      );
      expect(source).not.toContain("OPENAI_WIF_AUDIENCE");
    },
  );

  test.each(["provider-check.yml", "scan-and-publish.yml"])(
    "%s uses the bounded JSON repair credentials",
    async (name) => {
      const source = await readFile(
        new URL(`../.github/workflows/${name}`, import.meta.url),
        "utf8",
      );

      expect(source).toContain(
        "JSONREPAIR_API_ENDPOINT: ${{ secrets.JSONREPAIR_API_ENDPOINT }}",
      );
      expect(source).toContain(
        "JSONREPAIR_API_KEY: ${{ secrets.JSONREPAIR_API_KEY }}",
      );
      expect(source).toContain(
        "JSONREPAIR_MODEL: ${{ secrets.JSONREPAIR_MODEL }}",
      );
    },
  );

  test("reconcile does not treat JSON repair as a primary provider", async () => {
    const source = await readFile(
      new URL("../.github/workflows/reconcile.yml", import.meta.url),
      "utf8",
    );
    expect(source).not.toContain("JSONREPAIR_");
  });
});
