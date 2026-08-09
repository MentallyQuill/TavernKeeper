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
});
