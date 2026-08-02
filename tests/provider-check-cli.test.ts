import { describe, expect, test } from "vitest";

import { checkConfiguredProvider } from "../src/cli/provider-check.js";

describe("provider connectivity CLI", () => {
  test("classifies missing provider settings as model configuration", async () => {
    await expect(checkConfiguredProvider({})).rejects.toMatchObject({
      code: "MODEL_CONFIGURATION",
      scope: "system",
    });
  });
});
