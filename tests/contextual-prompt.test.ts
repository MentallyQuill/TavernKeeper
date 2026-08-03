import { describe, expect, test } from "vitest";

import {
  ECOSYSTEM_CONTEXT_VERSION,
  ecosystemContext,
} from "../src/context/ecosystem-context.js";

describe("SillyTavern ecosystem context", () => {
  test("balances expected extension powers with rare malicious threats", () => {
    expect(ECOSYSTEM_CONTEXT_VERSION).toBe("sillytavern-community-v1");
    expect(ecosystemContext()).toMatch(/built in good faith/iu);
    expect(ecosystemContext()).toMatch(/model-provider credentials/iu);
    expect(ecosystemContext()).toMatch(/API-key phishing/iu);
    expect(ecosystemContext()).toMatch(/untrusted data/iu);
  });
});
