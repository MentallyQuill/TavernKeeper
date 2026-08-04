import { describe, expect, test } from "vitest";

import {
  classifyFailure,
  failureFingerprint,
} from "../src/operations/failure.js";

describe("operation failure domains", () => {
  test.each([
    [
      { code: "SCANNER_FAILED", scope: "system", component: "opengrep" },
      { code: "SCANNER_FAILED", domain: "target", component: "opengrep" },
    ],
    [
      { code: "MODEL_PROVIDER", scope: "system" },
      {
        code: "MODEL_PROVIDER",
        domain: "shared",
        component: "contextual-model",
      },
    ],
    [
      { code: "MODEL_AUTHENTICATION", scope: "system" },
      {
        code: "MODEL_AUTHENTICATION",
        domain: "security",
        component: "contextual-model",
      },
    ],
    [
      { code: "SCAN_POLICY_MISMATCH", scope: "system" },
      {
        code: "SCAN_POLICY_MISMATCH",
        domain: "security",
        component: "orchestrator",
      },
    ],
    [
      { code: "MODEL_RESPONSE_ORIGIN", scope: "system" },
      {
        code: "MODEL_RESPONSE_ORIGIN",
        domain: "security",
        component: "contextual-model",
      },
    ],
    [
      { code: "MODEL_IDENTITY_MISMATCH", scope: "system" },
      {
        code: "MODEL_IDENTITY_MISMATCH",
        domain: "security",
        component: "contextual-model",
      },
    ],
    [
      { code: "UNRECOGNIZED_SYSTEM_FAILURE", scope: "system" },
      {
        code: "UNRECOGNIZED_SYSTEM_FAILURE",
        domain: "shared",
        component: "orchestrator",
      },
    ],
    [
      new Error("body deliberately ignored"),
      { code: "CLI_FAILED", domain: "shared", component: "orchestrator" },
    ],
  ])("classifies a bounded failure descriptor", (input, expected) => {
    expect(classifyFailure(input)).toEqual(expected);
  });

  test("fingerprints the complete failure identity", () => {
    const opengrep = classifyFailure({
      code: "SCANNER_FAILED",
      scope: "system",
      component: "opengrep",
    });
    const gitleaks = classifyFailure({
      code: "SCANNER_FAILED",
      scope: "system",
      component: "gitleaks",
    });

    expect(failureFingerprint(opengrep)).not.toBe(failureFingerprint(gitleaks));
    expect(failureFingerprint(opengrep)).toMatch(/^[a-f0-9]{64}$/u);
  });

  test("preserves bounded scanner diagnostics", () => {
    expect(
      classifyFailure({
        code: "SCANNER_FAILED",
        scope: "system",
        component: "opengrep",
        diagnostic: "rule_timeout",
      }),
    ).toEqual({
      code: "SCANNER_FAILED",
      domain: "target",
      component: "opengrep",
      diagnostic: "rule_timeout",
    });
  });
});
