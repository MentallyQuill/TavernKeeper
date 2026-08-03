import { describe, expect, test } from "vitest";

import { safeCliErrorRecord } from "../src/cli/io.js";

describe("safe CLI error diagnostics", () => {
  test("retains only an allowlisted scanner component", () => {
    expect(
      safeCliErrorRecord({
        code: "MALFORMED_SCANNER_OUTPUT",
        scope: "system",
        component: "opengrep",
      }),
    ).toEqual({
      code: "MALFORMED_SCANNER_OUTPUT",
      scope: "system",
      component: "opengrep",
    });
  });

  test("drops arbitrary component text and preserves the sanitized contract", () => {
    expect(
      safeCliErrorRecord({
        code: "not safe",
        scope: "unexpected",
        component: "secret-bearing target output",
      }),
    ).toEqual({ code: "CLI_FAILED", scope: "system" });
  });

  test("does not preserve provider-shaped diagnostic fields", () => {
    expect(
      safeCliErrorRecord({
        code: "SCANNER_FAILED",
        scope: "system",
        diagnostic: "provider output that must never be logged",
        httpStatus: 413,
      }),
    ).toEqual({ code: "SCANNER_FAILED", scope: "system" });
  });
});
