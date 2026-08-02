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

  test("retains only allowlisted model response diagnostics", () => {
    expect(
      safeCliErrorRecord({
        code: "MODEL_INVALID_RESPONSE",
        scope: "system",
        diagnostic: "output_limit",
      }),
    ).toEqual({
      code: "MODEL_INVALID_RESPONSE",
      scope: "repository",
      diagnostic: "output_limit",
    });
    expect(
      safeCliErrorRecord({
        code: "MODEL_INVALID_RESPONSE",
        scope: "repository",
        diagnostic: "review_inconclusive",
      }),
    ).toEqual({
      code: "MODEL_INVALID_RESPONSE",
      scope: "repository",
      diagnostic: "review_inconclusive",
    });
    expect(
      safeCliErrorRecord({
        code: "MODEL_INVALID_RESPONSE",
        scope: "system",
        diagnostic: "role_schema_analyzer",
      }),
    ).toEqual({ code: "MODEL_INVALID_RESPONSE", scope: "repository" });
    expect(
      safeCliErrorRecord({
        code: "MODEL_INVALID_RESPONSE",
        scope: "system",
        diagnostic: "provider output that must never be logged",
      }),
    ).toEqual({ code: "MODEL_INVALID_RESPONSE", scope: "repository" });
  });

  test.each([
    "chunk_review_cache",
    "chunk_review_empty",
    "chunk_review_identity",
    "chunk_review_size",
    "synthesis_evidence",
    "synthesis_identity",
    "synthesis_inconclusive",
    "synthesis_schema",
  ])("retains repository-review diagnostic %s", (diagnostic) => {
    expect(
      safeCliErrorRecord({
        code: "MODEL_INVALID_RESPONSE",
        scope: "repository",
        diagnostic,
      }),
    ).toEqual({
      code: "MODEL_INVALID_RESPONSE",
      scope: "repository",
      diagnostic,
    });
  });

  test("retains only an error-range provider HTTP status", () => {
    expect(
      safeCliErrorRecord({
        code: "MODEL_PROVIDER",
        scope: "system",
        httpStatus: 413,
      }),
    ).toEqual({ code: "MODEL_PROVIDER", scope: "system", http_status: 413 });
    expect(
      safeCliErrorRecord({
        code: "MODEL_PROVIDER",
        scope: "system",
        httpStatus: "secret-bearing provider text",
      }),
    ).toEqual({ code: "MODEL_PROVIDER", scope: "system" });
    expect(
      safeCliErrorRecord({
        code: "MODEL_PROVIDER",
        scope: "system",
        httpStatus: 200,
      }),
    ).toEqual({ code: "MODEL_PROVIDER", scope: "system" });
  });
});
