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
      domain: "target",
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
    ).toEqual({
      code: "CLI_FAILED",
      domain: "shared",
      component: "orchestrator",
    });
  });

  test("uses a bounded phase fallback only for an otherwise-untyped error", () => {
    const fallback = {
      code: "CLI_FAILED",
      domain: "target" as const,
      component: "contextual-model" as const,
    };

    expect(
      safeCliErrorRecord(new Error("body deliberately ignored"), fallback),
    ).toEqual(fallback);
    expect(
      safeCliErrorRecord(
        {
          code: "MODEL_PROVIDER",
          scope: "system",
        },
        fallback,
      ),
    ).toEqual({
      code: "MODEL_PROVIDER",
      domain: "shared",
      component: "contextual-model",
    });
  });

  test("does not preserve provider-shaped diagnostic fields", () => {
    expect(
      safeCliErrorRecord({
        code: "SCANNER_FAILED",
        scope: "system",
        diagnostic: "provider output that must never be logged",
        httpStatus: 413,
      }),
    ).toEqual({
      code: "SCANNER_FAILED",
      domain: "target",
      component: "orchestrator",
    });
  });

  test("preserves only an allowlisted model-response stage", () => {
    expect(
      safeCliErrorRecord({
        code: "MODEL_INVALID_RESPONSE",
        scope: "repository",
        diagnostic: "assessment_developer_action",
      }),
    ).toEqual({
      code: "MODEL_INVALID_RESPONSE",
      domain: "target",
      component: "contextual-model",
      diagnostic: "assessment_developer_action",
    });

    expect(
      safeCliErrorRecord({
        code: "MODEL_INVALID_RESPONSE",
        scope: "repository",
        diagnostic: "secret-bearing provider output",
      }),
    ).toEqual({
      code: "MODEL_INVALID_RESPONSE",
      domain: "target",
      component: "contextual-model",
    });
  });

  test("preserves a locally derived provider category without raw details", () => {
    expect(
      safeCliErrorRecord({
        code: "MODEL_PROVIDER",
        scope: "system",
        diagnostic: "provider_schema_rejected",
        httpStatus: 400,
        message: "provider response text must not be logged",
      }),
    ).toEqual({
      code: "MODEL_PROVIDER",
      domain: "shared",
      component: "contextual-model",
      diagnostic: "provider_schema_rejected",
    });
  });

  test("preserves the bounded contextual-contract stage", () => {
    expect(
      safeCliErrorRecord({
        code: "MODEL_PROVIDER",
        scope: "system",
        diagnostic: "provider_contextual_contract_rejected",
      }),
    ).toEqual({
      code: "MODEL_PROVIDER",
      domain: "shared",
      component: "contextual-model",
      diagnostic: "provider_contextual_contract_rejected",
    });
  });
});
