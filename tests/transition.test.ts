import { describe, expect, test } from "vitest";

import {
  completedScanTransition,
  failedScanTransition,
  ScanTransitionSchema,
} from "../src/cli/transition.js";

const target = {
  source_id: "github-42",
  provider: "github" as const,
  repository_id: 42,
  repository: "owner/repo",
  target_sha: "a".repeat(40),
  canonical_url: "https://github.com/owner/repo",
};
const at = "2026-08-04T04:01:00.000Z";

describe("scan transitions", () => {
  test("emits a version 2 completed transition", () => {
    expect(completedScanTransition(target, at)).toEqual({
      schema_version: 2,
      status: "completed",
      target,
      at,
    });
  });

  test("preserves the complete bounded failure descriptor", () => {
    const transition = failedScanTransition(
      target,
      {
        code: "MODEL_PROVIDER",
        domain: "shared",
        component: "contextual-model",
      },
      at,
    );

    expect(transition).toEqual({
      schema_version: 2,
      status: "failure",
      target,
      failure: {
        code: "MODEL_PROVIDER",
        domain: "shared",
        component: "contextual-model",
      },
      at,
    });
    expect(ScanTransitionSchema.parse(transition)).toEqual(transition);
  });

  test("rejects legacy transitions that discard failure identity", () => {
    expect(
      ScanTransitionSchema.safeParse({
        schema_version: 1,
        status: "failure",
        target,
        code: "MODEL_PROVIDER",
        scope: "system",
        at,
      }).success,
    ).toBe(false);
  });
});
