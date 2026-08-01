import { describe, expect, test } from "vitest";

import { assertArchivePlan } from "../src/inventory/archive-guards.js";

const policy = {
  maxEntries: 100,
  maxDepth: 4,
  maxExpandedBytes: 1024,
  maxCompressionRatio: 200,
};

describe("archive guards", () => {
  test("rejects archives that exceed an expansion ceiling", () => {
    expect(() =>
      assertArchivePlan(
        [{ path: "payload.bin", compressed: 1, expanded: 1000, depth: 5 }],
        policy,
      ),
    ).toThrow(/archive ceiling/u);
  });

  test("rejects links and unsafe portable entry paths before extraction", () => {
    expect(() =>
      assertArchivePlan(
        [
          {
            path: "../outside.txt",
            compressed: 10,
            expanded: 10,
            depth: 1,
            kind: "link",
          },
        ],
        policy,
      ),
    ).toThrow(/unsafe entry/u);
  });

  test("returns bounded aggregate sizes for a safe archive table", () => {
    expect(
      assertArchivePlan(
        [
          {
            path: "src/index.js",
            compressed: 10,
            expanded: 100,
            depth: 1,
          },
          {
            path: "README.md",
            compressed: 5,
            expanded: 10,
            depth: 1,
          },
        ],
        policy,
      ),
    ).toMatchObject({ compressedBytes: 15, expandedBytes: 110 });
  });
});
