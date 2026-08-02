import { createHash } from "node:crypto";
import { mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, test } from "vitest";

import type { InventoryClassification } from "../src/inventory/classify.js";
import type { InventoryFile } from "../src/inventory/inventory-handler.js";
import { loadModelCorpus, selectModelCorpus } from "../src/model/corpus.js";

function file(path: string): InventoryFile {
  return {
    path,
    bytes: 100,
    sha256: "a".repeat(64),
    kind: "text",
  };
}

const classification: InventoryClassification = {
  modelEligible: [file("b.ts"), file("README.md"), file("a.ts")],
  applicability: { osv: false, zizmor: false, malcontent: false },
  scannerInputs: { osv: [], zizmor: [], malcontent: [] },
  excluded: {
    dependency_lockfiles: { files: 0, bytes: 0 },
    vendored_dependencies: { files: 0, bytes: 0 },
    generated_bundles: { files: 0, bytes: 0 },
    minified_files: { files: 0, bytes: 0 },
    binaries: { files: 0, bytes: 0 },
    archives: { files: 0, bytes: 0 },
    oversized_files: { files: 0, bytes: 0 },
    unsafe_entries: { files: 0, bytes: 0 },
  },
};

function compareExpectedPath(left: InventoryFile, right: InventoryFile) {
  const leftIdentity = left.path.toLowerCase();
  const rightIdentity = right.path.toLowerCase();
  if (leftIdentity !== rightIdentity)
    return leftIdentity < rightIdentity ? -1 : 1;
  return left.path === right.path ? 0 : left.path < right.path ? -1 : 1;
}

describe("model corpus selection", () => {
  test("standard mode includes every eligible first-party text file", () => {
    expect(selectModelCorpus({ classification })).toEqual(
      classification.modelEligible.toSorted(compareExpectedPath),
    );
  });

  test("deep mode includes every eligible first-party text file without aggregate caps", () => {
    expect(selectModelCorpus({ classification })).toEqual(
      classification.modelEligible.toSorted(compareExpectedPath),
    );
  });

  test("loads selected source only when bytes and hash still match inventory", async () => {
    const root = await mkdtemp(join(tmpdir(), "tavernkeeper-corpus-test-"));
    const content = "export const value = 1;\n";
    await writeFile(join(root, "source.ts"), content);
    const selected = [
      {
        path: "source.ts",
        bytes: Buffer.byteLength(content),
        sha256: createHash("sha256").update(content).digest("hex"),
        kind: "text" as const,
      },
    ];

    await expect(loadModelCorpus(root, selected)).resolves.toEqual([
      { ...selected[0], content },
    ]);
    await writeFile(join(root, "source.ts"), "changed\n");
    await expect(loadModelCorpus(root, selected)).rejects.toThrow(
      "changed after safe inventory",
    );
  });
});
