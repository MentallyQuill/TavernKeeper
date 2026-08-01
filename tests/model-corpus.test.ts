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

describe("model corpus selection", () => {
  test("standard mode includes the complete eligible changed and finding union", () => {
    expect(
      selectModelCorpus({
        mode: "standard",
        classification,
        changedPaths: ["b.ts", "not-eligible.bin"],
        findingPaths: ["a.ts", "a.ts"],
      }).map(({ path }) => path),
    ).toEqual(["a.ts", "b.ts"]);
  });

  test("deep mode includes every eligible first-party text file without aggregate caps", () => {
    expect(
      selectModelCorpus({
        mode: "deep",
        classification,
        changedPaths: [],
        findingPaths: [],
      }).map(({ path }) => path),
    ).toEqual(["a.ts", "b.ts", "README.md"]);
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
