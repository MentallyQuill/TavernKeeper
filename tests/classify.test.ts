import { describe, expect, test } from "vitest";

import { classifyInventory } from "../src/inventory/classify.js";
import type {
  Inventory,
  InventoryFile,
} from "../src/inventory/inventory-handler.js";

function file(
  path: string,
  bytes: number,
  kind: InventoryFile["kind"] = "text",
  extra: Partial<InventoryFile> = {},
): InventoryFile {
  return {
    path,
    bytes,
    kind,
    sha256: "a".repeat(64),
    ...extra,
  };
}

function inventory(files: InventoryFile[]): Inventory {
  const bytes = files.reduce((total, entry) => total + entry.bytes, 0);
  return {
    root: "C:/scan/repository",
    files,
    totals: { files: files.length, bytes },
    totalBytes: bytes,
  };
}

describe("inventory classification", () => {
  test("selects first-party text and records excluded file and byte totals", () => {
    const classification = classifyInventory(
      inventory([
        file("src/index.ts", 10),
        file("package-lock.json", 20),
        file("vendor/library.js", 30),
        file("dist/application.js", 40),
        file("src/application.min.js", 50, "text", {
          likelyMinified: true,
        }),
        file("assets/image.png", 60, "binary"),
        file("release.zip", 70, "binary"),
        file("docs/huge.md", 80, "oversized"),
      ]),
    );

    expect(classification.modelEligible.map((entry) => entry.path)).toEqual([
      "src/index.ts",
    ]);
    expect(classification.excluded).toMatchObject({
      dependency_lockfiles: { files: 1, bytes: 20 },
      vendored_dependencies: { files: 1, bytes: 30 },
      generated_bundles: { files: 1, bytes: 40 },
      minified_files: { files: 1, bytes: 50 },
      binaries: { files: 1, bytes: 60 },
      archives: { files: 1, bytes: 70 },
      oversized_files: { files: 1, bytes: 80 },
      unsafe_entries: { files: 0, bytes: 0 },
    });
  });

  test("routes only applicable artifacts to OSV, zizmor, and malcontent", () => {
    const classification = classifyInventory(
      inventory([
        file("package.json", 10),
        file("Cargo.toml", 11),
        file("composer.json", 12),
        file("pyproject.toml", 13),
        file("Gemfile", 14),
        file("package-lock.json", 15),
        file("go.mod", 16),
        file("requirements.txt", 17),
        file("packages.config", 18),
        file(".github/workflows/scan.yml", 20),
        file("scripts/install", 30, "text", { executable: true }),
        file("README.md", 40),
      ]),
    );

    expect(classification.applicability).toEqual({
      osv: true,
      zizmor: true,
      malcontent: true,
    });
    expect(classification.scannerInputs.osv.map((entry) => entry.path)).toEqual(
      ["package-lock.json", "go.mod", "requirements.txt", "packages.config"],
    );
    expect(
      classification.scannerInputs.zizmor.map((entry) => entry.path),
    ).toEqual([".github/workflows/scan.yml"]);
    expect(
      classification.scannerInputs.malcontent.map((entry) => entry.path),
    ).toEqual(["scripts/install"]);
  });
});
