import { mkdir, mkdtemp, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, test } from "vitest";

import {
  inventoryRepository,
  validatePortablePaths,
} from "../src/inventory/inventory-handler.js";

describe("safe inventory", () => {
  test("rejects symbolic links instead of silently reducing coverage", async () => {
    const temporary = await mkdtemp(join(tmpdir(), "tavernkeeper-inventory-"));
    const root = join(temporary, "repository");
    const outside = join(temporary, "outside");
    await mkdir(join(root, "src"), { recursive: true });
    await writeFile(join(root, "z.txt"), "last\n");
    await writeFile(join(root, "src", "a.ts"), "export const a = 1;\n");
    await mkdir(outside);
    await writeFile(join(outside, "outside.txt"), "outside\n");
    await symlink(outside, join(root, "outside-link"), "junction");

    const result = await inventoryRepository({
      root,
      maxFiles: 10,
      maxTotalBytes: 1024,
      maxFileBytes: 512,
    });

    expect(result).toMatchObject({
      ok: false,
      error: { code: "UNSAFE_LINK" },
    });
  });

  test("fails closed when file or byte budgets are exceeded", async () => {
    const temporary = await mkdtemp(join(tmpdir(), "tavernkeeper-budget-"));
    const root = join(temporary, "repository");
    await mkdir(root, { recursive: true });
    await writeFile(join(root, "a.txt"), "a");
    await writeFile(join(root, "b.txt"), "b");

    const result = await inventoryRepository({
      root,
      maxFiles: 1,
      maxTotalBytes: 1024,
      maxFileBytes: 512,
    });

    expect(result).toMatchObject({
      ok: false,
      error: { code: "FILE_BUDGET_EXCEEDED" },
    });
  });

  test("retains file metadata without retaining repository source", async () => {
    const temporary = await mkdtemp(join(tmpdir(), "tavernkeeper-metadata-"));
    const root = join(temporary, "repository");
    await mkdir(root, { recursive: true });
    await writeFile(join(root, "README.md"), "private source text\n");

    const result = await inventoryRepository({
      root,
      maxFiles: 10,
      maxTotalBytes: 1024,
      maxFileBytes: 512,
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.files[0]).not.toHaveProperty("content");
  });

  test("rejects portable paths that collide after case folding", () => {
    const result = validatePortablePaths(["src/Entry.ts", "src/entry.ts"]);

    expect(result).toMatchObject({
      ok: false,
      error: { code: "AMBIGUOUS_PATH" },
    });
  });

  test.each([
    "../escape.ts",
    "/absolute.ts",
    "C:/absolute.ts",
    "src/CON.txt",
    "src/bidi\u202Ename.ts",
    "src/lone-surrogate\uD800.ts",
  ])("rejects unsafe portable path %j", (path) => {
    const result = validatePortablePaths([path]);

    expect(result).toMatchObject({
      ok: false,
      error: { code: "UNSAFE_PATH" },
    });
  });

  test("hashes oversized files without retaining their source", async () => {
    const temporary = await mkdtemp(join(tmpdir(), "tavernkeeper-oversized-"));
    const root = join(temporary, "repository");
    await mkdir(root, { recursive: true });
    await writeFile(join(root, "large.bin"), "x".repeat(513));

    const result = await inventoryRepository({
      root,
      maxFiles: 10,
      maxTotalBytes: 1024,
      maxFileBytes: 512,
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.files).toEqual([
      expect.objectContaining({
        path: "large.bin",
        kind: "oversized",
        sha256: expect.stringMatching(/^[a-f0-9]{64}$/u),
      }),
    ]);
    expect(result.value.files[0]).not.toHaveProperty("content");
  });

  test("returns stable portable ordering and exact inventory totals", async () => {
    const temporary = await mkdtemp(join(tmpdir(), "tavernkeeper-totals-"));
    const root = join(temporary, "repository");
    await mkdir(join(root, "src"), { recursive: true });
    await writeFile(join(root, "z.txt"), "zz");
    await writeFile(join(root, "src", "a.ts"), "a");

    const result = await inventoryRepository({
      root,
      maxFiles: 10,
      maxTotalBytes: 1024,
      maxFileBytes: 512,
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.files.map((file) => file.path)).toEqual([
      "src/a.ts",
      "z.txt",
    ]);
    expect(result.value.totals).toEqual({ files: 2, bytes: 3 });
  });

  test("inventories committed node_modules content", async () => {
    const temporary = await mkdtemp(join(tmpdir(), "tavernkeeper-vendored-"));
    const root = join(temporary, "repository");
    await mkdir(join(root, "node_modules", "vendored"), { recursive: true });
    await writeFile(
      join(root, "node_modules", "vendored", "index.min.js"),
      "fetch(endpoint)",
    );

    const result = await inventoryRepository({
      root,
      maxFiles: 10,
      maxTotalBytes: 1024,
      maxFileBytes: 512,
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.files.map(({ path }) => path)).toEqual([
      "node_modules/vendored/index.min.js",
    ]);
  });

  test("classifies invalid UTF-8 source as binary", async () => {
    const temporary = await mkdtemp(join(tmpdir(), "tavernkeeper-utf8-"));
    const root = join(temporary, "repository");
    await mkdir(root, { recursive: true });
    await writeFile(join(root, "opaque.dat"), Uint8Array.from([0xc3, 0x28]));

    const result = await inventoryRepository({
      root,
      maxFiles: 10,
      maxTotalBytes: 1024,
      maxFileBytes: 512,
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.files[0]?.kind).toBe("binary");
  });

  test("marks heavily minified text from bounded metadata sampling", async () => {
    const temporary = await mkdtemp(join(tmpdir(), "tavernkeeper-minified-"));
    const root = join(temporary, "repository");
    await mkdir(root, { recursive: true });
    await writeFile(join(root, "application.js"), "const value=1;".repeat(400));

    const result = await inventoryRepository({
      root,
      maxFiles: 10,
      maxTotalBytes: 10_000,
      maxFileBytes: 10_000,
    });

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.files[0]?.likelyMinified).toBe(true);
  });
});
