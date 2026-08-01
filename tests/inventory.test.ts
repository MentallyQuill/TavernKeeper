import { mkdir, mkdtemp, symlink, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, test } from "vitest";

import { inventoryRepository } from "../src/inventory/inventory-handler.js";

describe("safe inventory", () => {
  test("sorts files and never follows symbolic links", async () => {
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

    expect(result.ok).toBe(true);
    if (!result.ok) return;
    expect(result.value.files.map(({ path }) => path)).toEqual([
      "src/a.ts",
      "z.txt",
    ]);
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
});
