import { readFile } from "node:fs/promises";
import { basename, resolve } from "node:path";

import { describe, expect, test } from "vitest";

import {
  assertSafeArchiveEntries,
  releaseDownloads,
  verifyDigest,
} from "../scripts/install-scanners.mjs";
import { verifyScannerVersions } from "../scripts/verify-scanners.mjs";
import { ScannerPinsSchema } from "../src/config/policy.js";

async function pins() {
  return ScannerPinsSchema.parse(
    JSON.parse(
      await readFile(
        new URL("../config/scanners.v1.json", import.meta.url),
        "utf8",
      ),
    ),
  );
}

describe("pinned scanner installation", () => {
  test("derives every release download from the versioned scanner pins", async () => {
    expect(releaseDownloads(await pins())).toEqual([
      expect.objectContaining({ name: "gitleaks", version: "8.30.1" }),
      expect.objectContaining({ name: "opengrep", version: "1.26.0" }),
      expect.objectContaining({ name: "osv-scanner", version: "2.4.0" }),
      expect.objectContaining({ name: "zizmor", version: "1.28.0" }),
    ]);
  });

  test("rejects bytes that do not match the pinned digest", () => {
    expect(() => verifyDigest(Buffer.from("scanner"), "0".repeat(64))).toThrow(
      /digest/u,
    );
  });

  test("rejects traversal and links before scanner archive extraction", () => {
    expect(() =>
      assertSafeArchiveEntries([{ path: "../outside", type: "File", size: 1 }]),
    ).toThrow(/archive/u);
    expect(() =>
      assertSafeArchiveEntries([
        { path: "scanner", type: "SymbolicLink", size: 0 },
      ]),
    ).toThrow(/archive/u);
  });

  test("verifies each executable with only its pinned version command", async () => {
    const calls: Array<{ command: string; args: string[] }> = [];
    const toolsDir = resolve("/runner/temp/tavernkeeper-tools");
    const output = new Map([
      ["gitleaks", "8.30.1"],
      ["opengrep", "opengrep 1.26.0"],
      ["osv-scanner", "osv-scanner version: 2.4.0"],
      ["zizmor", "zizmor 1.28.0"],
      ["malcontent", "malcontent version v1.25.7"],
    ]);

    await verifyScannerVersions({
      pins: await pins(),
      toolsDir,
      run: async ({ command, args }) => {
        calls.push({ command, args });
        return {
          code: 0,
          stdout: output.get(basename(command)) ?? "",
          stderr: "",
        };
      },
    });

    expect(calls).toHaveLength(5);
    expect(calls.every(({ command }) => command.startsWith(toolsDir))).toBe(
      true,
    );
    expect(calls.map(({ args }) => args)).toEqual([
      ["version"],
      ["--version"],
      ["--version"],
      ["--version"],
      ["--version"],
    ]);
  });
});
