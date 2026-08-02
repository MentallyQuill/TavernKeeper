import { mkdtemp, readFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { basename, join, resolve } from "node:path";

import { describe, expect, test } from "vitest";

import {
  assertSafeArchiveEntries,
  installMalcontentContainer,
  malcontentContainerWrapper,
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

  test("pins Malcontent to an immutable official linux-amd64 image", async () => {
    const pin = (await pins()).malcontent;

    expect(pin).toEqual({
      version: "1.25.7",
      image:
        "cgr.dev/chainguard/malcontent@sha256:8c976e9536ded51e277f57946bb11e5ecd16989d1f767c5c2f1423722f5c0138",
    });
  });

  test("installs a locked-down Malcontent container wrapper", async () => {
    const scannerPins = await pins();
    const toolsDir = await mkdtemp(join(tmpdir(), "tavernkeeper-installer-"));
    const calls: Array<{ command: string; args: string[] }> = [];

    try {
      await installMalcontentContainer({
        pins: scannerPins,
        toolsDir,
        write: async () => undefined,
        chmodFile: async () => undefined,
        run: async ({ command, args }) => {
          calls.push({ command, args });
          return {
            code: 0,
            stdout:
              args[0] === "image"
                ? `${scannerPins.malcontent.image}\n`
                : "pulled\n",
            stderr: "",
          };
        },
      });
    } finally {
      await rm(toolsDir, { recursive: true, force: true });
    }

    expect(calls).toEqual([
      {
        command: "/usr/bin/docker",
        args: ["pull", scannerPins.malcontent.image],
      },
      {
        command: "/usr/bin/docker",
        args: [
          "image",
          "inspect",
          "--format={{index .RepoDigests 0}}",
          scannerPins.malcontent.image,
        ],
      },
    ]);

    const wrapper = malcontentContainerWrapper(scannerPins.malcontent.image);
    expect(wrapper).toContain("#!/bin/bash");
    expect(wrapper).toContain("--pull=never");
    expect(wrapper).toContain("--network=none");
    expect(wrapper).toContain("--read-only");
    expect(wrapper).toContain("--cap-drop=ALL");
    expect(wrapper).toContain("--security-opt=no-new-privileges");
    expect(wrapper).toContain(scannerPins.malcontent.image);
    expect(wrapper).not.toContain(":latest");
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
