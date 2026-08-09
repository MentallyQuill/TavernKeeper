import { readFile } from "node:fs/promises";
import { resolve } from "node:path";

import { describe, expect, test } from "vitest";

import { normalizeJavascript } from "../src/scanners/javascript-normalizer.js";

const testLimits = {
  transformTimeoutMs: 10_000,
  maxWorkerOldGenerationMb: 128,
  maxDerivativeBytes: 1_000_000,
  maxDerivativeBytesPerCandidate: 4_000_000,
  maxDerivativesPerCandidate: 64,
};

describe("non-executing JavaScript normalization", () => {
  test("extracts and returns actual bundle modules", async () => {
    const source = await readFile(
      resolve("tests/fixtures/javascript-analysis/webpack-hidden.js"),
      "utf8",
    );
    const result = await normalizeJavascript(source, testLimits);

    expect(
      result.derivatives.some(
        ({ transform }) => transform === "webcrack-module",
      ),
    ).toBe(true);
    expect(result.derivatives.map(({ content }) => content).join("\n")).toMatch(
      /process\.env/u,
    );
  });

  test("does not enable webcrack deobfuscation or a sandbox", async () => {
    const calls: unknown[] = [];
    await normalizeJavascript(
      "const value=1",
      testLimits,
      async (source, options) => {
        calls.push(options);
        return { code: source, bundle: undefined };
      },
    );
    expect(calls).toEqual([
      { deobfuscate: false, unminify: true, unpack: true, jsx: false },
    ]);
  });

  test("reports malformed input as a parse limitation", async () => {
    const result = await normalizeJavascript("function {", testLimits);
    expect(result).toMatchObject({ derivatives: [], limitation: "parse" });
  });

  test("never executes target source", async () => {
    delete (globalThis as Record<string, unknown>).__tavernkeeperTargetRan;
    await normalizeJavascript(
      "globalThis.__tavernkeeperTargetRan=true;(()=>42)()",
      testLimits,
    );
    expect(
      (globalThis as Record<string, unknown>).__tavernkeeperTargetRan,
    ).toBeUndefined();
  });
});
