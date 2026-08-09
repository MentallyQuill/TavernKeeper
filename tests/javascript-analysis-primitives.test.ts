import { createHash } from "node:crypto";

import { describe, expect, test } from "vitest";

import type { InventoryFile } from "../src/inventory/inventory-handler.js";
import { selectJavascriptCandidates } from "../src/scanners/javascript-candidates.js";
import { decodeJavascriptLiterals } from "../src/scanners/javascript-literals.js";
import { scanJavascriptSignatures } from "../src/scanners/javascript-signatures.js";
import type { JavascriptRepresentation } from "../src/scanners/javascript-analysis-types.js";

function inventoryFile(
  path: string,
  overrides: Partial<InventoryFile> = {},
): InventoryFile {
  return {
    path,
    bytes: 1,
    sha256: "a".repeat(64),
    kind: "text",
    ...overrides,
  };
}

function rawRepresentation(source: string): JavascriptRepresentation {
  return {
    stage: "raw",
    sha256: createHash("sha256").update(source).digest("hex"),
    parentSha256: null,
    transform: "original",
    depth: 0,
  };
}

describe("JavaScript candidate selection", () => {
  test("selects committed vendored and generated JavaScript", () => {
    expect(
      selectJavascriptCandidates([
        inventoryFile("src/index.ts"),
        inventoryFile("dist/app.min.js", { likelyMinified: true }),
        inventoryFile("node_modules/pkg/index.js"),
        inventoryFile("assets/logo.png", { kind: "binary" }),
      ]).map(({ path }) => path),
    ).toEqual(["dist/app.min.js", "node_modules/pkg/index.js", "src/index.ts"]);
  });

  test("retains binary and oversized JavaScript candidates for coverage", () => {
    expect(
      selectJavascriptCandidates([
        inventoryFile("dist/binary.js", { kind: "binary" }),
        inventoryFile("dist/huge.mjs", { kind: "oversized" }),
      ]).map(({ path, kind }) => ({ path, kind })),
    ).toEqual([
      { path: "dist/binary.js", kind: "binary" },
      { path: "dist/huge.mjs", kind: "oversized" },
    ]);
  });

  test("requires normalization only for minified or bundle-like JavaScript", () => {
    expect(
      selectJavascriptCandidates([
        inventoryFile("src/a.js"),
        inventoryFile("dist/app.min.js"),
        inventoryFile("dist/app.bundle.js"),
        inventoryFile("dist/generated.js", { likelyMinified: true }),
        inventoryFile("src/a.ts", { likelyMinified: true }),
      ]).map(({ path, language, requiresNormalization }) => ({
        path,
        language,
        requiresNormalization,
      })),
    ).toEqual([
      {
        path: "dist/app.bundle.js",
        language: "javascript",
        requiresNormalization: true,
      },
      {
        path: "dist/app.min.js",
        language: "javascript",
        requiresNormalization: true,
      },
      {
        path: "dist/generated.js",
        language: "javascript",
        requiresNormalization: true,
      },
      {
        path: "src/a.js",
        language: "javascript",
        requiresNormalization: false,
      },
      {
        path: "src/a.ts",
        language: "typescript",
        requiresNormalization: false,
      },
    ]);
  });
});

describe("parser-independent JavaScript signatures", () => {
  test("correlates credential access with an outbound sink without retaining literals", () => {
    const source = "const t=process.env.API_TOKEN;fetch(endpoint,{body:t})";
    const result = scanJavascriptSignatures({
      source,
      path: "dist/a.min.js",
      representation: rawRepresentation(source),
    });

    expect(result.findings).toMatchObject([
      {
        rule_id: "javascript.credential-to-network",
        category: "credential-theft",
        path: "dist/a.min.js",
      },
    ]);
    expect(JSON.stringify(result.findings)).not.toContain("API_TOKEN");
    expect(result.evidenceHints[0]).toMatchObject({
      original_path: "dist/a.min.js",
      stage: "raw",
      source,
    });
  });

  test("does not flag an isolated base64 literal or ordinary fetch", () => {
    const source = `const logo="${Buffer.from("ordinary image data").toString("base64")}"; fetch("/status")`;
    expect(
      scanJavascriptSignatures({
        source,
        path: "src/a.js",
        representation: rawRepresentation(source),
      }).findings,
    ).toEqual([]);
  });

  test("correlates a network download with an execution sink", () => {
    const source = "fetch(url).then(r=>r.text()).then(code=>eval(code))";
    expect(
      scanJavascriptSignatures({
        source,
        path: "dist/loader.js",
        representation: rawRepresentation(source),
      }).findings,
    ).toEqual([
      expect.objectContaining({
        rule_id: "javascript.download-to-execution",
        category: "code-execution",
      }),
    ]);
  });
});

describe("non-executing JavaScript literal decoding", () => {
  test.each([
    [
      `atob("${Buffer.from("eval(fetch(endpoint))").toString("base64")}")`,
      "base64",
    ],
    ["String.fromCharCode(101,118,97,108,40,120,41)", "char-code"],
    ["decodeURIComponent('%65%76%61%6c%28%78%29')", "percent"],
    [String.raw`const payload="\x65\x76\x61\x6c\x28\x78\x29"`, "hex"],
    [`const payload="ev" + "al(" + "x)"`, "literal-concat"],
  ] as const)(
    "decodes supported %s literal form without executing it",
    (source, transform) => {
      const outputs = decodeJavascriptLiterals({
        source,
        maxOutputs: 8,
        maxOutputBytes: 4096,
      });
      expect(outputs).toEqual(
        expect.arrayContaining([
          expect.objectContaining({
            transform,
            content: expect.stringMatching(/eval/u),
          }),
        ]),
      );
    },
  );

  test("does not resolve identifiers or retain malformed and noisy output", () => {
    expect(
      decodeJavascriptLiterals({
        source: "atob(payload); atob('%%%'); String.fromCharCode(0,1,2,3,4)",
        maxOutputs: 8,
        maxOutputBytes: 4096,
      }),
    ).toEqual([]);
  });

  test("enforces output count and byte ceilings", () => {
    const source = ["eval(x)", "eval(y)", "eval(z)"]
      .map((value) => `atob("${Buffer.from(value).toString("base64")}")`)
      .join(";");
    const outputs = decodeJavascriptLiterals({
      source,
      maxOutputs: 2,
      maxOutputBytes: 7,
    });
    expect(outputs).toHaveLength(2);
    expect(
      outputs.every(({ content }) => Buffer.byteLength(content) <= 7),
    ).toBe(true);
  });
});
