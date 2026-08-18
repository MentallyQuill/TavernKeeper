import { createHash } from "node:crypto";
import { mkdir, mkdtemp, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";

import type { Warning } from "@nodesecure/js-x-ray";
import { describe, expect, test } from "vitest";

import {
  loadScannerPolicy,
  type ScannerPolicyV4,
} from "../src/config/policy.js";
import type { InventoryFile } from "../src/inventory/inventory-handler.js";
import type { CommandRunner } from "../src/process/command-runner.js";
import {
  JAVASCRIPT_ANALYSIS_VERSION,
  runJavascriptAnalysis,
  type JavascriptAnalysisDependencies,
} from "../src/scanners/javascript-analysis.js";
import type { ScannerRun } from "../src/scanners/types.js";

async function policy() {
  const loaded = await loadScannerPolicy(
    resolve("config/scanner-policy.v4.json"),
  );
  if (loaded.version !== "4") throw new Error("Expected scanner policy 4.");
  return loaded;
}

const openGrep: JavascriptAnalysisDependencies["openGrep"] = async ({
  expectedPaths = [],
}): Promise<ScannerRun> => ({
  name: "opengrep",
  version: "test",
  status: "completed",
  findings: [],
  pathCoverage: { scanned: [...expectedPaths], skipped: [] },
});

async function analyzeFixture(
  source: string,
  policyOverride?: ScannerPolicyV4,
  dependencyOverrides: Partial<JavascriptAnalysisDependencies> = {},
) {
  const root = await mkdtemp(join(tmpdir(), "tavernkeeper-js-analysis-"));
  const path = "dist/application.min.js";
  await mkdir(join(root, "dist"), { recursive: true });
  await writeFile(join(root, path), source);
  const file: InventoryFile = {
    path,
    bytes: Buffer.byteLength(source),
    sha256: createHash("sha256").update(source).digest("hex"),
    kind: "text",
    likelyMinified: true,
  };
  return runJavascriptAnalysis(
    {
      root,
      inventoryFiles: [file],
      rawOpenGrepCoverage: { scanned: [path], skipped: [] },
      runner: {} as CommandRunner,
      rulesRoot: resolve("config/opengrep"),
      policy: policyOverride ?? (await policy()),
      temporaryRoot: root,
      opengrepVersion: "test",
    },
    { openGrep, ...dependencyOverrides },
  );
}

function nestedEncoding(depth: number) {
  let source =
    "const credential=process.env.API_TOKEN;fetch(endpoint,{body:credential})";
  for (let index = 0; index < depth; index += 1)
    source = `atob("${Buffer.from(source).toString("base64")}")`;
  return source;
}

describe("integrated JavaScript derivative analysis", () => {
  test("preserves a UTF-8 BOM in raw evidence identity", async () => {
    const source = "\uFEFFeval(payload)";
    const run = await analyzeFixture(source);
    const hint = run.evidenceHints?.find(({ stage }) => stage === "raw");

    expect(hint?.source).toBe(source);
    expect(hint?.representation_sha256).toBe(
      createHash("sha256").update(source).digest("hex"),
    );
  });

  test("finds a signal revealed only after literal decoding", async () => {
    const encoded = Buffer.from(
      "const t=process.env.API_TOKEN;fetch(endpoint,{body:t})",
    ).toString("base64");
    const run = await analyzeFixture(`eval(atob("${encoded}"))`);

    expect(run.name).toBe("javascript-analysis");
    expect(run.version).toBe(JAVASCRIPT_ANALYSIS_VERSION);
    expect(run.findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          rule_id: "javascript.credential-to-network",
        }),
      ]),
    );
    expect(run.javascriptAnalysis?.representations.decoded).toBeGreaterThan(0);
    expect(run.evidenceHints).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          stage: "decoded",
          source: expect.any(String),
        }),
      ]),
    );
  });

  test("marks exhausted recursion incomplete instead of clean", async () => {
    const run = await analyzeFixture(nestedEncoding(4));
    expect(run.javascriptAnalysis).toMatchObject({
      status: "incomplete",
      unresolved: expect.arrayContaining([
        expect.objectContaining({
          stage: "literal-decode",
          reason: "recursion-limit",
          recovered: false,
        }),
      ]),
    });
    expect(run.status).toBe("completed-with-limitations");
  });

  test("maps AST warning locations and never retains warning values", async () => {
    const run = await analyzeFixture("eval(payload)");
    const finding = run.findings.find(({ rule_id }) =>
      rule_id.startsWith("javascript.xray."),
    );
    expect(finding).toMatchObject({
      origin: "javascript-analysis",
      path: "dist/application.min.js",
      line_start: 1,
    });
    expect(JSON.stringify(finding)).not.toContain("payload");
  });

  test("reviews repeated X-ray warnings as one evidence-preserving family", async () => {
    const source = Array.from({ length: 100 }, (_, index) =>
      index === 4
        ? "const first = JSON.stringify(process.env);"
        : index === 89
          ? "const second = JSON.stringify(process.env);"
          : `const line${index + 1} = ${index + 1};`,
    ).join("\n");
    const warnings: Warning[] = [
      {
        kind: "serialize-environment",
        value: "first-secret-shaped-value",
        source: "first",
        location: [
          [
            [5, 14],
            [5, 41],
          ],
        ],
        i18n: "test",
        severity: "Warning",
      },
      {
        kind: "serialize-environment",
        value: "second-secret-shaped-value",
        source: "second",
        location: [
          [
            [90, 15],
            [90, 42],
          ],
        ],
        i18n: "test",
        severity: "Warning",
      },
    ];
    const run = await analyzeFixture(source, undefined, {
      analyzeAst: () => ({ warnings }),
      normalize: async () => ({ derivatives: [] }),
    });

    const findings = run.findings.filter(
      ({ rule_id }) => rule_id === "javascript.xray.serialize-environment",
    );
    expect(findings).toHaveLength(1);
    expect(findings[0]?.explanation).toContain("2 occurrences");
    expect(JSON.stringify(findings)).not.toContain("secret-shaped-value");
    expect(
      run.evidenceHints
        ?.filter(
          ({ finding_fingerprint }) =>
            finding_fingerprint === findings[0]?.fingerprint,
        )
        .map(({ line_start }) => line_start),
    ).toEqual([5, 90]);
    expect(run.javascriptAnalysis).toMatchObject({
      warning_occurrences: 2,
      warning_families: 1,
    });
  });

  test("sends every derived representation to OpenGrep even without a finding", async () => {
    const expectedManifests: string[][] = [];
    const run = await analyzeFixture("const ordinary=1", undefined, {
      normalize: async (source) => ({
        derivatives: [
          {
            id: "normalized",
            content: source.endsWith(";") ? source : `${source};`,
            transform: "webcrack-normalized",
          },
        ],
      }),
      openGrep: async ({ expectedPaths = [] }) => {
        expectedManifests.push([...expectedPaths]);
        return {
          name: "opengrep",
          version: "test",
          status: "completed",
          findings: [],
          pathCoverage: { scanned: [...expectedPaths], skipped: [] },
        };
      },
    });

    expect(expectedManifests).toEqual([["derived/000000.js"]]);
    expect(run.javascriptAnalysis?.stages.derived_opengrep).toBe(1);
  });

  test("does not treat decoded display text or repeated normalization as a coverage gap", async () => {
    const normalizationInputs: string[] = [];
    const source = String.raw`const label="\uD83D\uDC41\uFE0F Manually run continuity state extraction";`;
    const run = await analyzeFixture(source, undefined, {
      normalize: async (input) => {
        normalizationInputs.push(input);
        return {
          derivatives: [
            {
              id: "normalized",
              content: `${input}\n`,
              transform: "webcrack-normalized",
            },
          ],
        };
      },
    });

    expect(normalizationInputs).toEqual([source]);
    expect(run.javascriptAnalysis).toMatchObject({
      status: "complete",
      unresolved: [],
      representations: { raw: 1, decoded: 1, normalized: 1 },
    });
  });

  test.each([
    String.raw`const label="\x52un now (recommended)!";`,
    String.raw`const label="\x53tatus: [ready];";`,
    String.raw`const label="\x43ontinue if safe";`,
    String.raw`const smartQuoted = parseStructuredJsonText('\uFEFF{\u201cschema\u201d:\u201crecursion.providerTest.v1\u201d,\u201cok\u201d:true}');`,
  ])("does not parse decoded display or data text", async (source) => {
    const astInputs: string[] = [];
    const run = await analyzeFixture(source, undefined, {
      analyzeAst: (input) => {
        astInputs.push(input);
        return { warnings: [] };
      },
      normalize: async () => ({ derivatives: [] }),
    });

    expect(astInputs).toEqual([source]);
    expect(run.javascriptAnalysis).toMatchObject({
      status: "complete",
      unresolved: [],
      representations: { raw: 1, decoded: 1, normalized: 0 },
    });
  });

  test("parses and normalizes decoded computed-member execution chains", async () => {
    const decoded = String.raw`[]["filter"]["constructor"]("return 1")()`;
    const source = `atob("${Buffer.from(decoded).toString("base64")}")`;
    const astInputs: string[] = [];
    const normalizationInputs: string[] = [];
    const run = await analyzeFixture(source, undefined, {
      analyzeAst: (input) => {
        astInputs.push(input);
        return { warnings: [] };
      },
      normalize: async (input) => {
        normalizationInputs.push(input);
        return { derivatives: [] };
      },
    });

    expect(astInputs).toEqual(expect.arrayContaining([source, decoded]));
    expect(normalizationInputs).toEqual(
      expect.arrayContaining([source, decoded]),
    );
    expect(run.javascriptAnalysis).toMatchObject({
      status: "complete",
      unresolved: [],
      representations: { raw: 1, decoded: 1, normalized: 0 },
    });
  });

  test("fails closed when inventory content changes after hashing", async () => {
    const root = await mkdtemp(join(tmpdir(), "tavernkeeper-js-digest-"));
    await writeFile(join(root, "app.js"), "const changed=true");
    await expect(
      runJavascriptAnalysis(
        {
          root,
          inventoryFiles: [
            {
              path: "app.js",
              bytes: 1,
              sha256: "0".repeat(64),
              kind: "text",
            },
          ],
          rawOpenGrepCoverage: { scanned: ["app.js"], skipped: [] },
          runner: {} as CommandRunner,
          rulesRoot: resolve("config/opengrep"),
          policy: await policy(),
          temporaryRoot: root,
          opengrepVersion: "test",
        },
        { openGrep },
      ),
    ).rejects.toMatchObject({ code: "SCANNER_FAILED", scope: "system" });
  });
});
