import { readFile } from "node:fs/promises";
import { dirname, join, resolve } from "node:path";

import { parse } from "yaml";
import { describe, expect, test } from "vitest";

import { FindingSchema } from "../src/contracts/reports.js";
import { runOpenGrep } from "../src/scanners/opengrep.js";
import type {
  CommandExecutionResult,
  CommandOptions,
  CommandRunner,
} from "../src/process/command-runner.js";

const seedSecret = "ghp_abcdefghijklmnopqrstuvwxyz1234567890";

class OpenGrepRunner implements CommandRunner {
  calls: Array<{ command: string; args: string[]; options: CommandOptions }> =
    [];

  constructor(
    private readonly stdout: string,
    private readonly exitCode = 0,
    private readonly stderr = "",
  ) {}

  async run(
    command: string,
    args: string[],
    options: CommandOptions,
  ): Promise<CommandExecutionResult> {
    this.calls.push({ command, args, options });
    return {
      ok: true,
      value: {
        exitCode: this.exitCode,
        stdout: this.stdout,
        stderr: this.stderr,
      },
    };
  }
}

function resultJson(path = "src/index.ts", errors: unknown[] = []) {
  return JSON.stringify({
    version: "1.26.0",
    results: [
      {
        check_id:
          "tavernkeeper.credential-exfiltration.javascript-browser-secret-to-fetch",
        path,
        start: { line: 3, col: 1, offset: 20 },
        end: { line: 5, col: 2, offset: 90 },
        extra: {
          message: `Secret ${seedSecret} sent to the network`,
          lines: `fetch(${seedSecret})`,
          metavars: { $TOKEN: { abstract_content: seedSecret } },
          severity: "ERROR",
          metadata: {
            tavernkeeper_category: "credential-theft",
            tavernkeeper_severity: "high",
            tavernkeeper_confidence: "high",
            tavernkeeper_title: "Credential source reaches network sink",
          },
        },
      },
    ],
    errors,
    paths: { scanned: ["src/index.ts"] },
  });
}

describe("OpenGrep adapter", () => {
  test("startup persistence rule distinguishes startup paths from object properties", async () => {
    const document = parse(
      await readFile(
        new URL(
          "../rules/opengrep/install-and-persistence.yml",
          import.meta.url,
        ),
        "utf8",
      ),
    ) as { rules: Array<Record<string, unknown>> };
    const rule = document.rules.find((candidate) =>
      String(candidate.id).includes("persistence.startup-modification"),
    );
    const expression = new RegExp(
      String(rule?.["pattern-regex"]).replace(/^\(\?i\)/u, ""),
      "iu",
    );

    expect(expression.test("const id = profile.profileId;")).toBe(false);
    expect(expression.test('writeFile("~/.profile", contents);')).toBe(true);
  });

  test("node execution rule restricts method calls to recognized process APIs", async () => {
    const document = parse(
      await readFile(
        new URL("../rules/opengrep/dynamic-execution.yml", import.meta.url),
        "utf8",
      ),
    ) as { rules: Array<Record<string, unknown>> };
    const rule = document.rules.find((candidate) =>
      String(candidate.id).includes("dynamic-execution.node-shell"),
    );
    const serialized = JSON.stringify(rule);

    expect(serialized).toContain("metavariable-regex");
    expect(serialized).toMatch(/child_process|childProcess/iu);
  });

  test("ships TavernKeeper-owned rules for every approved V1 signal family", async () => {
    const files = [
      "credential-exfiltration.yml",
      "dynamic-execution.yml",
      "install-and-persistence.yml",
      "obfuscation.yml",
    ];
    const documents = await Promise.all(
      files.map(async (file) =>
        parse(
          await readFile(
            new URL(`../rules/opengrep/${file}`, import.meta.url),
            "utf8",
          ),
        ),
      ),
    );
    const rules = documents.flatMap(
      (document) => document.rules as Array<Record<string, unknown>>,
    );
    const ids = rules.map((rule) => String(rule.id));

    expect(ids).toEqual(
      expect.arrayContaining([
        expect.stringContaining("credential-exfiltration"),
        expect.stringContaining("dynamic-execution"),
        expect.stringContaining("download-and-execute"),
        expect.stringContaining("persistence"),
        expect.stringContaining("encoded-payload"),
        expect.stringContaining("reconnaissance-transmission"),
      ]),
    );
    expect(
      rules.every((rule) => {
        const metadata = rule.metadata as Record<string, unknown> | undefined;
        return (
          typeof rule.id === "string" &&
          typeof rule.message === "string" &&
          typeof rule.severity === "string" &&
          typeof metadata?.tavernkeeper_category === "string" &&
          typeof metadata?.tavernkeeper_severity === "string" &&
          typeof metadata?.tavernkeeper_confidence === "string" &&
          typeof metadata?.tavernkeeper_title === "string"
        );
      }),
    ).toBe(true);
  });

  test("uses only trusted rules and normalizes findings without source excerpts", async () => {
    const runner = new OpenGrepRunner(resultJson());
    const run = await runOpenGrep({
      root: "C:/scan/repository",
      rulesRoot: "C:/trusted/TavernKeeper/rules/opengrep",
      runner,
      executable: "C:/trusted/opengrep",
      version: "1.26.0",
    });

    expect(runner.calls).toHaveLength(1);
    expect(runner.calls[0]).toMatchObject({
      command: "C:/trusted/opengrep",
      options: {
        cwd: "C:/scan/repository",
        shell: false,
      },
    });
    expect(runner.calls[0]?.args).toEqual([
      "scan",
      "--json",
      "--verbose",
      "--disable-version-check",
      "--disable-nosem",
      "--no-git-ignore",
      "--x-ignore-semgrepignore-files",
      "--no-rewrite-rule-ids",
      "--exclude=.git",
      "--no-exclude-minified-files",
      "--max-target-bytes=268435456",
      "--config",
      "C:/trusted/TavernKeeper/rules/opengrep",
      "C:/scan/repository",
    ]);
    expect(runner.calls[0]?.args).not.toContain("auto");
    expect(run).toMatchObject({
      name: "opengrep",
      version: "1.26.0",
      status: "completed",
      findings: [
        expect.objectContaining({
          origin: "opengrep",
          rule_id:
            "tavernkeeper.credential-exfiltration.javascript-browser-secret-to-fetch",
          category: "credential-theft",
          severity: "high",
          confidence: "high",
          path: "src/index.ts",
          line_start: 3,
          line_end: 5,
        }),
      ],
    });
    expect(
      run.findings.every((finding) => FindingSchema.safeParse(finding).success),
    ).toBe(true);
    expect(JSON.stringify(run.findings)).not.toContain(seedSecret);
  });

  test("extracts one bounded JSON report from trusted scanner console noise", async () => {
    const runner = new OpenGrepRunner(
      [
        "OpenGrep emitted a progress message instead of JSON.",
        resultJson(),
        "OpenGrep finished.",
      ].join("\n"),
    );

    await expect(
      runOpenGrep({
        root: "C:/scan/repository",
        rulesRoot: "C:/trusted/TavernKeeper/rules/opengrep",
        runner,
        version: "1.26.0",
      }),
    ).resolves.toMatchObject({
      name: "opengrep",
      findings: [expect.objectContaining({ category: "credential-theft" })],
    });
  });

  test("rejects ambiguous console output containing multiple scanner reports", async () => {
    const runner = new OpenGrepRunner([resultJson(), resultJson()].join("\n"));

    await expect(
      runOpenGrep({
        root: "C:/scan/repository",
        rulesRoot: "C:/trusted/TavernKeeper/rules/opengrep",
        runner,
        version: "1.26.0",
      }),
    ).rejects.toMatchObject({
      code: "MALFORMED_SCANNER_OUTPUT",
      message: expect.stringContaining(
        "OpenGrep returned multiple JSON reports.",
      ),
    });
  });

  test("reports only process shape when OpenGrep returns no JSON", async () => {
    const runner = new OpenGrepRunner(
      "",
      2,
      "opengrep: unknown option '--no-exclude-minified-files'",
    );

    await expect(
      runOpenGrep({
        root: "C:/scan/repository",
        rulesRoot: "C:/trusted/TavernKeeper/rules/opengrep",
        runner,
        version: "1.26.0",
      }),
    ).rejects.toMatchObject({
      code: "MALFORMED_SCANNER_OUTPUT",
      message: expect.stringContaining(
        "stderr class option-error; option mentions --no-exclude-minified-files",
      ),
    });
  });

  test.each([
    {
      name: "other syntax error",
      diagnostic: {
        code: 2,
        level: "warn",
        type: "Other syntax error",
        message: "Unexpected token Memprof",
        path: "public/lib/epub.min.js",
      },
    },
    {
      name: "partial parsing",
      diagnostic: {
        code: 3,
        level: "warn",
        type: ["PartialParsing", [{ line: 1, column: 1 }]],
        message: "Partially parsed bundled JavaScript",
        path: "public/lib/pdf.min.mjs",
      },
    },
  ])(
    "preserves findings with the approved $name warning",
    async ({ diagnostic }) => {
      const runner = new OpenGrepRunner(
        resultJson("src/index.ts", [diagnostic]),
      );

      const run = await runOpenGrep({
        root: "C:/scan/repository",
        rulesRoot: "C:/trusted/TavernKeeper/rules/opengrep",
        runner,
        version: "1.26.0",
      });

      expect(run.status).toBe("completed");
      expect(run.findings).toHaveLength(1);
      expect(run.findings[0]?.path).toBe("src/index.ts");
    },
  );

  test.each([
    {
      name: "unknown warning code",
      diagnostic: { code: 4, level: "warn", type: "Other syntax error" },
    },
    {
      name: "recognized diagnostic at error level",
      diagnostic: { code: 2, level: "error", type: "Other syntax error" },
    },
    {
      name: "malformed partial-parsing type",
      diagnostic: { code: 3, level: "warn", type: "PartialParsing" },
    },
    {
      name: "missing diagnostic level",
      diagnostic: { code: 3, type: ["PartialParsing", []] },
    },
  ])("rejects a $name diagnostic", async ({ diagnostic }) => {
    const runner = new OpenGrepRunner(resultJson("src/index.ts", [diagnostic]));

    await expect(
      runOpenGrep({
        root: "C:/scan/repository",
        rulesRoot: "C:/trusted/TavernKeeper/rules/opengrep",
        runner,
        version: "1.26.0",
      }),
    ).rejects.toMatchObject({
      code: "SCANNER_FAILED",
      scope: "system",
      component: "opengrep",
    });
  });

  test("preserves findings with a bounded syntax coverage limitation", async () => {
    const runner = new OpenGrepRunner(
      resultJson("src/index.ts", [
        {
          code: 3,
          level: "warn",
          type: "Syntax error",
          path: "private/source.ts",
        },
      ]),
    );

    await expect(
      runOpenGrep({
        root: "C:/scan/repository",
        rulesRoot: "C:/trusted/TavernKeeper/rules/opengrep",
        runner,
        version: "1.26.0",
      }),
    ).resolves.toMatchObject({
      status: "completed-with-limitations",
      limitations: ["parser_syntax"],
      findings: [expect.objectContaining({ path: "src/index.ts" })],
    });
  });

  test("preserves findings with a bounded rule-timeout limitation", async () => {
    const runner = new OpenGrepRunner(
      resultJson("src/index.ts", [{ code: 2, level: "warn", type: "Timeout" }]),
    );

    await expect(
      runOpenGrep({
        root: "C:/scan/repository",
        rulesRoot: "C:/trusted/TavernKeeper/rules/opengrep",
        runner,
        version: "1.26.0",
      }),
    ).resolves.toMatchObject({
      status: "completed-with-limitations",
      limitations: ["rule_timeout"],
      findings: [expect.objectContaining({ path: "src/index.ts" })],
    });
  });

  test("reports each bounded limitation once when syntax and timeout both occur", async () => {
    const runner = new OpenGrepRunner(
      resultJson("src/index.ts", [
        { code: 2, level: "warn", type: "Timeout" },
        { code: 3, level: "warn", type: "Syntax error" },
      ]),
    );

    await expect(
      runOpenGrep({
        root: "C:/scan/repository",
        rulesRoot: "C:/trusted/TavernKeeper/rules/opengrep",
        runner,
        version: "1.26.0",
      }),
    ).resolves.toMatchObject({
      status: "completed-with-limitations",
      limitations: ["parser_syntax", "rule_timeout"],
    });
  });

  test.each([
    { code: 2, level: "warn", type: "Syntax error" },
    { code: 3, level: "error", type: "Syntax error" },
    { code: 3, level: "warn", type: "Timeout" },
    { code: 2, level: "error", type: "Timeout" },
  ])(
    "rejects a near-match partial coverage diagnostic %#",
    async (diagnostic) => {
      const runner = new OpenGrepRunner(
        resultJson("src/index.ts", [diagnostic]),
      );

      await expect(
        runOpenGrep({
          root: "C:/scan/repository",
          rulesRoot: "C:/trusted/TavernKeeper/rules/opengrep",
          runner,
          version: "1.26.0",
        }),
      ).rejects.toMatchObject({ code: "SCANNER_FAILED" });
    },
  );

  test.each([
    {
      exitCode: 2,
      diagnostic: { code: 2, level: "warn", type: "Other syntax error" },
    },
    {
      exitCode: 3,
      diagnostic: {
        code: 3,
        level: "warn",
        type: ["PartialParsing", [{ line: 1, column: 1 }]],
      },
    },
  ])(
    "preserves findings when approved parser warnings produce exit $exitCode",
    async ({ exitCode, diagnostic }) => {
      const runner = new OpenGrepRunner(
        resultJson("src/index.ts", [diagnostic]),
        exitCode,
      );

      const run = await runOpenGrep({
        root: "C:/scan/repository",
        rulesRoot: "C:/trusted/TavernKeeper/rules/opengrep",
        runner,
        version: "1.26.0",
      });

      expect(run.status).toBe("completed");
      expect(run.findings).toHaveLength(1);
    },
  );

  test.each([1, 4, 137])(
    "rejects unexpected scanner exit %s even when JSON contains only approved warnings",
    async (exitCode) => {
      const runner = new OpenGrepRunner(
        resultJson("src/index.ts", [
          { code: 2, level: "warn", type: "Other syntax error" },
        ]),
        exitCode,
      );

      await expect(
        runOpenGrep({
          root: "C:/scan/repository",
          rulesRoot: "C:/trusted/TavernKeeper/rules/opengrep",
          runner,
          version: "1.26.0",
        }),
      ).rejects.toMatchObject({
        code: "SCANNER_FAILED",
        scope: "system",
        component: "opengrep",
      });
    },
  );

  test.each([2, 3])(
    "rejects approved exit %s without a matching parser warning",
    async (exitCode) => {
      const runner = new OpenGrepRunner(resultJson("src/index.ts"), exitCode);

      await expect(
        runOpenGrep({
          root: "C:/scan/repository",
          rulesRoot: "C:/trusted/TavernKeeper/rules/opengrep",
          runner,
          version: "1.26.0",
        }),
      ).rejects.toMatchObject({
        code: "SCANNER_FAILED",
        scope: "system",
        component: "opengrep",
      });
    },
  );

  test("rejects malformed scanner output", async () => {
    const runner = new OpenGrepRunner(
      JSON.stringify({ results: "not-an-array" }),
    );

    await expect(
      runOpenGrep({
        root: "C:/scan/repository",
        rulesRoot: "C:/trusted/TavernKeeper/rules/opengrep",
        runner,
        version: "1.26.0",
      }),
    ).rejects.toMatchObject({
      code: "MALFORMED_SCANNER_OUTPUT",
      scope: "system",
      message: expect.stringContaining("report schema mismatch at results"),
    });
  });

  test("normalizes an absolute scanner path beneath the repository root", async () => {
    const root = resolve("fixture", "repository");
    const runner = new OpenGrepRunner(
      resultJson(join(root, "src", "index.ts")),
    );

    const run = await runOpenGrep({
      root,
      rulesRoot: resolve("rules", "opengrep"),
      runner,
      version: "1.26.0",
    });

    expect(run.findings[0]?.path).toBe("src/index.ts");
  });

  test("accounts for each expected minified path exactly once", async () => {
    const report = JSON.parse(resultJson()) as Record<string, unknown>;
    report.results = [];
    report.paths = {
      scanned: ["dist/app.min.js", "dist/large.js", "src/harmless.txt"],
      skipped: [{ path: "dist/large.js", reason: "Too_big" }],
    };
    const run = await runOpenGrep({
      root: "C:/scan/repository",
      rulesRoot: "C:/trusted/TavernKeeper/rules/opengrep",
      runner: new OpenGrepRunner(JSON.stringify(report)),
      version: "1.26.0",
      expectedPaths: ["dist/app.min.js", "dist/large.js"],
    });

    expect(run.pathCoverage).toEqual({
      scanned: ["dist/app.min.js"],
      skipped: [{ path: "dist/large.js", reason: "target-limit" }],
    });
  });

  test.each([
    {
      name: "missing",
      paths: { scanned: [], skipped: [] },
      message: "did not account for expected paths",
    },
    {
      name: "duplicate",
      paths: { scanned: ["dist/app.js", "dist/app.js"], skipped: [] },
      message: "path coverage contains duplicates",
    },
  ])("rejects $name expected-path accounting", async ({ paths, message }) => {
    const report = JSON.parse(resultJson()) as Record<string, unknown>;
    report.results = [];
    report.paths = paths;
    await expect(
      runOpenGrep({
        root: "C:/scan/repository",
        rulesRoot: "C:/trusted/TavernKeeper/rules/opengrep",
        runner: new OpenGrepRunner(JSON.stringify(report)),
        version: "1.26.0",
        expectedPaths: ["dist/app.js"],
      }),
    ).rejects.toMatchObject({
      code: "MALFORMED_SCANNER_OUTPUT",
      message: expect.stringContaining(message),
    });
  });

  test("filters non-JavaScript repository paths from expected path coverage", async () => {
    const report = JSON.parse(resultJson()) as Record<string, unknown>;
    report.results = [];
    report.paths = {
      scanned: ["dist/app.js", "src/harmless.txt"],
      skipped: [],
    };

    const run = await runOpenGrep({
      root: "C:/scan/repository",
      rulesRoot: "C:/trusted/TavernKeeper/rules/opengrep",
      runner: new OpenGrepRunner(JSON.stringify(report)),
      version: "1.26.0",
      expectedPaths: ["dist/app.js"],
    });

    expect(run.pathCoverage).toEqual({
      scanned: ["dist/app.js"],
      skipped: [],
    });
  });

  test("rejects an unknown skipped-target reason", async () => {
    const report = JSON.parse(resultJson()) as Record<string, unknown>;
    report.results = [];
    report.paths = {
      scanned: [],
      skipped: [{ path: "dist/app.js", reason: "mystery" }],
    };
    await expect(
      runOpenGrep({
        root: "C:/scan/repository",
        rulesRoot: "C:/trusted/TavernKeeper/rules/opengrep",
        runner: new OpenGrepRunner(JSON.stringify(report)),
        version: "1.26.0",
        expectedPaths: ["dist/app.js"],
      }),
    ).rejects.toMatchObject({ code: "MALFORMED_SCANNER_OUTPUT" });
  });

  test("accounts for binary JavaScript as an unsupported target", async () => {
    const report = JSON.parse(resultJson()) as Record<string, unknown>;
    report.results = [];
    report.paths = {
      scanned: [],
      skipped: [{ path: "vendor/opaque.js", reason: "binary file" }],
    };
    const run = await runOpenGrep({
      root: "C:/scan/repository",
      rulesRoot: "C:/trusted/TavernKeeper/rules/opengrep",
      runner: new OpenGrepRunner(JSON.stringify(report)),
      version: "1.26.0",
      expectedPaths: ["vendor/opaque.js"],
    });

    expect(run.pathCoverage).toEqual({
      scanned: [],
      skipped: [{ path: "vendor/opaque.js", reason: "unsupported" }],
    });
  });

  test("rejects an absolute scanner path outside the repository root", async () => {
    const root = resolve("fixture", "repository");
    const runner = new OpenGrepRunner(
      resultJson(join(dirname(root), "outside.ts")),
    );

    await expect(
      runOpenGrep({
        root,
        rulesRoot: resolve("rules", "opengrep"),
        runner,
        version: "1.26.0",
      }),
    ).rejects.toMatchObject({
      code: "MALFORMED_SCANNER_OUTPUT",
      component: "opengrep",
    });
  });
});
