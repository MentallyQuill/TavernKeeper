import { readFile } from "node:fs/promises";

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

  constructor(private readonly stdout: string) {}

  async run(
    command: string,
    args: string[],
    options: CommandOptions,
  ): Promise<CommandExecutionResult> {
    this.calls.push({ command, args, options });
    return {
      ok: true,
      value: { exitCode: 0, stdout: this.stdout, stderr: "" },
    };
  }
}

function resultJson() {
  return JSON.stringify({
    version: "1.26.0",
    results: [
      {
        check_id:
          "tavernkeeper.credential-exfiltration.javascript-browser-secret-to-fetch",
        path: "src/index.ts",
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
    errors: [],
    paths: { scanned: ["src/index.ts"] },
  });
}

describe("OpenGrep adapter", () => {
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
      "--disable-version-check",
      "--disable-nosem",
      "--no-git-ignore",
      "--x-ignore-semgrepignore-files",
      "--no-rewrite-rule-ids",
      "--exclude=.git",
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
    });
  });
});
