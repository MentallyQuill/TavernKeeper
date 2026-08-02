import { mkdtemp, readFile, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, test } from "vitest";

import { FindingSchema } from "../src/contracts/reports.js";
import { runGitleaks } from "../src/scanners/gitleaks.js";
import type {
  CommandExecutionResult,
  CommandOptions,
  CommandRunner,
} from "../src/process/command-runner.js";

const fullSha = "a".repeat(40);
const seedSecret = "ghp_abcdefghijklmnopqrstuvwxyz1234567890";

class GitleaksRunner implements CommandRunner {
  calls: Array<{ command: string; args: string[]; options: CommandOptions }> =
    [];
  reportsAfterRun: string[] = [];

  constructor(private readonly file = "src/index.ts") {}

  async run(
    command: string,
    args: string[],
    options: CommandOptions,
  ): Promise<CommandExecutionResult> {
    this.calls.push({ command, args, options });
    const reportPath = args[args.indexOf("--report-path") + 1];
    if (!reportPath) throw new Error("missing report path");
    await writeFile(
      reportPath,
      JSON.stringify([
        {
          RuleID: "generic-api-key",
          Description: `Found ${seedSecret}`,
          File: this.file,
          StartLine: 4,
          EndLine: 4,
          Commit: args[0] === "git" ? fullSha : "",
          Secret: seedSecret,
          Match: `token=${seedSecret}`,
        },
      ]),
    );
    this.reportsAfterRun.push(reportPath);
    return {
      ok: true,
      value: { exitCode: 1, stdout: seedSecret, stderr: seedSecret },
    };
  }
}

describe("Gitleaks adapter", () => {
  test("scans the current tree and bounded history without retaining secret material", async () => {
    const runner = new GitleaksRunner();
    const temporaryRoot = await mkdtemp(
      join(tmpdir(), "tavernkeeper-gitleaks-test-"),
    );

    const run = await runGitleaks({
      root: "C:/scan/repository",
      history: { baseSha: "b".repeat(40), targetSha: fullSha, commits: 20 },
      runner,
      executable: "C:/trusted/gitleaks",
      version: "8.30.1",
      temporaryRoot,
    });

    expect(runner.calls.map(({ args }) => args[0])).toEqual(["dir", "git"]);
    expect(runner.calls[1]?.args).toContain(
      `--log-opts=--no-merges ${"b".repeat(40)}..${fullSha}`,
    );
    expect(
      runner.calls.every(
        ({ args, options }) =>
          args.includes("--redact=100") &&
          args.includes("--report-format=json") &&
          args.includes("--ignore-gitleaks-allow") &&
          args.includes("--gitleaks-ignore-path") &&
          args[args.indexOf("--gitleaks-ignore-path") + 1] !==
            "C:/scan/repository" &&
          options.shell === false &&
          options.environment.GITLEAKS_CONFIG_TOML?.includes(
            "useDefault = true",
          ) === true &&
          options.environment.GIT_TERMINAL_PROMPT === "0",
      ),
    ).toBe(true);
    expect(run).toMatchObject({
      name: "gitleaks",
      version: "8.30.1",
      status: "completed",
    });
    expect(run.findings).toHaveLength(2);
    expect(run.findings[0]).toMatchObject({
      origin: "gitleaks",
      confidence: "high",
      category: "credential-exposure",
    });
    expect(
      run.findings.every((finding) => FindingSchema.safeParse(finding).success),
    ).toBe(true);
    expect(JSON.stringify(run.findings)).not.toContain(seedSecret);
    for (const reportPath of runner.reportsAfterRun) {
      await expect(readFile(reportPath, "utf8")).rejects.toMatchObject({
        code: "ENOENT",
      });
    }
  });

  test("uses the newest commit ceiling when there is no prior scanned ancestor", async () => {
    const runner = new GitleaksRunner();
    const temporaryRoot = await mkdtemp(
      join(tmpdir(), "tavernkeeper-gitleaks-test-"),
    );

    await runGitleaks({
      root: "C:/scan/repository",
      history: { baseSha: null, targetSha: fullSha, commits: 7 },
      runner,
      executable: "C:/trusted/gitleaks",
      version: "8.30.1",
      temporaryRoot,
    });

    expect(runner.calls[1]?.args).toContain(
      `--log-opts=--no-merges -n 7 ${fullSha}`,
    );
  });

  test("normalizes absolute findings beneath the trusted checkout root", async () => {
    const runner = new GitleaksRunner("C:/scan/repository/src/nested/index.ts");
    const temporaryRoot = await mkdtemp(
      join(tmpdir(), "tavernkeeper-gitleaks-test-"),
    );

    const run = await runGitleaks({
      root: "C:/scan/repository",
      history: { baseSha: null, targetSha: fullSha, commits: 7 },
      runner,
      executable: "C:/trusted/gitleaks",
      version: "8.30.1",
      temporaryRoot,
    });

    expect(run.findings.map(({ path }) => path)).toEqual([
      "src/nested/index.ts",
      "src/nested/index.ts",
    ]);
  });
});
