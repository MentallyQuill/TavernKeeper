import { describe, expect, test } from "vitest";

import { FindingSchema } from "../src/contracts/reports.js";
import { runExternalTools } from "../src/scanners/external-tools.js";
import type {
  CommandExecutionResult,
  CommandOptions,
  CommandRunner,
} from "../src/process/command-runner.js";

class MixedRunner implements CommandRunner {
  calls: Array<{ command: string; args: string[] }> = [];

  async run(
    command: string,
    args: string[],
    _options: CommandOptions,
  ): Promise<CommandExecutionResult> {
    this.calls.push({ command, args });
    if (command === "opengrep") {
      return {
        ok: false,
        error: {
          code: "SPAWN_FAILED",
          message: "Command could not be started.",
        },
      };
    }
    if (command === "gitleaks") {
      return {
        ok: true,
        value: {
          exitCode: 1,
          stdout: JSON.stringify([
            {
              RuleID: "generic-api-key",
              Description: "Generic API key",
              File: "src/index.ts",
              StartLine: 4,
            },
          ]),
          stderr: "",
        },
      };
    }
    return {
      ok: true,
      value: { exitCode: 0, stdout: "[]", stderr: "" },
    };
  }
}

describe("external scanner adapters", () => {
  test("uses argument arrays and reports missing tools as unavailable", async () => {
    const runner = new MixedRunner();
    const runs = await runExternalTools({ root: "C:/scan/repository", runner });

    expect(runs.find(({ name }) => name === "opengrep")).toEqual({
      name: "opengrep",
      status: "unavailable",
      version: null,
      detail: "Executable not found.",
      findings: [],
    });
    expect(runner.calls).toContainEqual({
      command: "gitleaks",
      args: expect.arrayContaining([
        "dir",
        "--no-banner",
        "--redact=100",
        "C:/scan/repository",
      ]),
    });
    expect(runner.calls).toContainEqual({
      command: "osv-scanner",
      args: ["scan", "source", "--format", "json", "-r", "C:/scan/repository"],
    });
    expect(runner.calls).toContainEqual({
      command: "zizmor",
      args: ["--format=json-v1", "--no-progress", "C:/scan/repository"],
    });
    const findings = runs.flatMap((run) => run.findings);
    expect(findings).toHaveLength(1);
    expect(
      findings.every((finding) => FindingSchema.safeParse(finding).success),
    ).toBe(true);
  });
});
