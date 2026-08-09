import { describe, expect, test } from "vitest";

import { planHistory } from "../src/git/history.js";
import type {
  CommandExecutionResult,
  CommandOptions,
  CommandRunner,
} from "../src/process/command-runner.js";

const newestPrevious = "c".repeat(40);
const ancestorPrevious = "b".repeat(40);

class HistoryRunner implements CommandRunner {
  calls: Array<{ command: string; args: string[]; options: CommandOptions }> =
    [];

  async run(
    command: string,
    args: string[],
    options: CommandOptions,
  ): Promise<CommandExecutionResult> {
    this.calls.push({ command, args, options });
    if (args.includes("merge-base")) {
      return {
        ok: true,
        value: {
          exitCode: args.includes(ancestorPrevious) ? 0 : 1,
          stdout: "",
          stderr: "",
        },
      };
    }
    if (args.includes("diff")) {
      return {
        ok: true,
        value: {
          exitCode: 0,
          stdout: "src/a file.ts\0--leading;$(still-data).js\0",
          stderr: "",
        },
      };
    }
    return {
      ok: true,
      value: { exitCode: 0, stdout: "3\n", stderr: "" },
    };
  }
}

describe("bounded history planning", () => {
  test("selects the newest reported ancestor and preserves NUL-delimited paths", async () => {
    const runner = new HistoryRunner();

    const result = await planHistory(
      "C:/repository with spaces",
      [newestPrevious, ancestorPrevious],
      runner,
    );

    expect(result).toEqual({
      ok: true,
      value: {
        baseSha: ancestorPrevious,
        historyCommits: 3,
        changedPaths: ["--leading;$(still-data).js", "src/a file.ts"],
      },
    });
    expect(runner.calls.every((call) => call.options.shell === false)).toBe(
      true,
    );
    expect(runner.calls).toContainEqual(
      expect.objectContaining({
        command: "git",
        args: ["diff", "--name-only", "-z", `${ancestorPrevious}..HEAD`, "--"],
      }),
    );
  });

  test("falls back to paths changed across the newest twenty commits", async () => {
    const runner: CommandRunner = {
      async run(_command, args) {
        if (args.includes("merge-base")) {
          return {
            ok: true,
            value: { exitCode: 1, stdout: "", stderr: "" },
          };
        }
        if (args.includes("log")) {
          return {
            ok: true,
            value: {
              exitCode: 0,
              stdout: "src/new.ts\0README.md\0src/new.ts\0",
              stderr: "",
            },
          };
        }
        return {
          ok: true,
          value: { exitCode: 0, stdout: "20\n", stderr: "" },
        };
      },
    };

    const result = await planHistory("C:/repository", [newestPrevious], runner);

    expect(result).toEqual({
      ok: true,
      value: {
        baseSha: null,
        historyCommits: 20,
        changedPaths: ["README.md", "src/new.ts"],
      },
    });
  });

  test("falls back when a previous report commit is absent from the shallow clone", async () => {
    const calls: string[][] = [];
    const runner: CommandRunner = {
      async run(_command, args) {
        calls.push(args);
        if (args[0] === "rev-parse")
          return {
            ok: true,
            value: { exitCode: 1, stdout: "", stderr: "" },
          };
        if (args.includes("merge-base"))
          throw new Error(
            "An absent optional commit must not reach merge-base.",
          );
        if (args.includes("log"))
          return {
            ok: true,
            value: { exitCode: 0, stdout: "src/current.ts\0", stderr: "" },
          };
        return {
          ok: true,
          value: { exitCode: 0, stdout: "20\n", stderr: "" },
        };
      },
    };

    const result = await planHistory("C:/repository", [newestPrevious], runner);

    expect(result).toEqual({
      ok: true,
      value: {
        baseSha: null,
        historyCommits: 20,
        changedPaths: ["src/current.ts"],
      },
    });
    expect(calls).toContainEqual([
      "rev-parse",
      "--verify",
      "--quiet",
      `${newestPrevious}^{commit}`,
    ]);
  });

  test("uses current bounded history when the newest report already targets HEAD", async () => {
    const runner: CommandRunner = {
      async run(_command, args) {
        if (args.includes("merge-base"))
          return {
            ok: true,
            value: { exitCode: 0, stdout: "", stderr: "" },
          };
        if (args.includes("diff"))
          return {
            ok: true,
            value: { exitCode: 0, stdout: "", stderr: "" },
          };
        if (args.includes(`${newestPrevious}..HEAD`))
          return {
            ok: true,
            value: { exitCode: 0, stdout: "0\n", stderr: "" },
          };
        if (args.includes("log"))
          return {
            ok: true,
            value: { exitCode: 0, stdout: "README.md\0", stderr: "" },
          };
        return {
          ok: true,
          value: { exitCode: 0, stdout: "5\n", stderr: "" },
        };
      },
    };

    const result = await planHistory("C:/repository", [newestPrevious], runner);

    expect(result).toEqual({
      ok: true,
      value: {
        baseSha: null,
        historyCommits: 5,
        changedPaths: ["README.md"],
      },
    });
  });
});
