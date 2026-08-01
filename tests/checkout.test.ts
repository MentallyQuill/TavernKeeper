import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, test } from "vitest";

import { checkoutExactTarget } from "../src/git/checkout.js";
import type {
  CommandExecutionResult,
  CommandOptions,
  CommandRunner,
} from "../src/process/command-runner.js";

const fullSha = "a".repeat(40);

class RecordingRunner implements CommandRunner {
  constructor(private readonly headSha = fullSha) {}

  calls: Array<{
    command: string;
    args: string[];
    options: CommandOptions;
  }> = [];

  async run(
    command: string,
    args: string[],
    options: CommandOptions,
  ): Promise<CommandExecutionResult> {
    this.calls.push({ command, args, options });
    return {
      ok: true,
      value: {
        exitCode: 0,
        stdout: args.includes("rev-list")
          ? "5\n"
          : args.includes("rev-parse")
            ? `${this.headSha}\n`
            : "",
        stderr: "",
      },
    };
  }
}

describe("exact target checkout", () => {
  test("fetches and detaches only the requested SHA with hooks and LFS disabled", async () => {
    const runner = new RecordingRunner();
    const destination = join(
      await mkdtemp(join(tmpdir(), "tavernkeeper-checkout-")),
      "repository",
    );

    const result = await checkoutExactTarget({
      target: {
        source_id: "github-42",
        provider: "github",
        repository_id: 42,
        repository: "owner/repo",
        target_sha: fullSha,
        canonical_url: "https://github.com/owner/repo",
      },
      destination,
      runner,
    });

    expect(result).toMatchObject({
      ok: true,
      value: { headSha: fullSha, historyCommits: 5 },
    });
    expect(runner.calls).toContainEqual(
      expect.objectContaining({
        command: "git",
        args: [
          "-c",
          `core.hooksPath=${process.platform === "win32" ? "NUL" : "/dev/null"}`,
          "checkout",
          "--detach",
          fullSha,
        ],
      }),
    );
    expect(runner.calls).toContainEqual(
      expect.objectContaining({
        command: "git",
        args: [
          "fetch",
          "--no-tags",
          "--depth=20",
          "--no-recurse-submodules",
          "origin",
          fullSha,
        ],
      }),
    );
    expect(runner.calls.every(({ options }) => options.shell === false)).toBe(
      true,
    );
    expect(
      runner.calls.every(
        ({ options }) =>
          options.environment.GIT_CONFIG_NOSYSTEM === "1" &&
          options.environment.GIT_CONFIG_GLOBAL ===
            (process.platform === "win32" ? "NUL" : "/dev/null") &&
          options.environment.GIT_LFS_SKIP_SMUDGE === "1" &&
          options.environment.GIT_TERMINAL_PROMPT === "0" &&
          options.environment.GIT_PROTOCOL_FROM_USER === "0",
      ),
    ).toBe(true);
  });

  test("rejects a branch before invoking git", async () => {
    const runner = new RecordingRunner();
    const result = await checkoutExactTarget({
      target: {
        source_id: "github-42",
        provider: "github",
        repository_id: 42,
        repository: "owner/repo",
        target_sha: "main",
        canonical_url: "https://github.com/owner/repo",
      },
      destination: join(tmpdir(), "not-created"),
      runner,
    });

    expect(result).toMatchObject({
      ok: false,
      error: { code: "INVALID_TARGET" },
    });
    expect(runner.calls).toEqual([]);
  });

  test("rejects a checked-out HEAD that differs from the requested SHA", async () => {
    const runner = new RecordingRunner("b".repeat(40));
    const result = await checkoutExactTarget({
      target: {
        source_id: "github-42",
        provider: "github",
        repository_id: 42,
        repository: "owner/repo",
        target_sha: fullSha,
        canonical_url: "https://github.com/owner/repo",
      },
      destination: join(tmpdir(), "tavernkeeper-head-mismatch"),
      runner,
    });

    expect(result).toMatchObject({
      ok: false,
      error: { code: "HEAD_MISMATCH" },
    });
  });
});
