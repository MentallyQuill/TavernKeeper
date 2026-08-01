import { mkdtemp } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, test } from "vitest";

import { checkoutExactTarget } from "../src/git/checkout.js";
import type {
  CommandOptions,
  CommandResult,
  CommandRunner,
} from "../src/process/command-runner.js";

const fullSha = "a".repeat(40);

class RecordingRunner implements CommandRunner {
  calls: Array<{
    command: string;
    args: string[];
    options: CommandOptions;
  }> = [];

  async run(
    command: string,
    args: string[],
    options: CommandOptions,
  ): Promise<CommandResult> {
    this.calls.push({ command, args, options });
    return {
      exitCode: 0,
      stdout: args.includes("rev-list") ? "5\n" : "",
      stderr: "",
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

    expect(result).toMatchObject({ ok: true, value: { historyCommits: 5 } });
    expect(runner.calls).toContainEqual(
      expect.objectContaining({
        command: "git",
        args: ["-c", "core.hooksPath=/dev/null", "checkout", "--detach", fullSha],
      }),
    );
    expect(runner.calls).toContainEqual(
      expect.objectContaining({
        command: "git",
        args: ["fetch", "--no-tags", "--depth=21", "--filter=blob:none", "origin", fullSha],
      }),
    );
    expect(runner.calls.every(({ options }) => options.shell === false)).toBe(
      true,
    );
    expect(
      runner.calls.every(
        ({ options }) => options.environment.GIT_LFS_SKIP_SMUDGE === "1",
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
});
