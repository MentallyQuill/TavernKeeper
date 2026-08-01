import { resolve } from "node:path";

import { FullShaSchema } from "../contracts/targets.js";
import { err, ok, type Result } from "../core/result.js";
import {
  restrictedEnvironment,
  type CommandOptions,
  type CommandRunner,
} from "../process/command-runner.js";

export interface HistoryPlan {
  baseSha: string | null;
  historyCommits: number;
  changedPaths: string[];
}

const nullDevice = process.platform === "win32" ? "NUL" : "/dev/null";

const historyOptions = (cwd: string): CommandOptions => ({
  cwd,
  environment: restrictedEnvironment({
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: nullDevice,
    GIT_LFS_SKIP_SMUDGE: "1",
    GIT_TERMINAL_PROMPT: "0",
    GIT_PROTOCOL_FROM_USER: "0",
  }),
  timeoutMs: 120_000,
  maxOutputBytes: 20_000_000,
  shell: false,
});

function parseNulPaths(stdout: string): string[] {
  return [
    ...new Set(stdout.split("\0").filter((path) => path.length > 0)),
  ].sort((left, right) => left.localeCompare(right));
}

async function readHistoryCount(
  root: string,
  revision: string,
  runner: CommandRunner,
): Promise<Result<number, "HISTORY_FAILED">> {
  const result = await runner.run(
    "git",
    ["rev-list", "--count", "--max-count=20", revision],
    historyOptions(root),
  );
  if (!result.ok || result.value.exitCode !== 0) {
    return err("HISTORY_FAILED", "Could not count bounded history.");
  }
  const count = Number.parseInt(result.value.stdout.trim(), 10);
  return Number.isInteger(count) && count >= 0 && count <= 20
    ? ok(count)
    : err("HISTORY_FAILED", "Could not count bounded history.");
}

export async function planHistory(
  root: string,
  previousShas: string[],
  runner: CommandRunner,
): Promise<Result<HistoryPlan, "HISTORY_FAILED">> {
  if (!previousShas.every((sha) => FullShaSchema.safeParse(sha).success)) {
    return err(
      "HISTORY_FAILED",
      "Previous report history contains an invalid SHA.",
    );
  }
  const repositoryRoot = resolve(root);

  for (const previousSha of previousShas) {
    const ancestor = await runner.run(
      "git",
      ["merge-base", "--is-ancestor", previousSha, "HEAD"],
      historyOptions(repositoryRoot),
    );
    if (!ancestor.ok || ![0, 1].includes(ancestor.value.exitCode)) {
      return err(
        "HISTORY_FAILED",
        "Could not inspect bounded commit ancestry.",
      );
    }
    if (ancestor.value.exitCode !== 0) continue;

    const revision = `${previousSha}..HEAD`;
    const changed = await runner.run(
      "git",
      ["diff", "--name-only", "-z", revision, "--"],
      historyOptions(repositoryRoot),
    );
    if (!changed.ok || changed.value.exitCode !== 0) {
      return err("HISTORY_FAILED", "Could not list bounded changed paths.");
    }
    const count = await readHistoryCount(repositoryRoot, revision, runner);
    if (!count.ok) return count;
    if (count.value === 0) continue;
    return ok({
      baseSha: previousSha,
      historyCommits: count.value,
      changedPaths: parseNulPaths(changed.value.stdout),
    });
  }

  const changed = await runner.run(
    "git",
    ["log", "--format=", "--name-only", "-z", "--max-count=20", "HEAD", "--"],
    historyOptions(repositoryRoot),
  );
  if (!changed.ok || changed.value.exitCode !== 0) {
    return err("HISTORY_FAILED", "Could not list bounded changed paths.");
  }
  const count = await readHistoryCount(repositoryRoot, "HEAD", runner);
  if (!count.ok) return count;
  return ok({
    baseSha: null,
    historyCommits: count.value,
    changedPaths: parseNulPaths(changed.value.stdout),
  });
}
