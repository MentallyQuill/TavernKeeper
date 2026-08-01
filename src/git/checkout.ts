import { mkdir } from "node:fs/promises";
import { resolve } from "node:path";

import { TargetSchema, type Target } from "../contracts/targets.js";
import { err, ok, type Result } from "../core/result.js";
import {
  restrictedEnvironment,
  type CommandOptions,
  type CommandRunner,
} from "../process/command-runner.js";

export type CheckoutErrorCode =
  "INVALID_TARGET" | "CHECKOUT_FAILED" | "HISTORY_FAILED";

export interface CheckoutSpec {
  target: Target | Record<string, unknown>;
  destination: string;
  runner: CommandRunner;
}

export interface CheckoutResult {
  directory: string;
  historyCommits: number;
}

const gitOptions = (cwd: string): CommandOptions => ({
  cwd,
  environment: restrictedEnvironment({
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_LFS_SKIP_SMUDGE: "1",
    GIT_TERMINAL_PROMPT: "0",
  }),
  timeoutMs: 120_000,
  maxOutputBytes: 2_000_000,
  shell: false,
});

export async function checkoutExactTarget(
  spec: CheckoutSpec,
): Promise<Result<CheckoutResult, CheckoutErrorCode>> {
  const parsedTarget = TargetSchema.safeParse(spec.target);
  if (!parsedTarget.success) {
    return err("INVALID_TARGET", "Target must use a full GitHub commit SHA.");
  }
  const target = parsedTarget.data;
  const destination = resolve(spec.destination);
  await mkdir(destination, { recursive: true });

  const commands: Array<[string, string[]]> = [
    ["git", ["init"]],
    ["git", ["remote", "add", "origin", `${target.canonical_url}.git`]],
    [
      "git",
      [
        "fetch",
        "--no-tags",
        "--depth=21",
        "--filter=blob:none",
        "origin",
        target.target_sha,
      ],
    ],
    [
      "git",
      [
        "-c",
        "core.hooksPath=/dev/null",
        "checkout",
        "--detach",
        target.target_sha,
      ],
    ],
  ];

  try {
    for (const [command, args] of commands) {
      const result = await spec.runner.run(
        command,
        args,
        gitOptions(destination),
      );
      if (result.exitCode !== 0) {
        return err(
          "CHECKOUT_FAILED",
          `Git checkout step failed with exit code ${result.exitCode}.`,
        );
      }
    }
    const history = await spec.runner.run(
      "git",
      ["rev-list", "--count", "--max-count=20", "HEAD"],
      gitOptions(destination),
    );
    const historyCommits = Number.parseInt(history.stdout.trim(), 10);
    if (
      history.exitCode !== 0 ||
      !Number.isInteger(historyCommits) ||
      historyCommits < 1 ||
      historyCommits > 20
    ) {
      return err("HISTORY_FAILED", "Could not read bounded commit history.");
    }
    return ok({ directory: destination, historyCommits });
  } catch (error) {
    return err(
      "CHECKOUT_FAILED",
      error instanceof Error ? error.message : "Git checkout failed.",
    );
  }
}
