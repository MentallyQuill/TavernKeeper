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
  "INVALID_TARGET" | "CHECKOUT_FAILED" | "HEAD_MISMATCH" | "HISTORY_FAILED";

export interface CheckoutSpec {
  target: Target | Record<string, unknown>;
  destination: string;
  runner: CommandRunner;
}

export interface CheckoutResult {
  directory: string;
  headSha: string;
  historyCommits: number;
}

const nullDevice = process.platform === "win32" ? "NUL" : "/dev/null";

const gitOptions = (cwd: string): CommandOptions => ({
  cwd,
  environment: restrictedEnvironment({
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: nullDevice,
    GIT_LFS_SKIP_SMUDGE: "1",
    GIT_TERMINAL_PROMPT: "0",
    GIT_PROTOCOL_FROM_USER: "0",
  }),
  timeoutMs: 120_000,
  maxOutputBytes: 2_000_000,
  shell: false,
});

export async function verifyExactHead(
  root: string,
  expectedSha: string,
  runner: CommandRunner,
): Promise<Result<string, "CHECKOUT_FAILED" | "HEAD_MISMATCH">> {
  const result = await runner.run(
    "git",
    ["rev-parse", "HEAD"],
    gitOptions(root),
  );
  if (!result.ok || result.value.exitCode !== 0) {
    return err("CHECKOUT_FAILED", "Could not verify checked-out commit.");
  }
  const headSha = result.value.stdout.trim();
  return headSha === expectedSha
    ? ok(headSha)
    : err("HEAD_MISMATCH", "Checked-out commit does not match target SHA.");
}

export async function checkoutExactTarget(
  spec: CheckoutSpec,
): Promise<Result<CheckoutResult, CheckoutErrorCode>> {
  const parsedTarget = TargetSchema.safeParse(spec.target);
  if (!parsedTarget.success) {
    return err("INVALID_TARGET", "Target must use a full GitHub commit SHA.");
  }
  const target = parsedTarget.data;
  const destination = resolve(spec.destination);
  const repositoryUrl = `https://github.com/${target.repository}.git`;
  const commands: Array<[string, string[]]> = [
    ["git", ["init"]],
    ["git", ["remote", "add", "origin", repositoryUrl]],
    [
      "git",
      [
        "fetch",
        "--no-tags",
        "--depth=20",
        "--no-recurse-submodules",
        "origin",
        target.target_sha,
      ],
    ],
    [
      "git",
      [
        "-c",
        `core.hooksPath=${nullDevice}`,
        "checkout",
        "--detach",
        target.target_sha,
      ],
    ],
  ];

  try {
    await mkdir(destination, { recursive: true });
    for (const [command, args] of commands) {
      const result = await spec.runner.run(
        command,
        args,
        gitOptions(destination),
      );
      if (!result.ok || result.value.exitCode !== 0) {
        return err("CHECKOUT_FAILED", "Git checkout step failed.");
      }
    }

    const verifiedHead = await verifyExactHead(
      destination,
      target.target_sha,
      spec.runner,
    );
    if (!verifiedHead.ok) return verifiedHead;

    const history = await spec.runner.run(
      "git",
      ["rev-list", "--count", "--max-count=20", "HEAD"],
      gitOptions(destination),
    );
    if (!history.ok || history.value.exitCode !== 0) {
      return err("HISTORY_FAILED", "Could not read bounded commit history.");
    }
    const historyCommits = Number.parseInt(history.value.stdout.trim(), 10);
    if (
      !Number.isInteger(historyCommits) ||
      historyCommits < 1 ||
      historyCommits > 20
    ) {
      return err("HISTORY_FAILED", "Could not read bounded commit history.");
    }
    return ok({
      directory: destination,
      headSha: verifiedHead.value,
      historyCommits,
    });
  } catch {
    return err("CHECKOUT_FAILED", "Git checkout could not be completed.");
  }
}
