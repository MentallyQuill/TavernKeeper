import { access, mkdtemp, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, test } from "vitest";

import {
  ProcessCommandRunner,
  restrictedEnvironment,
} from "../src/process/command-runner.js";

describe("bounded command runner", () => {
  test("passes hostile arguments as data without shell interpretation", async () => {
    const hostileArgument = `spaces "quotes" 'single' ; & | $(echo nope) --leading`;
    const runner = new ProcessCommandRunner();

    const result = await runner.run(
      process.execPath,
      ["-e", "process.stdout.write(process.argv[1])", hostileArgument],
      {
        cwd: process.cwd(),
        environment: restrictedEnvironment(),
        timeoutMs: 10_000,
        maxOutputBytes: 10_000,
        shell: false,
      },
    );

    expect(result).toEqual({
      ok: true,
      value: { exitCode: 0, stdout: hostileArgument, stderr: "" },
    });
  });

  test("returns a typed timeout without including command arguments", async () => {
    const runner = new ProcessCommandRunner();
    const secretLikeArgument = "ghp_abcdefghijklmnopqrstuvwxyz1234567890";

    const result = await runner.run(
      process.execPath,
      ["-e", "setInterval(() => {}, 1000)", secretLikeArgument],
      {
        cwd: process.cwd(),
        environment: restrictedEnvironment(),
        timeoutMs: 25,
        maxOutputBytes: 10_000,
        shell: false,
      },
    );

    expect(result).toMatchObject({ ok: false, error: { code: "TIMED_OUT" } });
    expect(JSON.stringify(result)).not.toContain(secretLikeArgument);
  });

  test("returns a typed failure when either output stream exceeds its cap", async () => {
    const runner = new ProcessCommandRunner();

    const result = await runner.run(
      process.execPath,
      ["-e", 'process.stderr.write("sensitive-output")'],
      {
        cwd: process.cwd(),
        environment: restrictedEnvironment(),
        timeoutMs: 10_000,
        maxOutputBytes: 4,
        shell: false,
      },
    );

    expect(result).toEqual({
      ok: false,
      error: {
        code: "OUTPUT_LIMIT_EXCEEDED",
        message: "Command output exceeded the configured limit.",
      },
    });
  });

  test("returns a typed sanitized spawn failure", async () => {
    const runner = new ProcessCommandRunner();

    const result = await runner.run(
      "definitely-not-a-tavernkeeper-command",
      ["secret-source-value"],
      {
        cwd: process.cwd(),
        environment: restrictedEnvironment(),
        timeoutMs: 10_000,
        maxOutputBytes: 1_000,
        shell: false,
      },
    );

    expect(result).toEqual({
      ok: false,
      error: { code: "SPAWN_FAILED", message: "Command could not be started." },
    });
  });

  test("terminates the child process tree on timeout", async () => {
    const root = await mkdtemp(join(tmpdir(), "tavernkeeper-process-tree-"));
    const controlMarker = join(root, "control-child.txt");
    const marker = join(root, "child-survived.txt");
    const runner = new ProcessCommandRunner();
    const childScript =
      'setTimeout(() => require("node:fs").writeFileSync(process.argv[1], "bad"), 200);';
    const parentScript =
      'const { spawn } = require("node:child_process"); ' +
      `spawn(process.execPath, ["-e", ${JSON.stringify(childScript)}, process.argv[1]], { stdio: "ignore" }); ` +
      "setInterval(() => {}, 1000);";

    try {
      const controlResult = await runner.run(
        process.execPath,
        ["-e", childScript, controlMarker],
        {
          cwd: root,
          environment: restrictedEnvironment(),
          timeoutMs: 1_000,
          maxOutputBytes: 1_000,
          shell: false,
        },
      );
      expect(controlResult).toMatchObject({ ok: true });
      await expect(access(controlMarker)).resolves.toBeUndefined();

      const result = await runner.run(
        process.execPath,
        ["-e", parentScript, marker],
        {
          cwd: root,
          environment: restrictedEnvironment(),
          timeoutMs: 100,
          maxOutputBytes: 1_000,
          shell: false,
        },
      );
      await new Promise((resolve) => setTimeout(resolve, 300));

      expect(result).toMatchObject({ ok: false, error: { code: "TIMED_OUT" } });
      await expect(access(marker)).rejects.toThrow();
    } finally {
      await rm(root, { force: true, recursive: true });
    }
  });
});
