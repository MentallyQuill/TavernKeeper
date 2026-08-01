import { spawn } from "node:child_process";

import { err, ok, type Result } from "../core/result.js";

export interface CommandOptions {
  cwd: string;
  environment: Record<string, string>;
  timeoutMs: number;
  maxOutputBytes: number;
  shell: false;
}

export interface CommandResult {
  exitCode: number;
  stdout: string;
  stderr: string;
}

export type CommandExecutionErrorCode =
  "SPAWN_FAILED" | "TIMED_OUT" | "OUTPUT_LIMIT_EXCEEDED";
export type CommandExecutionResult = Result<
  CommandResult,
  CommandExecutionErrorCode
>;

export interface CommandRunner {
  run(
    command: string,
    args: string[],
    options: CommandOptions,
  ): Promise<CommandExecutionResult>;
}

export class ProcessCommandRunner implements CommandRunner {
  run(
    command: string,
    args: string[],
    options: CommandOptions,
  ): Promise<CommandExecutionResult> {
    return new Promise((resolve) => {
      const child = spawn(command, args, {
        cwd: options.cwd,
        env: options.environment,
        shell: options.shell,
        stdio: ["ignore", "pipe", "pipe"],
        windowsHide: true,
      });
      let stdout = Buffer.alloc(0);
      let stderr = Buffer.alloc(0);
      let outputExceeded = false;
      let timedOut = false;
      const timer = setTimeout(() => {
        timedOut = true;
        child.kill("SIGKILL");
      }, options.timeoutMs);

      const append = (current: Buffer, chunk: Buffer) => {
        const combined = Buffer.concat([current, chunk]);
        if (combined.length > options.maxOutputBytes) {
          outputExceeded = true;
          child.kill("SIGKILL");
          return combined.subarray(0, options.maxOutputBytes);
        }
        return combined;
      };

      child.stdout.on("data", (chunk: Buffer) => {
        stdout = append(stdout, chunk);
      });
      child.stderr.on("data", (chunk: Buffer) => {
        stderr = append(stderr, chunk);
      });
      child.on("error", () => {
        clearTimeout(timer);
        resolve(err("SPAWN_FAILED", "Command could not be started."));
      });
      child.on("close", (exitCode) => {
        clearTimeout(timer);
        if (timedOut) {
          resolve(err("TIMED_OUT", "Command exceeded the configured timeout."));
          return;
        }
        if (outputExceeded) {
          resolve(
            err(
              "OUTPUT_LIMIT_EXCEEDED",
              "Command output exceeded the configured limit.",
            ),
          );
          return;
        }
        resolve(
          ok({
            exitCode: exitCode ?? 1,
            stdout: stdout.toString("utf8"),
            stderr: stderr.toString("utf8"),
          }),
        );
      });
    });
  }
}

export function restrictedEnvironment(
  additions: Record<string, string> = {},
): Record<string, string> {
  const environment: Record<string, string> = { ...additions };
  for (const name of ["PATH", "Path", "SystemRoot", "WINDIR", "TMP", "TEMP"]) {
    const value = process.env[name];
    if (value) environment[name] = value;
  }
  return environment;
}
