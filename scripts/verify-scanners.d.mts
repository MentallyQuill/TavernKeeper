import type { ScannerPins } from "../src/config/policy.js";

export interface CommandSpec {
  command: string;
  args: string[];
  cwd: string;
  env: Record<string, string>;
  timeoutMs?: number;
  maxOutputBytes?: number;
}

export interface CommandResult {
  code: number;
  stdout: string;
  stderr: string;
}

export type CommandRunner = (spec: CommandSpec) => Promise<CommandResult>;

export function resolveToolsDirectory(environment?: NodeJS.ProcessEnv): string;
export function restrictedToolEnvironment(
  toolsDir: string,
): Record<string, string>;
export function runCommand(spec: CommandSpec): Promise<CommandResult>;
export function versionChecks(
  pins: ScannerPins,
  toolsDir: string,
): Array<{
  name: string;
  command: string;
  args: string[];
  version: string;
}>;
export function verifyScannerVersions(spec: {
  pins: ScannerPins;
  toolsDir: string;
  run?: CommandRunner;
}): Promise<void>;
