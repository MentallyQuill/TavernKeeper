import { spawn } from "node:child_process";
import { fileURLToPath } from "node:url";
import { join, relative, resolve } from "node:path";
import { tmpdir } from "node:os";

import { loadScannerPins } from "../src/config/policy.ts";

const scriptPath = fileURLToPath(import.meta.url);
const repositoryRoot = resolve(scriptPath, "..", "..");

export function resolveToolsDirectory(environment = process.env) {
  const temporaryRoot = resolve(environment.RUNNER_TEMP || tmpdir());
  const toolsDir = resolve(
    environment.TAVERNKEEPER_TOOLS_DIR ||
      join(temporaryRoot, "tavernkeeper-tools-v1"),
  );
  const child = relative(temporaryRoot, toolsDir);
  if (!child || child.startsWith("..") || resolve(child) === child) {
    throw new Error(
      "Scanner tool directory must be inside runner temporary storage.",
    );
  }
  return toolsDir;
}

export function restrictedToolEnvironment(toolsDir) {
  const bin = join(toolsDir, "bin");
  return {
    HOME: join(toolsDir, "home"),
    LANG: "C.UTF-8",
    LC_ALL: "C.UTF-8",
    PATH: bin,
    TMP: join(toolsDir, "tmp"),
    TEMP: join(toolsDir, "tmp"),
    TMPDIR: join(toolsDir, "tmp"),
  };
}

export function runCommand({
  command,
  args,
  cwd,
  env,
  timeoutMs = 30_000,
  maxOutputBytes = 65_536,
}) {
  return new Promise((resolveResult, reject) => {
    const child = spawn(command, args, {
      cwd,
      env,
      shell: false,
      windowsHide: true,
      stdio: ["ignore", "pipe", "pipe"],
    });
    let stdout = "";
    let stderr = "";
    let outputBytes = 0;
    let outputExceeded = false;
    const capture = (target, chunk) => {
      outputBytes += chunk.length;
      if (outputBytes > maxOutputBytes) {
        outputExceeded = true;
        child.kill("SIGKILL");
        return target;
      }
      return target + chunk.toString("utf8");
    };
    child.stdout.on("data", (chunk) => {
      stdout = capture(stdout, chunk);
    });
    child.stderr.on("data", (chunk) => {
      stderr = capture(stderr, chunk);
    });
    child.once("error", reject);
    const timeout = setTimeout(() => child.kill("SIGKILL"), timeoutMs);
    child.once("close", (code, signal) => {
      clearTimeout(timeout);
      if (outputExceeded) {
        reject(new Error("Scanner version output exceeded its ceiling."));
        return;
      }
      if (signal) {
        reject(new Error("Scanner version command exceeded its time ceiling."));
        return;
      }
      resolveResult({ code: code ?? -1, stdout, stderr });
    });
  });
}

function escapeRegex(value) {
  return value.replace(/[.*+?^${}()|[\]\\]/gu, "\\$&");
}

export function versionChecks(pins, toolsDir) {
  const executable = (name) => join(toolsDir, "bin", name);
  return [
    {
      name: "gitleaks",
      command: executable("gitleaks"),
      args: ["version"],
      version: pins.gitleaks.version,
    },
    {
      name: "opengrep",
      command: executable("opengrep"),
      args: ["--version"],
      version: pins.opengrep.version,
    },
    {
      name: "osv-scanner",
      command: executable("osv-scanner"),
      args: ["--version"],
      version: pins.osvScanner.version,
    },
    {
      name: "zizmor",
      command: executable("zizmor"),
      args: ["--version"],
      version: pins.zizmor.version,
    },
    {
      name: "malcontent",
      command: executable("malcontent"),
      args: ["--version"],
      version: pins.malcontent.version,
    },
  ];
}

export async function verifyScannerVersions({
  pins,
  toolsDir,
  run = runCommand,
}) {
  const env = restrictedToolEnvironment(toolsDir);
  for (const check of versionChecks(pins, toolsDir)) {
    const result = await run({
      command: check.command,
      args: check.args,
      cwd: toolsDir,
      env,
    });
    const output = `${result.stdout}\n${result.stderr}`;
    const versionPattern = new RegExp(
      `(?:^|[^0-9.])v?${escapeRegex(check.version)}(?:[^0-9.]|$)`,
      "u",
    );
    if (result.code !== 0 || !versionPattern.test(output)) {
      throw new Error(
        `${check.name} did not report pinned version ${check.version}.`,
      );
    }
  }
}

async function main() {
  if (process.platform !== "linux" || process.arch !== "x64") {
    throw new Error("Pinned scanner binaries require a Linux x64 runner.");
  }
  const pins = await loadScannerPins(
    join(repositoryRoot, "config", "scanners.v1.json"),
  );
  await verifyScannerVersions({
    pins,
    toolsDir: resolveToolsDirectory(),
  });
}

if (process.argv[1] && resolve(process.argv[1]) === scriptPath) {
  main().catch((error) => {
    process.stderr.write(
      `${error instanceof Error ? error.message : "Scanner verification failed."}\n`,
    );
    process.exitCode = 1;
  });
}
