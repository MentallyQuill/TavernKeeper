import { mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { z } from "zod";

import { FullShaSchema } from "../contracts/targets.js";
import {
  restrictedEnvironment,
  type CommandRunner,
} from "../process/command-runner.js";
import {
  normalizeFinding,
  ScannerError,
  scannerExecutionError,
  type ScannerRun,
} from "./types.js";

const GITLEAKS_CONFIG_TOML =
  'title = "TavernKeeper pinned built-in rules"\n\n[extend]\nuseDefault = true\n';

const GitleaksFindingSchema = z.looseObject({
  RuleID: z.string().min(1).max(500),
  File: z.string().min(1).max(2_000),
  StartLine: z.number().int().positive(),
  EndLine: z.number().int().positive().optional(),
  Commit: z.string().optional(),
});
const GitleaksReportSchema = z.array(GitleaksFindingSchema).max(100_000);

export interface GitleaksHistory {
  baseSha: string | null;
  targetSha: string;
  commits: number;
}

function historyLogOptions(history: GitleaksHistory) {
  const targetSha = FullShaSchema.parse(history.targetSha);
  if (
    !Number.isInteger(history.commits) ||
    history.commits < 1 ||
    history.commits > 20
  )
    throw new ScannerError(
      "MALFORMED_SCANNER_OUTPUT",
      "system",
      "Gitleaks history bounds are invalid.",
      "gitleaks",
    );
  return history.baseSha === null
    ? `--no-merges -n ${history.commits} ${targetSha}`
    : `--no-merges ${FullShaSchema.parse(history.baseSha)}..${targetSha}`;
}

function scannerArgs(
  mode: "dir" | "git",
  root: string,
  reportPath: string,
  ignorePath: string,
  history: GitleaksHistory,
) {
  return [
    mode,
    "--no-banner",
    "--no-color",
    "--redact=100",
    "--report-format=json",
    "--report-path",
    reportPath,
    "--ignore-gitleaks-allow",
    "--gitleaks-ignore-path",
    ignorePath,
    "--max-archive-depth=0",
    "--max-decode-depth=0",
    ...(mode === "git" ? [`--log-opts=${historyLogOptions(history)}`] : []),
    root,
  ];
}

function normalizePath(value: string) {
  return value.replaceAll("\\", "/").replace(/^\.\//u, "");
}

async function parseReport(reportPath: string) {
  let parsed: z.infer<typeof GitleaksReportSchema>;
  try {
    parsed = GitleaksReportSchema.parse(
      JSON.parse(await readFile(reportPath, "utf8")),
    );
  } catch {
    throw new ScannerError(
      "MALFORMED_SCANNER_OUTPUT",
      "system",
      "Gitleaks returned malformed JSON output.",
      "gitleaks",
    );
  }
  try {
    return parsed.map((value) => {
      const commit = value.Commit?.toLowerCase() || null;
      return normalizeFinding({
        origin: "gitleaks",
        ruleId: value.RuleID.replace(/[\u0000-\u001f\u007f]/gu, "").slice(
          0,
          120,
        ),
        category: "credential-exposure",
        severity: "high",
        confidence: "high",
        path: normalizePath(value.File),
        lineStart: value.StartLine,
        lineEnd: value.EndLine ?? value.StartLine,
        evidenceSha: commit,
        title: "Potential credential exposure",
        explanation:
          "Gitleaks matched a credential pattern; the matched value was removed.",
      });
    });
  } catch {
    throw new ScannerError(
      "MALFORMED_SCANNER_OUTPUT",
      "system",
      "Gitleaks returned an invalid finding identity or location.",
      "gitleaks",
    );
  }
}

async function invokeGitleaks({
  mode,
  root,
  history,
  runner,
  executable,
  reportPath,
  ignorePath,
}: {
  mode: "dir" | "git";
  root: string;
  history: GitleaksHistory;
  runner: CommandRunner;
  executable: string;
  reportPath: string;
  ignorePath: string;
}) {
  const result = await runner.run(
    executable,
    scannerArgs(mode, root, reportPath, ignorePath, history),
    {
      cwd: root,
      environment: restrictedEnvironment({
        GIT_TERMINAL_PROMPT: "0",
        GITLEAKS_CONFIG_TOML,
        NO_COLOR: "1",
      }),
      timeoutMs: 300_000,
      maxOutputBytes: 1_000_000,
      shell: false,
    },
  );
  if (!result.ok) throw scannerExecutionError("gitleaks", result.error.code);
  if (result.value.exitCode !== 0 && result.value.exitCode !== 1)
    throw new ScannerError(
      "SCANNER_FAILED",
      "system",
      `Gitleaks exited with code ${result.value.exitCode}.`,
      "gitleaks",
    );
  return parseReport(reportPath);
}

export async function runGitleaks({
  root,
  history,
  runner,
  executable = "gitleaks",
  version,
  temporaryRoot = tmpdir(),
}: {
  root: string;
  history: GitleaksHistory;
  runner: CommandRunner;
  executable?: string;
  version: string;
  temporaryRoot?: string;
}): Promise<ScannerRun> {
  const operationRoot = await mkdtemp(join(temporaryRoot, "gitleaks-"));
  try {
    const ignorePath = join(operationRoot, "trusted-empty-ignore");
    await writeFile(ignorePath, "", { flag: "wx" });
    const tree = await invokeGitleaks({
      mode: "dir",
      root,
      history,
      runner,
      executable,
      reportPath: join(operationRoot, "tree.json"),
      ignorePath,
    });
    const git = await invokeGitleaks({
      mode: "git",
      root,
      history,
      runner,
      executable,
      reportPath: join(operationRoot, "history.json"),
      ignorePath,
    });
    return {
      name: "gitleaks",
      version,
      status: "completed",
      findings: [...tree, ...git].sort((left, right) =>
        left.fingerprint.localeCompare(right.fingerprint),
      ),
    };
  } finally {
    await rm(operationRoot, { recursive: true, force: true });
  }
}
