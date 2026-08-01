import { createHash } from "node:crypto";

import type { Confidence, Finding, Severity } from "../contracts/reports.js";
import {
  restrictedEnvironment,
  type CommandRunner,
} from "../process/command-runner.js";

export interface ExternalToolRun {
  name: string;
  status: "completed" | "not-applicable" | "unavailable" | "failed";
  version: string | null;
  detail?: string;
  findings: Finding[];
}

interface ToolDefinition {
  name: string;
  command: string;
  args(root: string): string[];
  acceptedExitCodes: number[];
}

const definitions: ToolDefinition[] = [
  {
    name: "gitleaks",
    command: "gitleaks",
    args: (root) => [
      "dir",
      "--no-banner",
      "--redact=100",
      "--report-format",
      "json",
      "--report-path",
      "-",
      root,
    ],
    acceptedExitCodes: [0, 1],
  },
  {
    name: "opengrep",
    command: "opengrep",
    args: (root) => ["scan", "--json", "--config", "auto", root],
    acceptedExitCodes: [0, 1],
  },
  {
    name: "osv-scanner",
    command: "osv-scanner",
    args: (root) => ["scan", "source", "--format", "json", "-r", root],
    acceptedExitCodes: [0, 1, 128],
  },
  {
    name: "zizmor",
    command: "zizmor",
    args: (root) => ["--format=json-v1", "--no-progress", root],
    acceptedExitCodes: [0, 1],
  },
  {
    name: "malcontent",
    command: "malcontent",
    args: (root) => ["scan", "--format", "json", root],
    acceptedExitCodes: [0, 1],
  },
];

function severity(value: unknown): Severity {
  const normalized = String(value ?? "medium").toLowerCase();
  return ["critical", "high", "medium", "low", "info"].includes(normalized)
    ? (normalized as Severity)
    : "medium";
}

function confidence(detector: string): Confidence {
  return detector === "gitleaks" || detector === "malcontent"
    ? "high"
    : "medium";
}

function category(detector: string): string {
  return (
    {
      gitleaks: "credential-exposure",
      opengrep: "static-analysis",
      "osv-scanner": "dependency-vulnerability",
      zizmor: "workflow-security",
      malcontent: "binary-analysis",
    }[detector] ?? "scanner-finding"
  );
}

function normalizedFinding(
  detector: string,
  value: Record<string, unknown>,
  index: number,
): Finding {
  const extra = (value.extra ?? {}) as Record<string, unknown>;
  const start = (value.start ?? {}) as Record<string, unknown>;
  const determinations = (value.determinations ?? {}) as Record<
    string,
    unknown
  >;
  const ruleId = String(
    value.RuleID ??
      value.check_id ??
      value.ident ??
      value.id ??
      `finding-${index}`,
  );
  const path = String(
    value.File ?? value.path ?? value.file ?? "dependency-manifest",
  );
  const lineValue = value.StartLine ?? start.line ?? value.line;
  const line =
    Number.isInteger(lineValue) && Number(lineValue) > 0
      ? Number(lineValue)
      : null;
  const title = String(
    value.Description ?? extra.message ?? value.desc ?? value.title ?? ruleId,
  ).slice(0, 200);
  const findingSeverity = severity(
    extra.severity ?? determinations.severity ?? value.severity,
  );
  const fingerprint = createHash("sha256")
    .update([detector, ruleId, path, line ?? 0].join(":"))
    .digest("hex");
  return {
    origin: detector,
    rule_id: ruleId.slice(0, 120),
    category: category(detector),
    severity: findingSeverity,
    confidence: confidence(detector),
    path: path.slice(0, 500),
    line_start: line,
    line_end: line,
    evidence_sha: null,
    title,
    explanation:
      "External scanner reported a matching rule; sensitive match text was omitted.",
    fingerprint,
    disposition: "active",
  };
}

function parseFindings(name: string, stdout: string): Finding[] {
  if (!stdout.trim()) return [];
  const parsed = JSON.parse(stdout) as unknown;
  let values: unknown[] = [];
  if (Array.isArray(parsed)) values = parsed;
  else if (parsed && typeof parsed === "object") {
    const object = parsed as Record<string, unknown>;
    if (Array.isArray(object.results)) values = object.results;
    else if (Array.isArray(object.findings)) values = object.findings;
  }
  return values
    .filter((value): value is Record<string, unknown> =>
      Boolean(value && typeof value === "object"),
    )
    .map((value, index) => normalizedFinding(name, value, index));
}

export async function runExternalTools({
  root,
  runner,
}: {
  root: string;
  runner: CommandRunner;
}): Promise<ExternalToolRun[]> {
  const runs: ExternalToolRun[] = [];
  for (const definition of definitions) {
    try {
      const result = await runner.run(
        definition.command,
        definition.args(root),
        {
          cwd: root,
          environment: restrictedEnvironment({
            NO_COLOR: "1",
            GIT_TERMINAL_PROMPT: "0",
          }),
          timeoutMs: 300_000,
          maxOutputBytes: 20_000_000,
          shell: false,
        },
      );
      if (!definition.acceptedExitCodes.includes(result.exitCode)) {
        runs.push({
          name: definition.name,
          status: "failed",
          version: null,
          detail: `Exited with code ${result.exitCode}.`,
          findings: [],
        });
        continue;
      }
      runs.push({
        name: definition.name,
        status: "completed",
        version: null,
        findings: parseFindings(definition.name, result.stdout),
      });
    } catch (error) {
      const missing = (error as NodeJS.ErrnoException).code === "ENOENT";
      runs.push({
        name: definition.name,
        status: missing ? "unavailable" : "failed",
        version: null,
        detail: missing
          ? "Executable not found."
          : "Scanner invocation failed.",
        findings: [],
      });
    }
  }
  return runs;
}
