import type { Confidence, Finding, Severity } from "../contracts/reports.js";
import type { InventoryFile } from "../inventory/inventory-handler.js";
import { normalizeFinding } from "./types.js";

export type StaticSourceFile = InventoryFile & { content?: string | null };

const secretPatterns = [
  /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/gu,
  /\bgithub_pat_[A-Za-z0-9_]{20,}\b/gu,
  /\bsk-[A-Za-z0-9_-]{20,}\b/gu,
  /\bAKIA[0-9A-Z]{16}\b/gu,
];

function redact(value: string) {
  let redacted = value;
  for (const pattern of secretPatterns)
    redacted = redacted.replace(pattern, "[REDACTED_SECRET]");
  return redacted
    .replace(
      /process\.env(?:\.[A-Za-z_][A-Za-z0-9_]*|\[[^\]]+\])/gu,
      "process.env.[REDACTED]",
    )
    .slice(0, 500);
}

function finding(input: {
  ruleId: string;
  category: string;
  severity: Severity;
  confidence: Confidence;
  path: string;
  line: number | null;
  title: string;
  explanation: string;
}): Finding {
  return normalizeFinding({
    origin: "tavernkeeper",
    ruleId: input.ruleId,
    category: input.category,
    severity: input.severity,
    confidence: input.confidence,
    path: input.path,
    lineStart: input.line,
    lineEnd: input.line,
    evidenceSha: null,
    title: input.title,
    explanation: redact(input.explanation),
  });
}

function lineNumber(content: string, index: number) {
  return content.slice(0, Math.max(0, index)).split("\n").length;
}

function scanCredentialExfiltration(file: StaticSourceFile): Finding[] {
  const content = file.content ?? "";
  const credentialSource =
    /process\.env|localStorage|document\.cookie|authorization|api[_-]?key|token/iu.test(
      content,
    );
  const networkMatch =
    /\b(?:fetch|XMLHttpRequest|WebSocket|axios\.(?:get|post|put)|https?\.request)\s*\(/iu.exec(
      content,
    );
  if (!credentialSource || !networkMatch) return [];
  return [
    finding({
      ruleId: "credential-exfiltration",
      category: "credential-theft",
      severity: "high",
      confidence: "high",
      path: file.path,
      line: lineNumber(content, networkMatch.index),
      title: "Credential access and network transmission in one file",
      explanation:
        "Credential source and outbound network sink appear in the same file.",
    }),
  ];
}

function scanInstallHooks(file: StaticSourceFile): Finding[] {
  if (file.path !== "package.json" || !file.content) return [];
  try {
    const parsed = JSON.parse(file.content) as {
      scripts?: Record<string, unknown>;
    };
    return ["preinstall", "install", "postinstall"].flatMap((hook) => {
      const command = parsed.scripts?.[hook];
      if (
        typeof command !== "string" ||
        !/\b(?:curl|wget|powershell|pwsh|Invoke-WebRequest|certutil)\b|https?:\/\//iu.test(
          command,
        )
      )
        return [];
      return [
        finding({
          ruleId: "network-install-hook",
          category: "install-hook",
          severity: "high",
          confidence: "high",
          path: file.path,
          line: 1,
          title: "Install hook performs a network-capable command",
          explanation: `${hook} contains a network-capable installation command; the command was removed.`,
        }),
      ];
    });
  } catch {
    return [];
  }
}

function scanBidiControls(file: StaticSourceFile): Finding[] {
  if (!file.content) return [];
  const match = /[\u202a-\u202e\u2066-\u2069]/u.exec(file.content);
  if (!match) return [];
  return [
    finding({
      ruleId: "unicode-bidi-control",
      category: "obfuscation",
      severity: "medium",
      confidence: "medium",
      path: file.path,
      line: lineNumber(file.content, match.index),
      title: "Bidirectional Unicode control in source text",
      explanation:
        "A bidirectional control character can disguise source ordering.",
    }),
  ];
}

export function scanStaticRules(files: StaticSourceFile[]): Finding[] {
  return files
    .flatMap((file) => [
      ...scanCredentialExfiltration(file),
      ...scanInstallHooks(file),
      ...scanBidiControls(file),
    ])
    .sort((left, right) =>
      [left.path, left.line_start ?? 0, left.rule_id]
        .join(":")
        .localeCompare(
          [right.path, right.line_start ?? 0, right.rule_id].join(":"),
        ),
    );
}
