import { normalizeFinding } from "./types.js";
import type {
  JavaScriptEvidenceHint,
  JavascriptPrimitiveResult,
  JavascriptRepresentation,
} from "./javascript-analysis-types.js";

interface SignatureSpec {
  ruleId: string;
  category: string;
  title: string;
  explanation: string;
  remediation: string;
  source: RegExp;
  sink: RegExp;
}

const sensitiveCredential = String.raw`(?:api[_-]?key|auth|cookie|credential|password|passwd|secret|token)`;

const signatures: readonly SignatureSpec[] = [
  {
    ruleId: "javascript.credential-to-network",
    category: "credential-theft",
    title: "Credential access is correlated with an outbound network sink",
    explanation:
      "JavaScript reads credential-bearing state and also contains an outbound network sink in the same representation.",
    remediation:
      "Verify the data flow and remove any transmission of credentials to an untrusted destination.",
    source: new RegExp(
      String.raw`(?:process\s*\.\s*env(?:\s*\.\s*[A-Za-z0-9_$]*${sensitiveCredential}[A-Za-z0-9_$]*|\s*\[\s*["'][^"']*${sensitiveCredential}[^"']*["']\s*\])|document\s*\.\s*cookie|(?:local|session)Storage\s*\.\s*getItem\s*\(\s*["'][^"']*${sensitiveCredential}[^"']*["'])`,
      "iu",
    ),
    sink: /(?:\bfetch\s*\(|\baxios(?:\s*\.\s*(?:post|put|request))?\s*\(|\bnavigator\s*\.\s*sendBeacon\s*\(|\bnew\s+WebSocket\s*\(|\bXMLHttpRequest\b|\bhttps?\s*\.\s*(?:request|post)\s*\()/iu,
  },
  {
    ruleId: "javascript.download-to-execution",
    category: "code-execution",
    title: "Network retrieval is correlated with a code execution sink",
    explanation:
      "JavaScript contains both a network retrieval primitive and a dynamic code or command execution sink in the same representation.",
    remediation:
      "Remove dynamic execution of downloaded content and replace it with verified, declarative behavior.",
    source:
      /(?:\bfetch\s*\(|\baxios(?:\s*\.\s*(?:get|request))?\s*\(|\bhttps?\s*\.\s*(?:get|request)\s*\()/iu,
    sink: /(?:\beval\s*\(|\bnew\s+Function\s*\(|\bFunction\s*\(|\bchild_process\s*\.\s*(?:exec|execFile|spawn)\s*\(|\bvm\s*\.\s*runIn(?:New|This)Context\s*\()/iu,
  },
];

function firstMatch(expression: RegExp, source: string) {
  const match = expression.exec(source);
  return match === null
    ? null
    : { start: match.index, end: match.index + match[0].length };
}

function location(source: string, offset: number) {
  const prefix = source.slice(0, offset);
  const line = prefix.split("\n").length;
  const lastNewline = prefix.lastIndexOf("\n");
  return { line, column: offset - lastNewline };
}

export function scanJavascriptSignatures(input: {
  source: string;
  path: string;
  representation: JavascriptRepresentation;
}): JavascriptPrimitiveResult {
  const findings = [];
  const evidenceHints: JavaScriptEvidenceHint[] = [];

  for (const signature of signatures) {
    const sourceMatch = firstMatch(signature.source, input.source);
    const sinkMatch = firstMatch(signature.sink, input.source);
    if (sourceMatch === null || sinkMatch === null) continue;
    const start = Math.min(sourceMatch.start, sinkMatch.start);
    const end = Math.max(sourceMatch.end, sinkMatch.end);
    const startLocation = location(input.source, start);
    const endLocation = location(input.source, end);
    const finding = normalizeFinding({
      origin: "javascript-analysis",
      ruleId: signature.ruleId,
      category: signature.category,
      severity: "high",
      confidence: "medium",
      path: input.path,
      lineStart: startLocation.line,
      lineEnd: endLocation.line,
      evidenceSha: null,
      title: signature.title,
      explanation: signature.explanation,
      remediation: signature.remediation,
    });
    findings.push(finding);
    evidenceHints.push({
      finding_fingerprint: finding.fingerprint,
      original_path: input.path,
      stage: input.representation.stage,
      representation_sha256: input.representation.sha256,
      transform_depth: input.representation.depth,
      line_start: startLocation.line,
      line_end: endLocation.line,
      column_start: startLocation.column,
      column_end: endLocation.column,
      source: input.source,
    });
  }

  return { findings, evidenceHints };
}
