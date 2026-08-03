import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve, sep } from "node:path";

import type { Target } from "../contracts/targets.js";
import type {
  Inventory,
  InventoryFile,
} from "../inventory/inventory-handler.js";
import type { Finding } from "../contracts/reports.js";
import { redactSource } from "../model/redaction.js";
import {
  ECOSYSTEM_CONTEXT_VERSION,
  ecosystemContext,
} from "./ecosystem-context.js";

type ProjectKind = "extension" | "frontend" | "preset";
export type FileRole =
  | "production"
  | "test"
  | "fixture"
  | "documentation"
  | "tooling"
  | "generated"
  | "vendored"
  | "unknown";

export interface EvidenceCandidate {
  candidate_id: string;
  evidence_id: string;
  origin: string;
  rule_id: string;
  category: string;
  scanner_severity: Finding["severity"];
  scanner_confidence: Finding["confidence"];
  title: string;
  explanation: string;
  line_start: number | null;
  line_end: number | null;
}

export interface EvidenceContextGroup {
  group_id: string;
  repository: string;
  project_kinds: readonly ProjectKind[];
  path: string;
  file_role: FileRole;
  target_sha: string;
  evidence_sha: string | null;
  ecosystem_context_version: string;
  ecosystem_context: string;
  candidates: EvidenceCandidate[];
  context: {
    imports: string;
    source: string;
    project_purpose: string;
  };
}

interface BuildEvidenceContextGroupsInput {
  checkoutRoot: string;
  target: Target;
  projectKinds: readonly ProjectKind[];
  findings: readonly Finding[];
  inventory: Inventory;
  historicalSources?: readonly HistoricalEvidenceSource[];
}

export interface HistoricalEvidenceSource {
  path: string;
  evidence_sha: string;
  content: string;
  bytes: number;
  sha256: string;
}

const PURPOSE_FILES = [
  "README.md",
  "README.txt",
  "package.json",
  "manifest.json",
];
const SOURCE_CONTEXT_LINES = 40;
const MAX_CANDIDATES_PER_GROUP = 64;
const MAX_PURPOSE_CHARACTERS = 8_000;
const MAX_IMPORT_CHARACTERS = 4_000;

function digest(value: unknown) {
  return createHash("sha256").update(JSON.stringify(value)).digest("hex");
}

function absoluteInventoryPath(root: string, path: string) {
  const absoluteRoot = resolve(root);
  const absolutePath = resolve(absoluteRoot, ...path.split("/"));
  if (
    absolutePath !== absoluteRoot &&
    !absolutePath.startsWith(`${absoluteRoot}${sep}`)
  ) {
    throw new Error(`Evidence path escapes the repository root: ${path}`);
  }
  return absolutePath;
}

async function readVerifiedText(
  root: string,
  file: InventoryFile,
): Promise<string> {
  if (file.kind !== "text")
    throw new Error(`Evidence file is not text: ${file.path}`);
  const contents = await readFile(absoluteInventoryPath(root, file.path));
  const sha256 = createHash("sha256").update(contents).digest("hex");
  if (contents.byteLength !== file.bytes || sha256 !== file.sha256) {
    throw new Error(`Evidence file changed after inventory: ${file.path}`);
  }
  return contents.toString("utf8");
}

function classifyFileRole(path: string): FileRole {
  const normalized = path.toLowerCase();
  const segments = normalized.split("/");
  const filename = segments.at(-1) ?? normalized;
  if (segments.some((part) => ["fixture", "fixtures"].includes(part)))
    return "fixture";
  if (
    segments.some((part) => ["test", "tests", "__tests__"].includes(part)) ||
    /(?:^|\.)(?:test|spec)\.[^.]+$/u.test(filename)
  ) {
    return "test";
  }
  if (segments.includes("vendor") || segments.includes("vendored"))
    return "vendored";
  if (
    segments.includes("dist") ||
    segments.includes("build") ||
    filename.endsWith(".min.js")
  ) {
    return "generated";
  }
  if (
    segments.includes("docs") ||
    /^readme(?:\.|$)/u.test(filename) ||
    /\.(?:md|mdx|rst|txt)$/u.test(filename)
  ) {
    return "documentation";
  }
  if (
    segments.includes("scripts") ||
    segments.includes(".github") ||
    /(?:^|\.)(?:config|rc)\.[^.]+$/u.test(filename)
  ) {
    return "tooling";
  }
  return "production";
}

function numberedLines(lines: readonly string[], start: number, end: number) {
  return lines
    .slice(start - 1, end)
    .map((line, index) => `${String(start + index).padStart(6, " ")} | ${line}`)
    .join("\n");
}

function sourceWindows(source: string, findings: readonly Finding[]) {
  const lines = source.split(/\r?\n/u);
  const ranges = findings
    .map((finding) => {
      const lineStart = finding.line_start ?? 1;
      const lineEnd = finding.line_end ?? lineStart;
      return {
        start: Math.max(1, lineStart - SOURCE_CONTEXT_LINES),
        end: Math.min(lines.length, lineEnd + SOURCE_CONTEXT_LINES),
      };
    })
    .sort((left, right) => left.start - right.start || left.end - right.end);
  const merged: Array<{ start: number; end: number }> = [];
  for (const range of ranges) {
    const previous = merged.at(-1);
    if (previous && range.start <= previous.end + 1) {
      previous.end = Math.max(previous.end, range.end);
    } else {
      merged.push({ ...range });
    }
  }
  return merged
    .map((range) => numberedLines(lines, range.start, range.end))
    .join("\n\n[... separate evidence window ...]\n\n");
}

function coherentFindingGroups(findings: readonly Finding[]) {
  const ordered = [...findings].sort(
    (left, right) =>
      (left.line_start ?? 1) - (right.line_start ?? 1) ||
      (left.line_end ?? left.line_start ?? 1) -
        (right.line_end ?? right.line_start ?? 1) ||
      left.fingerprint.localeCompare(right.fingerprint),
  );
  const groups: Finding[][] = [];
  let previousEnd = 0;
  for (const finding of ordered) {
    const start = finding.line_start ?? 1;
    const end = finding.line_end ?? start;
    let group = groups.at(-1);
    if (
      !group ||
      group.length >= MAX_CANDIDATES_PER_GROUP ||
      (previousEnd > 0 && start > previousEnd + SOURCE_CONTEXT_LINES * 2)
    ) {
      group = [];
      groups.push(group);
      previousEnd = 0;
    }
    group.push(finding);
    previousEnd = Math.max(previousEnd, end);
  }
  return groups;
}

function importContext(source: string) {
  return source
    .split(/\r?\n/u)
    .map((line, index) => ({ line, number: index + 1 }))
    .filter(({ line }) =>
      /^\s*(?:import\b|export\b.*\bfrom\b|(?:const|let|var)\b.*\brequire\s*\()/u.test(
        line,
      ),
    )
    .map(({ line, number }) => `${String(number).padStart(6, " ")} | ${line}`)
    .join("\n")
    .slice(0, MAX_IMPORT_CHARACTERS);
}

async function projectPurpose(root: string, inventory: Inventory) {
  const byLowerPath = new Map(
    inventory.files.map((file) => [file.path.toLowerCase(), file]),
  );
  const sections: string[] = [];
  for (const name of PURPOSE_FILES) {
    const file = byLowerPath.get(name.toLowerCase());
    if (!file || file.kind !== "text") continue;
    const contents = redactSource(await readVerifiedText(root, file));
    sections.push(`--- ${file.path} ---\n${contents}`);
    if (sections.join("\n\n").length >= MAX_PURPOSE_CHARACTERS) break;
  }
  return sections.join("\n\n").slice(0, MAX_PURPOSE_CHARACTERS);
}

function verifiedHistoricalText(source: HistoricalEvidenceSource) {
  const contents = Buffer.from(source.content, "utf8");
  const sha256 = createHash("sha256").update(contents).digest("hex");
  if (contents.byteLength !== source.bytes || sha256 !== source.sha256) {
    throw new Error(
      `Historical evidence changed after extraction: ${source.path}`,
    );
  }
  return redactSource(source.content);
}

export async function buildEvidenceContextGroups({
  checkoutRoot,
  target,
  projectKinds,
  findings,
  inventory,
  historicalSources = [],
}: BuildEvidenceContextGroupsInput): Promise<EvidenceContextGroup[]> {
  const inventoryByPath = new Map(
    inventory.files.map((file) => [file.path, file]),
  );
  const historicalByIdentity = new Map(
    historicalSources.map((source) => [
      `${source.evidence_sha}:${source.path}`,
      source,
    ]),
  );
  if (historicalByIdentity.size !== historicalSources.length) {
    throw new Error("Historical evidence sources must be unique.");
  }
  const findingsByScope = new Map<string, Finding[]>();
  for (const finding of findings) {
    const evidenceSha =
      finding.evidence_sha === target.target_sha ? null : finding.evidence_sha;
    const identity = `${evidenceSha ?? "current"}:${finding.path}`;
    const group = findingsByScope.get(identity) ?? [];
    group.push(finding);
    findingsByScope.set(identity, group);
  }
  const purpose = await projectPurpose(checkoutRoot, inventory);
  const groups: EvidenceContextGroup[] = [];
  for (const [, pathFindings] of [...findingsByScope].sort(([left], [right]) =>
    left.localeCompare(right),
  )) {
    const firstFinding = pathFindings[0]!;
    const path = firstFinding.path;
    const evidenceSha =
      firstFinding.evidence_sha === target.target_sha
        ? null
        : firstFinding.evidence_sha;
    let source: string;
    if (evidenceSha === null) {
      const file = inventoryByPath.get(path);
      if (!file)
        throw new Error(`Evidence path is absent from inventory: ${path}`);
      source = redactSource(await readVerifiedText(checkoutRoot, file));
    } else {
      const historical = historicalByIdentity.get(`${evidenceSha}:${path}`);
      if (!historical)
        throw new Error(
          `Historical evidence source is unavailable: ${evidenceSha}:${path}`,
        );
      source = verifiedHistoricalText(historical);
    }
    for (const scopedFindings of coherentFindingGroups(pathFindings)) {
      const orderedFindings = [...scopedFindings].sort((left, right) =>
        left.fingerprint.localeCompare(right.fingerprint),
      );
      const candidates = orderedFindings.map((finding) => ({
        candidate_id: finding.fingerprint,
        evidence_id: finding.fingerprint,
        origin: finding.origin,
        rule_id: finding.rule_id,
        category: finding.category,
        scanner_severity: finding.severity,
        scanner_confidence: finding.confidence,
        title: finding.title,
        explanation: finding.explanation,
        line_start: finding.line_start,
        line_end: finding.line_end,
      }));
      groups.push({
        group_id: digest([
          target.source_id,
          target.target_sha,
          evidenceSha,
          path,
          candidates.map((candidate) => candidate.candidate_id),
        ]),
        repository: target.repository,
        project_kinds: [...projectKinds].sort(),
        path,
        file_role: classifyFileRole(path),
        target_sha: target.target_sha,
        evidence_sha: evidenceSha ?? target.target_sha,
        ecosystem_context_version: ECOSYSTEM_CONTEXT_VERSION,
        ecosystem_context: ecosystemContext(),
        candidates,
        context: {
          imports: importContext(source),
          source: sourceWindows(source, orderedFindings),
          project_purpose: purpose,
        },
      });
    }
  }
  return groups;
}
