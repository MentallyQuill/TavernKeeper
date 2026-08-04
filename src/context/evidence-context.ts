import { createHash } from "node:crypto";
import { readFile } from "node:fs/promises";
import { resolve, sep } from "node:path";

import { z } from "zod";

import type { Target } from "../contracts/targets.js";
import type {
  Inventory,
  InventoryFile,
} from "../inventory/inventory-handler.js";
import type { Finding } from "../contracts/reports.js";
import { redactSource } from "../model/redaction.js";
import {
  restrictedEnvironment,
  type CommandOptions,
  type CommandRunner,
} from "../process/command-runner.js";
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

const DigestSchema = z.string().regex(/^[0-9a-f]{64}$/u);
const FullShaSchema = z.string().regex(/^[0-9a-f]{40}$/u);
const RepositoryPathSchema = z
  .string()
  .min(1)
  .max(500)
  .refine(
    (value) =>
      !value.includes("\\") &&
      !value.startsWith("/") &&
      !/^[A-Za-z]:/u.test(value) &&
      value.split("/").every((part) => !["", ".", ".."].includes(part)),
  );
const FileRoleSchema = z.enum([
  "production",
  "test",
  "fixture",
  "documentation",
  "tooling",
  "generated",
  "vendored",
  "unknown",
]);

export const EvidenceCandidateSchema = z.strictObject({
  candidate_id: DigestSchema,
  evidence_id: DigestSchema,
  origin: z.string().regex(/^[a-z0-9][a-z0-9:_-]{0,79}$/u),
  rule_id: z.string().min(1).max(120),
  category: z.string().regex(/^[a-z0-9][a-z0-9-]{0,79}$/u),
  scanner_severity: z.enum(["critical", "high", "medium", "low", "info"]),
  scanner_confidence: z.enum(["high", "medium", "low"]),
  title: z.string().trim().min(1).max(200),
  explanation: z.string().trim().min(1).max(1_000),
  line_start: z.number().int().positive().nullable(),
  line_end: z.number().int().positive().nullable(),
});

export const EvidenceContextGroupSchema = z.strictObject({
  group_id: DigestSchema,
  repository: z.string().regex(/^[^/\s]+\/[^/\s]+$/u),
  project_kinds: z.array(z.enum(["extension", "frontend", "preset"])).min(1),
  path: RepositoryPathSchema,
  file_role: FileRoleSchema,
  target_sha: FullShaSchema,
  evidence_sha: FullShaSchema,
  source_bytes: z.number().int().nonnegative(),
  source_sha256: DigestSchema,
  ecosystem_context_version: z.literal("sillytavern-community-v1"),
  ecosystem_context: z.string().min(1),
  candidates: z.array(EvidenceCandidateSchema).min(1).max(64),
  context: z.strictObject({
    imports: z.string(),
    source: z.string().min(1),
    project_purpose: z.string(),
  }),
});

export const EvidenceContextGroupsSchema = z.array(EvidenceContextGroupSchema);
export type EvidenceCandidate = z.infer<typeof EvidenceCandidateSchema>;
export type EvidenceContextGroup = z.infer<typeof EvidenceContextGroupSchema>;

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

const nullDevice = process.platform === "win32" ? "NUL" : "/dev/null";

function evidenceGitOptions(
  cwd: string,
  maxOutputBytes: number,
): CommandOptions {
  return {
    cwd,
    environment: restrictedEnvironment({
      GIT_CONFIG_NOSYSTEM: "1",
      GIT_CONFIG_GLOBAL: nullDevice,
      GIT_LFS_SKIP_SMUDGE: "1",
      GIT_TERMINAL_PROMPT: "0",
      GIT_PROTOCOL_FROM_USER: "0",
    }),
    timeoutMs: 120_000,
    maxOutputBytes,
    shell: false,
  };
}

async function historicalSource(
  checkoutRoot: string,
  evidenceSha: string,
  path: string,
  runner: CommandRunner,
  maxOutputBytes: number,
) {
  const result = await runner.run(
    "git",
    ["show", "--no-ext-diff", "--no-textconv", `${evidenceSha}:${path}`],
    evidenceGitOptions(resolve(checkoutRoot), maxOutputBytes),
  );
  if (
    !result.ok ||
    result.value.exitCode !== 0 ||
    result.value.stdout.includes("\0")
  )
    throw new Error(
      "Historical evidence source could not be extracted safely.",
    );
  return result.value.stdout;
}

export async function extractHistoricalEvidenceSources({
  checkoutRoot,
  targetSha,
  findings,
  runner,
  maxFileBytes,
}: {
  checkoutRoot: string;
  targetSha: string;
  findings: readonly Finding[];
  runner: CommandRunner;
  maxFileBytes: number;
}): Promise<HistoricalEvidenceSource[]> {
  const identities = new Map<string, { evidenceSha: string; path: string }>();
  for (const finding of findings) {
    if (finding.evidence_sha === null || finding.evidence_sha === targetSha)
      continue;
    identities.set(`${finding.evidence_sha}:${finding.path}`, {
      evidenceSha: finding.evidence_sha,
      path: finding.path,
    });
  }
  const sources: HistoricalEvidenceSource[] = [];
  for (const { evidenceSha, path } of [...identities.values()].sort(
    (left, right) =>
      `${left.evidenceSha}:${left.path}`.localeCompare(
        `${right.evidenceSha}:${right.path}`,
      ),
  )) {
    const content = await historicalSource(
      checkoutRoot,
      evidenceSha,
      path,
      runner,
      maxFileBytes,
    );
    const bytes = Buffer.byteLength(content);
    if (bytes > maxFileBytes)
      throw new Error("Historical evidence source exceeds the file ceiling.");
    sources.push({
      path,
      evidence_sha: evidenceSha,
      content,
      bytes,
      sha256: createHash("sha256").update(content).digest("hex"),
    });
  }
  return sources;
}

export async function loadEvidenceSourceFromCheckout({
  checkoutRoot,
  group: groupInput,
  runner,
}: {
  checkoutRoot: string;
  group: EvidenceContextGroup;
  runner: CommandRunner;
}) {
  const group = EvidenceContextGroupSchema.parse(groupInput);
  if (group.evidence_sha === group.target_sha) {
    const contents = await readFile(
      absoluteInventoryPath(checkoutRoot, group.path),
    );
    return contents.toString("utf8");
  }
  return historicalSource(
    checkoutRoot,
    group.evidence_sha,
    group.path,
    runner,
    group.source_bytes + 1,
  );
}

const PURPOSE_FILES = [
  "README.md",
  "README.txt",
  "package.json",
  "manifest.json",
];
const SOURCE_CONTEXT_LINES = 40;
const MAX_CANDIDATES_PER_GROUP = 8;
const MAX_PURPOSE_CHARACTERS = 8_000;
const MAX_IMPORT_CHARACTERS = 4_000;

export class EvidenceContextError extends Error {
  readonly code = "EVIDENCE_CONTEXT_UNSUPPORTED";
  readonly scope = "repository";
  readonly component = "evidence-context";
  readonly diagnostic = "evidence_non_text";

  constructor() {
    super("A scanner finding requires unsupported non-text evidence context.");
    this.name = "EvidenceContextError";
  }
}

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
  if (file.kind !== "text") throw new EvidenceContextError();
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

function sourceWindows(
  source: string,
  findings: readonly Pick<Finding, "line_start" | "line_end">[],
  contextLines = SOURCE_CONTEXT_LINES,
) {
  const lines = source.split(/\r?\n/u);
  const ranges = findings
    .map((finding) => {
      const lineStart = finding.line_start ?? 1;
      const lineEnd = finding.line_end ?? lineStart;
      return {
        start: Math.max(1, lineStart - contextLines),
        end: Math.min(lines.length, lineEnd + contextLines),
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
    let sourceBytes: number;
    let sourceSha256: string;
    if (evidenceSha === null) {
      const file = inventoryByPath.get(path);
      if (!file)
        throw new Error(`Evidence path is absent from inventory: ${path}`);
      source = redactSource(await readVerifiedText(checkoutRoot, file));
      sourceBytes = file.bytes;
      sourceSha256 = file.sha256;
    } else {
      const historical = historicalByIdentity.get(`${evidenceSha}:${path}`);
      if (!historical)
        throw new Error(
          `Historical evidence source is unavailable: ${evidenceSha}:${path}`,
        );
      source = verifiedHistoricalText(historical);
      sourceBytes = historical.bytes;
      sourceSha256 = historical.sha256;
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
        source_bytes: sourceBytes,
        source_sha256: sourceSha256,
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
  return EvidenceContextGroupsSchema.parse(groups);
}

export function expandEvidenceContextGroup(
  groupInput: EvidenceContextGroup,
  source: string,
  attempt: number,
): EvidenceContextGroup {
  const group = EvidenceContextGroupSchema.parse(groupInput);
  if (!Number.isInteger(attempt) || attempt < 1 || attempt > 5)
    throw new Error("Evidence context expansion attempt is invalid.");
  const contents = Buffer.from(source, "utf8");
  if (
    contents.byteLength !== group.source_bytes ||
    createHash("sha256").update(contents).digest("hex") !== group.source_sha256
  )
    throw new Error("Evidence source changed before context expansion.");
  const redacted = redactSource(source);
  return EvidenceContextGroupSchema.parse({
    ...group,
    context: {
      ...group.context,
      imports: importContext(redacted),
      source: sourceWindows(
        redacted,
        group.candidates,
        SOURCE_CONTEXT_LINES * 4 ** attempt,
      ),
    },
  });
}
