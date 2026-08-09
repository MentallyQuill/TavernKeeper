import { createHash } from "node:crypto";
import { mkdir, mkdtemp, readFile, rm, writeFile } from "node:fs/promises";
import { isAbsolute, join, relative, resolve, sep } from "node:path";

import { AstAnalyser, type Warning } from "@nodesecure/js-x-ray";

import type { ScannerPolicyV4 } from "../config/policy.js";
import type { Finding } from "../contracts/reports.js";
import type { InventoryFile } from "../inventory/inventory-handler.js";
import type { CommandRunner } from "../process/command-runner.js";
import {
  JavascriptAnalysisCoverageSchema,
  type JavaScriptEvidenceHint,
  type JavascriptAnalysisCoverage,
  type JavascriptDerivativeAncestry,
  type JavascriptRepresentation,
  type JavascriptUnresolved,
} from "./javascript-analysis-types.js";
import {
  selectJavascriptCandidates,
  type JavascriptCandidate,
} from "./javascript-candidates.js";
import { decodeJavascriptLiterals } from "./javascript-literals.js";
import {
  normalizeJavascript,
  type JavascriptNormalizationLimitation,
} from "./javascript-normalizer.js";
import { runOpenGrep } from "./opengrep.js";
import { scanJavascriptSignatures } from "./javascript-signatures.js";
import {
  normalizeFinding,
  ScannerError,
  type ScannerPathCoverage,
  type ScannerRun,
} from "./types.js";

export const JAVASCRIPT_ANALYSIS_VERSION =
  "webcrack-2.16.0_js-x-ray-16.0.0_signatures-1_literals-1";

interface AstAnalysisResult {
  warnings: Warning[];
}

export interface JavascriptAnalysisDependencies {
  normalize: typeof normalizeJavascript;
  openGrep: typeof runOpenGrep;
  analyzeAst(
    source: string,
    path: string,
    minified: boolean,
  ): AstAnalysisResult;
}

export interface JavascriptAnalysisSpec {
  root: string;
  inventoryFiles: readonly InventoryFile[];
  rawOpenGrepCoverage: ScannerPathCoverage;
  runner: CommandRunner;
  rulesRoot: string;
  policy: ScannerPolicyV4;
  temporaryRoot: string;
  opengrepVersion: string;
  opengrepExecutable?: string;
}

interface QueuedRepresentation {
  candidate: JavascriptCandidate;
  representation: JavascriptRepresentation;
  content: string;
}

const analyser = new AstAnalyser({ sensitivity: "aggressive" });
const defaultDependencies: JavascriptAnalysisDependencies = {
  normalize: normalizeJavascript,
  openGrep: runOpenGrep,
  analyzeAst: (source, path, minified) =>
    analyser.analyse(source, { location: path, isMinified: minified }),
};

function digest(source: string | Buffer) {
  return createHash("sha256").update(source).digest("hex");
}

function safeRepositoryPath(root: string, path: string) {
  const repositoryRoot = resolve(root);
  const absolute = resolve(repositoryRoot, path);
  const repositoryPath = relative(repositoryRoot, absolute);
  if (
    isAbsolute(path) ||
    !repositoryPath ||
    isAbsolute(repositoryPath) ||
    repositoryPath === ".." ||
    repositoryPath.startsWith(`..${sep}`)
  )
    throw new ScannerError(
      "SCANNER_FAILED",
      "system",
      "JavaScript analysis received an unsafe repository path.",
      "javascript-analysis",
    );
  return { absolute, repositoryPath: repositoryPath.split(sep).join("/") };
}

function unresolvedIdentity(value: JavascriptUnresolved) {
  return `${value.path}\u0000${value.stage}\u0000${value.reason}\u0000${value.recovered}`;
}

function warningLocation(location: Warning["location"]) {
  if (location === null) return null;
  const first = Array.isArray(location[0]?.[0]) ? location[0] : location;
  if (
    !Array.isArray(first) ||
    !Array.isArray(first[0]) ||
    !Array.isArray(first[1])
  )
    return null;
  const start = first[0] as [number, number];
  const end = first[1] as [number, number];
  return {
    lineStart: Math.max(1, start[0]),
    lineEnd: Math.max(1, end[0]),
    columnStart: Math.max(1, start[1] + 1),
    columnEnd: Math.max(1, end[1] + 1),
  };
}

function warningCategory(kind: string) {
  if (/exfiltration|serialize-environment/iu.test(kind))
    return "credential-theft";
  if (/unsafe-(?:stmt|command|vm)|prototype-pollution/iu.test(kind))
    return "code-execution";
  if (/obfuscat|encoded|suspicious|short-identifiers/iu.test(kind))
    return "obfuscation";
  if (/link|network/iu.test(kind)) return "network-access";
  return "supply-chain-risk";
}

function safeWarningRule(kind: string) {
  const suffix = kind
    .toLowerCase()
    .replace(/[^a-z0-9._-]+/gu, "-")
    .replace(/^[^a-z0-9]+/u, "")
    .slice(0, 80);
  if (suffix.length === 0)
    throw new ScannerError(
      "MALFORMED_SCANNER_OUTPUT",
      "system",
      "JS-X-Ray returned an unsafe warning identity.",
      "javascript-analysis",
    );
  return `javascript.xray.${suffix}`;
}

function scanAst(
  queued: QueuedRepresentation,
  dependencies: JavascriptAnalysisDependencies,
) {
  const report = dependencies.analyzeAst(
    queued.content,
    queued.candidate.path,
    queued.candidate.likelyMinified === true,
  );
  const parseFailed = report.warnings.some(
    ({ kind }) => kind === "parsing-error",
  );
  const findings: Finding[] = [];
  const evidenceHints: JavaScriptEvidenceHint[] = [];
  for (const warning of report.warnings) {
    if (warning.kind === "parsing-error") continue;
    const location = warningLocation(warning.location);
    const ruleId = safeWarningRule(warning.kind);
    const finding = normalizeFinding({
      origin: "javascript-analysis",
      ruleId,
      category: warningCategory(warning.kind),
      severity:
        warning.severity === "Critical"
          ? "high"
          : warning.severity === "Warning"
            ? "medium"
            : "low",
      confidence: warning.experimental === true ? "low" : "medium",
      path: queued.candidate.path,
      lineStart: location?.lineStart ?? null,
      lineEnd: location?.lineEnd ?? null,
      evidenceSha: null,
      title: `Static JavaScript signal: ${warning.kind}`,
      explanation:
        "JS-X-Ray identified a fixed security signal in this JavaScript representation; matched literal values were not retained.",
      remediation:
        "Review the affected behavior and remove unsafe or unnecessary dynamic capabilities.",
    });
    findings.push(finding);
    evidenceHints.push({
      finding_fingerprint: finding.fingerprint,
      original_path: queued.candidate.path,
      stage: queued.representation.stage,
      representation_sha256: queued.representation.sha256,
      transform_depth: queued.representation.depth,
      line_start: location?.lineStart ?? null,
      line_end: location?.lineEnd ?? null,
      column_start: location?.columnStart ?? null,
      column_end: location?.columnEnd ?? null,
      source: queued.content,
    });
  }
  return { parseFailed, findings, evidenceHints };
}

function mapNormalizationReason(
  reason: JavascriptNormalizationLimitation,
): JavascriptUnresolved["reason"] {
  return reason;
}

function addUniqueFinding(target: Map<string, Finding>, finding: Finding) {
  target.set(finding.fingerprint, finding);
}

function addUniqueHint(
  target: Map<string, JavaScriptEvidenceHint>,
  hint: JavaScriptEvidenceHint,
) {
  target.set(
    `${hint.finding_fingerprint}\u0000${hint.representation_sha256}`,
    hint,
  );
}

function validateRawCoverage(
  candidates: readonly JavascriptCandidate[],
  coverage: ScannerPathCoverage,
) {
  const expected = candidates.map(({ path }) => path);
  const accounted = [
    ...coverage.scanned,
    ...coverage.skipped.map(({ path }) => path),
  ];
  if (
    new Set(accounted).size !== accounted.length ||
    accounted.length !== expected.length ||
    expected.some((path) => !accounted.includes(path)) ||
    accounted.some((path) => !expected.includes(path))
  )
    throw new ScannerError(
      "MALFORMED_SCANNER_OUTPUT",
      "system",
      "Repository OpenGrep coverage does not match JavaScript candidates.",
      "javascript-analysis",
    );
}

export async function runJavascriptAnalysis(
  spec: JavascriptAnalysisSpec,
  overrides: Partial<JavascriptAnalysisDependencies> = {},
): Promise<ScannerRun> {
  const dependencies = { ...defaultDependencies, ...overrides };
  const limits = spec.policy.javascriptAnalysis;
  const candidates = selectJavascriptCandidates(spec.inventoryFiles);
  validateRawCoverage(candidates, spec.rawOpenGrepCoverage);
  const candidateBytes = candidates.reduce(
    (total, file) => total + file.bytes,
    0,
  );
  const unresolved = new Map<string, JavascriptUnresolved>();
  const findings = new Map<string, Finding>();
  const evidenceHints = new Map<string, JavaScriptEvidenceHint>();
  const ancestry = new Map<string, JavascriptDerivativeAncestry>();
  const representationSources = new Map<string, QueuedRepresentation>();
  const queue: QueuedRepresentation[] = [];
  const seenByPath = new Map<string, Set<string>>();
  const derivativeCountByPath = new Map<string, number>();
  const derivativeBytesByPath = new Map<string, number>();
  let totalDerivativeBytes = 0;
  const startedAt = Date.now();
  const representationCounts = {
    raw: candidates.length,
    decoded: 0,
    normalized: 0,
    bundle_modules: 0,
  };
  const stageCounts = {
    raw_signatures: 0,
    raw_ast: 0,
    raw_opengrep: spec.rawOpenGrepCoverage.scanned.length,
    derived_signatures: 0,
    derived_ast: 0,
    derived_opengrep: 0,
  };
  const addUnresolved = (value: JavascriptUnresolved) =>
    unresolved.set(unresolvedIdentity(value), value);

  for (const skipped of spec.rawOpenGrepCoverage.skipped)
    addUnresolved({
      path: skipped.path,
      stage: "raw-opengrep",
      reason: skipped.reason,
      recovered: false,
    });

  let acceptedCandidateBytes = 0;
  for (const [index, candidate] of candidates.entries()) {
    const withinCandidateBudget =
      index < limits.maxCandidates &&
      acceptedCandidateBytes + candidate.bytes <= limits.maxCandidateBytes;
    if (!withinCandidateBudget) {
      for (const stage of ["raw-signatures", "raw-ast"] as const)
        addUnresolved({
          path: candidate.path,
          stage,
          reason: "candidate-limit",
          recovered: false,
        });
      continue;
    }
    acceptedCandidateBytes += candidate.bytes;
    if (candidate.kind !== "text") {
      const reason = candidate.kind === "binary" ? "binary" : "input-limit";
      for (const stage of [
        "raw-signatures",
        "raw-ast",
        "literal-decode",
        ...(candidate.requiresNormalization ? (["normalize"] as const) : []),
      ] as const)
        addUnresolved({
          path: candidate.path,
          stage,
          reason,
          recovered: false,
        });
      continue;
    }
    const { absolute } = safeRepositoryPath(spec.root, candidate.path);
    const bytes = await readFile(absolute);
    if (bytes.length !== candidate.bytes || digest(bytes) !== candidate.sha256)
      throw new ScannerError(
        "SCANNER_FAILED",
        "system",
        "JavaScript candidate changed after repository inventory.",
        "javascript-analysis",
      );
    let content: string;
    try {
      content = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch {
      for (const stage of ["raw-signatures", "raw-ast"] as const)
        addUnresolved({
          path: candidate.path,
          stage,
          reason: "invalid-utf8",
          recovered: false,
        });
      continue;
    }
    const representation: JavascriptRepresentation = {
      stage: "raw",
      sha256: candidate.sha256,
      parentSha256: null,
      transform: "original",
      depth: 0,
    };
    seenByPath.set(candidate.path, new Set([candidate.sha256]));
    const queued = { candidate, representation, content };
    queue.push(queued);
    representationSources.set(
      `${candidate.path}\u0000${candidate.sha256}`,
      queued,
    );
    ancestry.set(`${candidate.path}\u0000${candidate.sha256}`, {
      original_path: candidate.path,
      stage: "raw",
      representation_sha256: candidate.sha256,
      parent_sha256: null,
      transform: "original",
      transform_depth: 0,
    });
  }

  const addDerivative = (
    parent: QueuedRepresentation,
    content: string,
    stage: "decoded" | "normalized" | "bundle-module",
    transform: JavascriptRepresentation["transform"],
    sourceStage: "literal-decode" | "normalize" | "bundle-extract",
  ) => {
    const bytes = Buffer.byteLength(content, "utf8");
    const sha256 = digest(content);
    const seen = seenByPath.get(parent.candidate.path);
    if (seen?.has(sha256) === true) return;
    const count = derivativeCountByPath.get(parent.candidate.path) ?? 0;
    const pathBytes = derivativeBytesByPath.get(parent.candidate.path) ?? 0;
    if (
      bytes > limits.maxDerivativeBytes ||
      count >= limits.maxDerivativesPerCandidate ||
      pathBytes + bytes > limits.maxDerivativeBytesPerCandidate ||
      totalDerivativeBytes + bytes > limits.maxTotalDerivativeBytes
    ) {
      addUnresolved({
        path: parent.candidate.path,
        stage: sourceStage,
        reason: "derivative-limit",
        recovered: false,
      });
      return;
    }
    seen?.add(sha256);
    derivativeCountByPath.set(parent.candidate.path, count + 1);
    derivativeBytesByPath.set(parent.candidate.path, pathBytes + bytes);
    totalDerivativeBytes += bytes;
    const representation: JavascriptRepresentation = {
      stage,
      sha256,
      parentSha256: parent.representation.sha256,
      transform,
      depth: parent.representation.depth + 1,
    };
    const queued = { candidate: parent.candidate, representation, content };
    queue.push(queued);
    representationSources.set(
      `${parent.candidate.path}\u0000${sha256}`,
      queued,
    );
    if (stage === "decoded") representationCounts.decoded += 1;
    else if (stage === "normalized") representationCounts.normalized += 1;
    else representationCounts.bundle_modules += 1;
    ancestry.set(`${parent.candidate.path}\u0000${sha256}`, {
      original_path: parent.candidate.path,
      stage,
      representation_sha256: sha256,
      parent_sha256: parent.representation.sha256,
      transform,
      transform_depth: representation.depth,
    });
  };

  while (queue.length > 0) {
    queue.sort((left, right) =>
      `${left.representation.depth}\u0000${left.representation.sha256}`.localeCompare(
        `${right.representation.depth}\u0000${right.representation.sha256}`,
      ),
    );
    const current = queue.shift();
    if (current === undefined) break;
    const raw = current.representation.stage === "raw";
    if (Date.now() - startedAt > limits.analysisTimeoutMs) {
      addUnresolved({
        path: current.candidate.path,
        stage: raw ? "raw-signatures" : "derived-signatures",
        reason: "timeout",
        recovered: false,
      });
      continue;
    }

    const primitive = scanJavascriptSignatures({
      source: current.content,
      path: current.candidate.path,
      representation: current.representation,
    });
    for (const finding of primitive.findings)
      addUniqueFinding(findings, finding);
    for (const hint of primitive.evidenceHints)
      addUniqueHint(evidenceHints, hint);
    if (raw) stageCounts.raw_signatures += 1;
    else stageCounts.derived_signatures += 1;

    try {
      const ast = scanAst(current, dependencies);
      for (const finding of ast.findings) addUniqueFinding(findings, finding);
      for (const hint of ast.evidenceHints) addUniqueHint(evidenceHints, hint);
      if (ast.parseFailed) {
        addUnresolved({
          path: current.candidate.path,
          stage: raw ? "raw-ast" : "derived-ast",
          reason: "parse",
          recovered: false,
        });
      } else if (raw) stageCounts.raw_ast += 1;
      else stageCounts.derived_ast += 1;
    } catch {
      addUnresolved({
        path: current.candidate.path,
        stage: raw ? "raw-ast" : "derived-ast",
        reason: "parse",
        recovered: false,
      });
    }

    const decoded = decodeJavascriptLiterals({
      source: current.content,
      maxOutputs: limits.maxDecodedLiteralsPerRepresentation,
      maxOutputBytes: limits.maxDerivativeBytes,
    });
    if (current.representation.depth >= limits.maxRecursionDepth) {
      if (decoded.length > 0)
        addUnresolved({
          path: current.candidate.path,
          stage: "literal-decode",
          reason: "recursion-limit",
          recovered: false,
        });
    } else {
      for (const derivative of decoded)
        addDerivative(
          current,
          derivative.content,
          "decoded",
          derivative.transform,
          "literal-decode",
        );
    }

    const shouldNormalize = current.candidate.requiresNormalization || !raw;
    if (!shouldNormalize) continue;
    if (
      Buffer.byteLength(current.content, "utf8") > limits.maxTransformInputBytes
    ) {
      addUnresolved({
        path: current.candidate.path,
        stage: "normalize",
        reason: "input-limit",
        recovered: false,
      });
      continue;
    }
    const normalization = await dependencies.normalize(current.content, limits);
    if (normalization.limitation !== undefined)
      addUnresolved({
        path: current.candidate.path,
        stage: "normalize",
        reason: mapNormalizationReason(normalization.limitation),
        recovered: false,
      });
    const novel = normalization.derivatives.filter(
      ({ content }) =>
        !(
          seenByPath.get(current.candidate.path)?.has(digest(content)) ?? false
        ),
    );
    if (current.representation.depth >= limits.maxRecursionDepth) {
      if (novel.length > 0)
        addUnresolved({
          path: current.candidate.path,
          stage: "normalize",
          reason: "recursion-limit",
          recovered: false,
        });
      continue;
    }
    for (const derivative of novel)
      addDerivative(
        current,
        derivative.content,
        derivative.transform === "webcrack-module"
          ? "bundle-module"
          : "normalized",
        derivative.transform,
        derivative.transform === "webcrack-module"
          ? "bundle-extract"
          : "normalize",
      );
  }

  const derived = [...ancestry.values()]
    .filter(({ stage }) => stage !== "raw")
    .sort((left, right) =>
      `${left.original_path}\u0000${left.transform_depth}\u0000${left.representation_sha256}`.localeCompare(
        `${right.original_path}\u0000${right.transform_depth}\u0000${right.representation_sha256}`,
      ),
    );
  if (derived.length > 0) {
    await mkdir(spec.temporaryRoot, { recursive: true });
    const syntheticRoot = await mkdtemp(
      join(spec.temporaryRoot, "tavernkeeper-js-derived-"),
    );
    try {
      const paths: string[] = [];
      const sources = new Map<string, QueuedRepresentation>();
      for (const [index, ancestor] of derived.entries()) {
        const identity = `${ancestor.original_path}\u0000${ancestor.representation_sha256}`;
        const queued = representationSources.get(identity);
        if (queued === undefined)
          throw new ScannerError(
            "SCANNER_FAILED",
            "system",
            "JavaScript derivative source lost its bound ancestry.",
            "javascript-analysis",
          );
        const path = `derived/${String(index).padStart(6, "0")}.js`;
        await mkdir(join(syntheticRoot, "derived"), { recursive: true });
        await writeFile(join(syntheticRoot, path), queued.content);
        paths.push(path);
        sources.set(path, queued);
      }
      if (paths.length > 0) {
        const run = await dependencies.openGrep({
          root: syntheticRoot,
          rulesRoot: spec.rulesRoot,
          runner: spec.runner,
          version: spec.opengrepVersion,
          expectedPaths: paths,
          maxTargetBytes: limits.maxDerivativeBytes,
          ...(spec.opengrepExecutable === undefined
            ? {}
            : { executable: spec.opengrepExecutable }),
        });
        if (run.pathCoverage === undefined)
          throw new ScannerError(
            "MALFORMED_SCANNER_OUTPUT",
            "system",
            "Derived OpenGrep omitted path coverage.",
            "javascript-analysis",
          );
        stageCounts.derived_opengrep += run.pathCoverage.scanned.length;
        for (const skipped of run.pathCoverage.skipped) {
          const queued = sources.get(skipped.path);
          if (queued === undefined)
            throw new ScannerError(
              "MALFORMED_SCANNER_OUTPUT",
              "system",
              "Derived OpenGrep returned an unknown path.",
              "javascript-analysis",
            );
          addUnresolved({
            path: queued.candidate.path,
            stage: "derived-opengrep",
            reason: skipped.reason,
            recovered: false,
          });
        }
        for (const external of run.findings) {
          const queued = sources.get(external.path);
          if (queued === undefined)
            throw new ScannerError(
              "MALFORMED_SCANNER_OUTPUT",
              "system",
              "Derived OpenGrep finding has an unknown path.",
              "javascript-analysis",
            );
          const finding = normalizeFinding({
            origin: "javascript-analysis",
            ruleId: `javascript.opengrep.${external.rule_id}`,
            category: external.category,
            severity: external.severity,
            confidence: external.confidence,
            path: queued.candidate.path,
            lineStart: external.line_start,
            lineEnd: external.line_end,
            evidenceSha: null,
            title: "Derived JavaScript matched a static security rule",
            explanation:
              "OpenGrep matched a TavernKeeper rule after bounded non-executing JavaScript transformation.",
            ...(external.remediation === undefined
              ? {}
              : { remediation: external.remediation }),
          });
          addUniqueFinding(findings, finding);
          addUniqueHint(evidenceHints, {
            finding_fingerprint: finding.fingerprint,
            original_path: queued.candidate.path,
            stage: queued.representation.stage,
            representation_sha256: queued.representation.sha256,
            transform_depth: queued.representation.depth,
            line_start: external.line_start,
            line_end: external.line_end,
            column_start: null,
            column_end: null,
            source: queued.content,
          });
        }
      }
    } finally {
      await rm(syntheticRoot, { recursive: true, force: true });
    }
  }

  const unresolvedValues = [...unresolved.values()].sort((left, right) =>
    unresolvedIdentity(left).localeCompare(unresolvedIdentity(right)),
  );
  const coverage: JavascriptAnalysisCoverage =
    JavascriptAnalysisCoverageSchema.parse({
      status: unresolvedValues.length === 0 ? "complete" : "incomplete",
      candidates: candidates.length,
      candidate_bytes: candidateBytes,
      representations: representationCounts,
      stages: stageCounts,
      unresolved: unresolvedValues,
    });
  return {
    name: "javascript-analysis",
    version: JAVASCRIPT_ANALYSIS_VERSION,
    status:
      coverage.status === "complete"
        ? "completed"
        : "completed-with-limitations",
    findings: [...findings.values()].sort((left, right) =>
      left.fingerprint.localeCompare(right.fingerprint),
    ),
    javascriptAnalysis: coverage,
    evidenceHints: [...evidenceHints.values()].sort((left, right) =>
      `${left.finding_fingerprint}\u0000${left.representation_sha256}`.localeCompare(
        `${right.finding_fingerprint}\u0000${right.representation_sha256}`,
      ),
    ),
    derivativeAncestry: [...ancestry.values()].sort((left, right) =>
      `${left.original_path}\u0000${left.transform_depth}\u0000${left.representation_sha256}`.localeCompare(
        `${right.original_path}\u0000${right.transform_depth}\u0000${right.representation_sha256}`,
      ),
    ),
  };
}
