import { z } from "zod";
import { isAbsolute, relative, resolve, sep } from "node:path";

import {
  ConfidenceSchema,
  SeveritySchema,
  type Confidence,
  type Severity,
} from "../contracts/reports.js";
import {
  restrictedEnvironment,
  type CommandRunner,
} from "../process/command-runner.js";
import {
  normalizeFinding,
  ScannerError,
  scannerExecutionError,
  type ScannerRun,
  type ScannerDiagnostic,
} from "./types.js";

const MetadataSchema = z.looseObject({
  tavernkeeper_category: z.string().regex(/^[a-z0-9][a-z0-9-]{0,79}$/u),
  tavernkeeper_severity: SeveritySchema,
  tavernkeeper_confidence: ConfidenceSchema,
  tavernkeeper_title: z.string().min(1).max(200),
});
const OpenGrepFindingSchema = z.looseObject({
  check_id: z.string().min(1).max(120),
  path: z.string().min(1).max(2_000),
  start: z.looseObject({ line: z.number().int().positive() }),
  end: z.looseObject({ line: z.number().int().positive() }),
  extra: z.looseObject({ metadata: MetadataSchema }),
});
const OpenGrepDiagnosticSchema = z.looseObject({
  code: z.number().int(),
  level: z.string(),
  type: z.unknown(),
});
const OpenGrepReportSchema = z.looseObject({
  results: z.array(OpenGrepFindingSchema).max(100_000),
  errors: z.array(z.unknown()).max(10_000),
  paths: z
    .looseObject({
      scanned: z.array(z.string()).max(500_000).default([]),
      skipped: z.array(z.unknown()).max(500_000).default([]),
    })
    .optional(),
});
const OpenGrepSkippedPathSchema = z.looseObject({
  path: z.string().min(1).max(2_000),
  reason: z.string().min(1).max(500),
});

function skippedReason(value: string) {
  const normalized = value.toLowerCase().replace(/[^a-z0-9]+/gu, "_");
  if (
    ["too_big", "exceeded_size_limit"].includes(normalized) ||
    /size|too_large|max_target/iu.test(normalized)
  )
    return "target-limit" as const;
  if (/parse|syntax|analysis_failed/iu.test(normalized))
    return "parse" as const;
  if (/timeout/iu.test(normalized)) return "timeout" as const;
  if (
    /unsupported|wrong_language|irrelevant_rule|minified|too_many_matches|binary/iu.test(
      normalized,
    )
  )
    return "unsupported" as const;
  throw new Error("OpenGrep returned an unknown skipped-path reason.");
}

function isToleratedParserWarning(value: unknown) {
  const parsed = OpenGrepDiagnosticSchema.safeParse(value);
  if (!parsed.success || parsed.data.level !== "warn") return false;
  if (parsed.data.code === 2) return parsed.data.type === "Other syntax error";
  return (
    parsed.data.code === 3 &&
    Array.isArray(parsed.data.type) &&
    parsed.data.type[0] === "PartialParsing"
  );
}

function coverageLimitation(value: unknown): ScannerDiagnostic | undefined {
  const parsed = OpenGrepDiagnosticSchema.safeParse(value);
  if (!parsed.success || parsed.data.level !== "warn") return undefined;
  if (parsed.data.code === 3 && parsed.data.type === "Syntax error")
    return "parser_syntax";
  if (parsed.data.code === 2 && parsed.data.type === "Timeout")
    return "rule_timeout";
  return undefined;
}

function failureDiagnostic(errors: unknown[]): ScannerDiagnostic | undefined {
  const types = errors.flatMap((value) => {
    const parsed = OpenGrepDiagnosticSchema.safeParse(value);
    return parsed.success && typeof parsed.data.type === "string"
      ? [parsed.data.type]
      : [];
  });
  if (types.includes("Syntax error")) return "parser_syntax";
  if (types.includes("Timeout")) return "rule_timeout";
  return undefined;
}

function normalizePath(root: string, value: string) {
  const repositoryRoot = resolve(root);
  const candidate = isAbsolute(value)
    ? resolve(value)
    : resolve(repositoryRoot, value);
  const repositoryPath = relative(repositoryRoot, candidate);
  if (
    !repositoryPath ||
    isAbsolute(repositoryPath) ||
    repositoryPath === ".." ||
    repositoryPath.startsWith(`..${sep}`)
  )
    throw new Error("OpenGrep returned a path outside the repository root.");
  return repositoryPath.split(sep).join("/");
}

function cleanText(value: string, maxLength: number) {
  return value
    .replace(/[\u0000-\u001f\u007f]/gu, " ")
    .trim()
    .slice(0, maxLength);
}

function schemaIssueLocations(error: z.ZodError) {
  const locations = [
    ...new Set(
      error.issues.map(({ path }) =>
        path.length === 0 ? "root" : path.slice(0, 4).join("."),
      ),
    ),
  ];
  return locations.slice(0, 5).join(", ");
}

function safeReportFailureDetail(error: unknown) {
  if (error instanceof z.ZodError)
    return `OpenGrep report schema mismatch at ${schemaIssueLocations(error)}.`;
  if (error instanceof ScannerError) return error.message;
  if (error instanceof Error && error.message.startsWith("OpenGrep "))
    return error.message;
  return "OpenGrep output violated a bounded adapter invariant.";
}

function boundedJsonObject(value: string, start: number) {
  let depth = 0;
  let inString = false;
  let escaped = false;
  for (let index = start; index < value.length; index += 1) {
    const character = value[index];
    if (inString) {
      if (escaped) escaped = false;
      else if (character === "\\") escaped = true;
      else if (character === '"') inString = false;
      continue;
    }
    if (character === '"') inString = true;
    else if (character === "{") depth += 1;
    else if (character === "}") {
      depth -= 1;
      if (depth === 0) return value.slice(start, index + 1);
      if (depth < 0) return undefined;
    }
  }
  return undefined;
}

function decodeReport(stdout: string) {
  let schemaError: z.ZodError | undefined;
  try {
    const parsed = OpenGrepReportSchema.safeParse(JSON.parse(stdout.trim()));
    if (parsed.success) return parsed.data;
    schemaError = parsed.error;
  } catch {
    // A bounded extraction below handles trusted scanner console noise.
  }
  const starts: number[] = [];
  if (stdout.startsWith("{")) starts.push(0);
  let cursor = stdout.indexOf("\n{");
  while (cursor >= 0 && starts.length < 100) {
    starts.push(cursor + 1);
    cursor = stdout.indexOf("\n{", cursor + 2);
  }
  const reports: Array<z.infer<typeof OpenGrepReportSchema>> = [];
  for (const start of starts) {
    const candidate = boundedJsonObject(stdout, start);
    if (candidate === undefined) continue;
    let decoded: unknown;
    try {
      decoded = JSON.parse(candidate);
    } catch {
      continue;
    }
    const parsed = OpenGrepReportSchema.safeParse(decoded);
    if (parsed.success) reports.push(parsed.data);
    else schemaError ??= parsed.error;
  }
  if (reports.length === 1) return reports[0]!;
  if (reports.length > 1)
    throw new ScannerError(
      "MALFORMED_SCANNER_OUTPUT",
      "system",
      "OpenGrep returned multiple JSON reports.",
      "opengrep",
    );
  if (schemaError !== undefined)
    throw new ScannerError(
      "MALFORMED_SCANNER_OUTPUT",
      "system",
      `OpenGrep report schema mismatch at ${schemaIssueLocations(schemaError)}.`,
      "opengrep",
    );
  throw new ScannerError(
    "MALFORMED_SCANNER_OUTPUT",
    "system",
    "OpenGrep returned malformed JSON output.",
    "opengrep",
  );
}

function parseReport(
  root: string,
  stdout: string,
  exitCode: number,
  expectedPaths: readonly string[] | undefined,
) {
  const report = decodeReport(stdout);
  const hasOnlyRecognizedDiagnostics = report.errors.every(
    (error) =>
      isToleratedParserWarning(error) ||
      coverageLimitation(error) !== undefined,
  );
  const hasWarningBackedExit =
    exitCode === 0 ||
    ((exitCode === 2 || exitCode === 3) && report.errors.length > 0);
  if (!hasWarningBackedExit || !hasOnlyRecognizedDiagnostics)
    throw new ScannerError(
      "SCANNER_FAILED",
      "system",
      "OpenGrep reported scan errors.",
      "opengrep",
      failureDiagnostic(report.errors),
    );
  try {
    const findings = report.results
      .map((value) => {
        const metadata = value.extra.metadata;
        return normalizeFinding({
          origin: "opengrep",
          ruleId: cleanText(value.check_id, 120),
          category: metadata.tavernkeeper_category,
          severity: metadata.tavernkeeper_severity as Severity,
          confidence: metadata.tavernkeeper_confidence as Confidence,
          path: normalizePath(root, value.path),
          lineStart: value.start.line,
          lineEnd: value.end.line,
          evidenceSha: null,
          title: cleanText(metadata.tavernkeeper_title, 200),
          explanation:
            "OpenGrep matched a committed TavernKeeper security rule; source excerpts were removed.",
        });
      })
      .sort((left, right) => left.fingerprint.localeCompare(right.fingerprint));
    const limitations = [
      ...new Set(
        report.errors.flatMap((error) => {
          const limitation = coverageLimitation(error);
          return limitation === undefined ? [] : [limitation];
        }),
      ),
    ].sort();
    if (expectedPaths !== undefined && report.paths === undefined)
      throw new Error("OpenGrep omitted expected path coverage.");
    const reportedScanned = (report.paths?.scanned ?? []).map((path) =>
      normalizePath(root, path),
    );
    const reportedSkipped = (report.paths?.skipped ?? []).map((value) => {
      const parsed = OpenGrepSkippedPathSchema.parse(value);
      return {
        path: normalizePath(root, parsed.path),
        reason: skippedReason(parsed.reason),
      };
    });
    const reportedSkippedPaths = reportedSkipped.map(({ path }) => path);
    if (
      new Set(reportedScanned).size !== reportedScanned.length ||
      new Set(reportedSkippedPaths).size !== reportedSkippedPaths.length
    )
      throw new Error("OpenGrep path coverage contains duplicates.");
    let scanned = reportedScanned;
    let skipped = reportedSkipped;
    if (expectedPaths !== undefined) {
      const expected = expectedPaths.map((path) => normalizePath(root, path));
      if (new Set(expected).size !== expected.length)
        throw new Error("OpenGrep expected paths must be unique.");
      const scannedSet = new Set(reportedScanned);
      const skippedByPath = new Map(
        reportedSkipped.map((entry) => [entry.path, entry] as const),
      );
      if (
        expected.some(
          (path) => !scannedSet.has(path) && !skippedByPath.has(path),
        )
      )
        throw new Error("OpenGrep did not account for expected paths.");
      const expectedSet = new Set(expected);
      skipped = reportedSkipped.filter(({ path }) => expectedSet.has(path));
      const skippedSet = new Set(skipped.map(({ path }) => path));
      scanned = expected.filter(
        (path) => scannedSet.has(path) && !skippedSet.has(path),
      );
    } else {
      const skippedSet = new Set(reportedSkippedPaths);
      scanned = reportedScanned.filter((path) => !skippedSet.has(path));
    }
    return {
      findings,
      limitations,
      pathCoverage: {
        scanned: [...scanned].sort(),
        skipped: [...skipped].sort((left, right) =>
          `${left.path}\0${left.reason}`.localeCompare(
            `${right.path}\0${right.reason}`,
          ),
        ),
      },
    };
  } catch (error: unknown) {
    throw new ScannerError(
      "MALFORMED_SCANNER_OUTPUT",
      "system",
      `OpenGrep returned an invalid finding identity or location. ${safeReportFailureDetail(error)}`,
      "opengrep",
    );
  }
}

export async function runOpenGrep({
  root,
  rulesRoot,
  runner,
  executable = "opengrep",
  version,
  expectedPaths,
  maxTargetBytes = 268_435_456,
}: {
  root: string;
  rulesRoot: string;
  runner: CommandRunner;
  executable?: string;
  version: string;
  expectedPaths?: readonly string[];
  maxTargetBytes?: number;
}): Promise<ScannerRun> {
  const result = await runner.run(
    executable,
    [
      "scan",
      "--json",
      "--verbose",
      "--disable-version-check",
      "--disable-nosem",
      "--no-git-ignore",
      "--x-ignore-semgrepignore-files",
      "--no-rewrite-rule-ids",
      "--exclude=.git",
      "--no-exclude-minified-files",
      `--max-target-bytes=${maxTargetBytes}`,
      "--config",
      rulesRoot,
      root,
    ],
    {
      cwd: root,
      environment: restrictedEnvironment({
        NO_COLOR: "1",
        SEMGREP_SEND_METRICS: "off",
      }),
      timeoutMs: 600_000,
      maxOutputBytes: 50_000_000,
      shell: false,
    },
  );
  if (!result.ok) throw scannerExecutionError("opengrep", result.error.code);
  if (
    result.value.exitCode !== 0 &&
    result.value.exitCode !== 2 &&
    result.value.exitCode !== 3
  )
    throw new ScannerError(
      "SCANNER_FAILED",
      "system",
      `OpenGrep exited with code ${result.value.exitCode}.`,
      "opengrep",
    );
  const parsed = parseReport(
    root,
    result.value.stdout,
    result.value.exitCode,
    expectedPaths,
  );
  return {
    name: "opengrep",
    version,
    status:
      parsed.limitations.length === 0
        ? "completed"
        : "completed-with-limitations",
    ...(parsed.limitations.length === 0
      ? {}
      : { limitations: parsed.limitations }),
    findings: parsed.findings,
    pathCoverage: parsed.pathCoverage,
  };
}
