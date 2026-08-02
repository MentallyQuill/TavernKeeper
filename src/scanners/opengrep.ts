import { z } from "zod";

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
const OpenGrepReportSchema = z.looseObject({
  results: z.array(OpenGrepFindingSchema).max(100_000),
  errors: z.array(z.unknown()).max(10_000),
});

function normalizePath(value: string) {
  return value.replaceAll("\\", "/").replace(/^\.\//u, "");
}

function cleanText(value: string, maxLength: number) {
  return value
    .replace(/[\u0000-\u001f\u007f]/gu, " ")
    .trim()
    .slice(0, maxLength);
}

function parseReport(stdout: string) {
  let report: z.infer<typeof OpenGrepReportSchema>;
  try {
    report = OpenGrepReportSchema.parse(JSON.parse(stdout));
  } catch {
    throw new ScannerError(
      "MALFORMED_SCANNER_OUTPUT",
      "system",
      "OpenGrep returned malformed JSON output.",
      "opengrep",
    );
  }
  if (report.errors.length > 0)
    throw new ScannerError(
      "SCANNER_FAILED",
      "system",
      "OpenGrep reported scan errors.",
      "opengrep",
    );
  try {
    return report.results
      .map((value) => {
        const metadata = value.extra.metadata;
        return normalizeFinding({
          origin: "opengrep",
          ruleId: cleanText(value.check_id, 120),
          category: metadata.tavernkeeper_category,
          severity: metadata.tavernkeeper_severity as Severity,
          confidence: metadata.tavernkeeper_confidence as Confidence,
          path: normalizePath(value.path),
          lineStart: value.start.line,
          lineEnd: value.end.line,
          evidenceSha: null,
          title: cleanText(metadata.tavernkeeper_title, 200),
          explanation:
            "OpenGrep matched a committed TavernKeeper security rule; source excerpts were removed.",
        });
      })
      .sort((left, right) => left.fingerprint.localeCompare(right.fingerprint));
  } catch {
    throw new ScannerError(
      "MALFORMED_SCANNER_OUTPUT",
      "system",
      "OpenGrep returned an invalid finding identity or location.",
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
}: {
  root: string;
  rulesRoot: string;
  runner: CommandRunner;
  executable?: string;
  version: string;
}): Promise<ScannerRun> {
  const result = await runner.run(
    executable,
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
  if (result.value.exitCode !== 0)
    throw new ScannerError(
      "SCANNER_FAILED",
      "system",
      `OpenGrep exited with code ${result.value.exitCode}.`,
      "opengrep",
    );
  return {
    name: "opengrep",
    version,
    status: "completed",
    findings: parseReport(result.value.stdout),
  };
}
