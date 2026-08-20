import { join } from "node:path";

import { analyzeReviewOpportunities } from "../analysis/review-opportunities.js";
import {
  renderReviewOpportunitiesJson,
  renderReviewOpportunitiesMarkdown,
} from "../analysis/render-review-opportunities.js";
import {
  isDirectExecution,
  readJsonFile,
  safeCliErrorRecord,
  writeJsonFile,
} from "./io.js";

const usage = "Usage: review-opportunities --format <json|markdown>";

function parseFormat(args: readonly string[]) {
  if (
    args.length !== 2 ||
    args[0] !== "--format" ||
    !["json", "markdown"].includes(args[1] ?? "")
  )
    throw new Error(usage);
  return args[1] as "json" | "markdown";
}

export async function reviewOpportunitiesMain(input: {
  cwd: string;
  args: readonly string[];
}) {
  const format = parseFormat(input.args);
  const index = await readJsonFile(join(input.cwd, "reports", "index.json"));
  const analysis = await analyzeReviewOpportunities({
    index,
    loadReport: (entry) =>
      readJsonFile(
        join(
          input.cwd,
          "reports",
          "github",
          String(entry.repository_id),
          entry.target_sha,
          entry.scanner_policy_version,
          entry.report_id,
          "report.json",
        ),
      ),
  });
  return format === "json"
    ? renderReviewOpportunitiesJson(analysis)
    : renderReviewOpportunitiesMarkdown(analysis);
}

if (isDirectExecution(import.meta.url))
  void reviewOpportunitiesMain({
    cwd: process.cwd(),
    args: process.argv.slice(2),
  })
    .then((output) => {
      process.stdout.write(output);
    })
    .catch(async (error: unknown) => {
      const record = safeCliErrorRecord(error);
      const failureOutput = process.env.TAVERNKEEPER_ERROR_OUTPUT;
      if (failureOutput !== undefined)
        try {
          await writeJsonFile(failureOutput, record);
        } catch {
          // The stderr record below remains deliberately body-free.
        }
      process.stderr.write(`${JSON.stringify(record)}\n`);
      process.exitCode = 1;
    });
