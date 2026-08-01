import { readFile, writeFile } from "node:fs/promises";

import { z } from "zod";

import {
  addReusableDismissal,
  adjudicateFinding,
  DismissalRegistrySchema,
} from "../adjudication/adjudicate.js";
import {
  isDirectExecution,
  readJsonFile,
  requiredEnvironment,
  runJsonCli,
  writeJsonFile,
} from "./io.js";

const RequestSchema = z.strictObject({
  report_id: z.string().regex(/^[0-9a-f]{64}$/u),
  fingerprint: z.string().regex(/^[0-9a-f]{64}$/u),
  decision: z.enum(["dismiss", "restore"]),
  rationale: z.string().min(1).max(1_000),
  actor: z.string().regex(/^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$/u),
  reusable: z.boolean(),
});

async function main() {
  const reportPath = process.argv[2];
  const output = process.argv[3] ?? "candidate.json";
  if (reportPath === undefined)
    throw new Error("Adjudication report path is required.");
  const request = RequestSchema.parse(
    JSON.parse(requiredEnvironment(process.env, "TAVERNKEEPER_ADJUDICATION")),
  );
  const reportInput = await readJsonFile(reportPath);
  if (
    reportInput === null ||
    typeof reportInput !== "object" ||
    !("report_id" in reportInput) ||
    reportInput.report_id !== request.report_id
  )
    throw new Error(
      "Adjudication report ID does not match the selected report.",
    );
  const report = adjudicateFinding({
    report: reportInput,
    fingerprint: request.fingerprint,
    decision: request.decision,
    rationale: request.rationale,
    actor: request.actor,
    completedAt: new Date().toISOString(),
    reusable: request.reusable,
  });
  if (request.reusable) {
    const registry = DismissalRegistrySchema.parse(
      JSON.parse(await readFile("rules/dismissals.json", "utf8")),
    );
    const updated = addReusableDismissal({
      registry,
      report,
      fingerprint: request.fingerprint,
    });
    await writeFile(
      "rules/dismissals.json",
      `${JSON.stringify(updated, null, 2)}\n`,
    );
  }
  await writeJsonFile(output, { report });
  return { status: "adjudicated", report_id: report.report_id };
}

if (isDirectExecution(import.meta.url)) runJsonCli(main);
