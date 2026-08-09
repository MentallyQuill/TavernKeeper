import { join } from "node:path";

import {
  loadScannerPins,
  loadScannerPolicy,
  ScannerPolicyV4Schema,
} from "../config/policy.js";
import { prepareTargetSession } from "../orchestrator/session.js";
import { ProcessCommandRunner } from "../process/command-runner.js";
import { isDirectExecution, requiredEnvironment, runJsonCli } from "./io.js";
import { ScanRequestSchema } from "./staff-request.js";

async function main() {
  const request = ScanRequestSchema.parse(
    JSON.parse(requiredEnvironment(process.env, "TAVERNKEEPER_SCAN_REQUEST")),
  );
  const repositoryRoot = process.cwd();
  const policy = ScannerPolicyV4Schema.parse(
    await loadScannerPolicy(
      join(repositoryRoot, "config", "scanner-policy.v4.json"),
    ),
  );
  const pins = await loadScannerPins(
    join(repositoryRoot, "config", "scanners.v1.json"),
  );
  const prepared = await prepareTargetSession({
    target: {
      source_id: request.source_id,
      provider: request.provider,
      repository_id: request.repository_id,
      repository: request.repository,
      target_sha: request.target_sha,
      canonical_url: request.canonical_url,
    },
    projectKinds: request.project_kinds,
    checkoutRoot: requiredEnvironment(
      process.env,
      "TAVERNKEEPER_CHECKOUT_ROOT",
    ),
    sessionRoot: requiredEnvironment(process.env, "TAVERNKEEPER_SESSION_ROOT"),
    previousReportShas: request.previous_report_shas,
    preparedAt: new Date().toISOString(),
    scannerVersion: "0.1.0",
    scannerPolicyVersion: policy.version,
    ruleCatalogVersion: "1",
    reportVersion: request.report_version,
    supersedesReportId: request.supersedes_report_id,
    policy,
    pins,
    rulesRoot: join(repositoryRoot, "rules", "opengrep"),
    runner: new ProcessCommandRunner(),
    temporaryRoot: requiredEnvironment(process.env, "RUNNER_TEMP"),
  });
  return {
    status: "prepared",
    session_id: prepared.prepared.session_id,
    findings: prepared.prepared.findings.length,
  };
}

if (isDirectExecution(import.meta.url))
  runJsonCli(main, {
    code: "CLI_FAILED",
    domain: "target",
    component: "orchestrator",
  });
