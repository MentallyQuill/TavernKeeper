import type { CommandRunner } from "../process/command-runner.js";
import type { Finding } from "../contracts/reports.js";
import { ScannerError } from "./types.js";

export { runApplicableScanners } from "./run-scanners.js";
export type { ApplicableScannerSpec } from "./run-scanners.js";
/** @deprecated Transitional frozen-orchestrator shape; new scanners throw instead. */
export interface ExternalToolRun {
  name: string;
  status: "completed" | "not-applicable" | "unavailable" | "failed";
  version: string | null;
  detail?: string;
  findings: Finding[];
}

/** @deprecated Transitional callers must migrate to runApplicableScanners. */
export async function runExternalTools(_spec: {
  root: string;
  runner: CommandRunner;
}): Promise<ExternalToolRun[]> {
  throw new ScannerError(
    "SCANNER_FAILED",
    "system",
    "The legacy unclassified scanner coordinator is disabled.",
  );
}
