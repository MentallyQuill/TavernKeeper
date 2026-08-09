import { tmpdir } from "node:os";

import type { ScannerPins, ScannerPolicyV4 } from "../config/policy.js";
import type { Finding } from "../contracts/reports.js";
import type { InventoryClassification } from "../inventory/classify.js";
import type { InventoryFile } from "../inventory/inventory-handler.js";
import type { CommandRunner } from "../process/command-runner.js";
import { runGitleaks, type GitleaksHistory } from "./gitleaks.js";
import { runJavascriptAnalysis } from "./javascript-analysis.js";
import { selectJavascriptCandidates } from "./javascript-candidates.js";
import { runMalcontent } from "./malcontent.js";
import { runOpenGrep } from "./opengrep.js";
import { runOsv } from "./osv.js";
import { scanStaticRules, type StaticSourceFile } from "./static-rules.js";
import {
  ScannerError,
  type ScannerComponent,
  type ScannerRun,
} from "./types.js";
import { runZizmor } from "./zizmor.js";

export interface ScannerExecutables {
  gitleaks: string;
  opengrep: string;
  osvScanner: string;
  zizmor: string;
  malcontent: string;
}

export type ScannerVersionPins = {
  [Name in keyof ScannerPins]: Pick<ScannerPins[Name], "version">;
};

export interface ApplicableScannerSpec {
  root: string;
  history: GitleaksHistory;
  classification: InventoryClassification;
  inventoryFiles: readonly InventoryFile[];
  structuralFiles: StaticSourceFile[];
  structuralFindings?: Finding[];
  runner: CommandRunner;
  policy: ScannerPolicyV4;
  pins: ScannerVersionPins;
  rulesRoot: string;
  executables?: Partial<ScannerExecutables>;
  temporaryRoot?: string;
}

export interface ScannerAdapterDependencies {
  staticScan: typeof scanStaticRules;
  gitleaks: typeof runGitleaks;
  opengrep: typeof runOpenGrep;
  javascriptAnalysis: typeof runJavascriptAnalysis;
  osv: typeof runOsv;
  zizmor: typeof runZizmor;
  malcontent: typeof runMalcontent;
}

const defaultAdapters: ScannerAdapterDependencies = {
  staticScan: scanStaticRules,
  gitleaks: runGitleaks,
  opengrep: runOpenGrep,
  javascriptAnalysis: runJavascriptAnalysis,
  osv: runOsv,
  zizmor: runZizmor,
  malcontent: runMalcontent,
};

function executable(
  executables: Partial<ScannerExecutables> | undefined,
  name: keyof ScannerExecutables,
) {
  const value = executables?.[name];
  return value === undefined ? {} : { executable: value };
}

function temporaryRoot(value: string | undefined) {
  return value === undefined ? {} : { temporaryRoot: value };
}

async function runScanner(
  component: ScannerComponent,
  displayName: string,
  operation: () => Promise<ScannerRun>,
): Promise<ScannerRun> {
  try {
    return await operation();
  } catch (error) {
    if (error instanceof ScannerError) throw error;
    throw new ScannerError(
      "SCANNER_FAILED",
      "repository",
      `${displayName} failed for this repository.`,
      component,
    );
  }
}

function validateClassification(classification: InventoryClassification) {
  for (const name of ["osv", "zizmor", "malcontent"] as const) {
    if (
      classification.applicability[name] !==
      classification.scannerInputs[name].length > 0
    )
      throw new ScannerError(
        "SCANNER_FAILED",
        "system",
        `Inventory classification is inconsistent for ${name}.`,
      );
  }
}

export async function runApplicableScanners(
  spec: ApplicableScannerSpec,
  adapters: ScannerAdapterDependencies = defaultAdapters,
): Promise<ScannerRun[]> {
  validateClassification(spec.classification);
  if (
    spec.history.commits < 1 ||
    spec.history.commits > spec.policy.history.maxCommits
  )
    throw new ScannerError(
      "SCANNER_FAILED",
      "system",
      "Scanner history is outside policy bounds.",
    );

  const runs: ScannerRun[] = [
    {
      name: "tavernkeeper-static",
      version: spec.policy.version,
      status: "completed",
      findings:
        spec.structuralFindings ?? adapters.staticScan(spec.structuralFiles),
    },
  ];
  runs.push(
    await runScanner("gitleaks", "Gitleaks", () =>
      adapters.gitleaks({
        root: spec.root,
        history: spec.history,
        runner: spec.runner,
        version: spec.pins.gitleaks.version,
        ...executable(spec.executables, "gitleaks"),
        ...temporaryRoot(spec.temporaryRoot),
      }),
    ),
  );
  const javascriptPaths = selectJavascriptCandidates(spec.inventoryFiles).map(
    ({ path }) => path,
  );
  const openGrepRun = await runScanner("opengrep", "OpenGrep", () =>
    adapters.opengrep({
      root: spec.root,
      rulesRoot: spec.rulesRoot,
      runner: spec.runner,
      version: spec.pins.opengrep.version,
      expectedPaths: javascriptPaths,
      maxTargetBytes: spec.policy.inventory.maxFileBytes,
      ...executable(spec.executables, "opengrep"),
    }),
  );
  if (openGrepRun.pathCoverage === undefined)
    throw new ScannerError(
      "MALFORMED_SCANNER_OUTPUT",
      "system",
      "Repository OpenGrep omitted JavaScript path coverage.",
      "opengrep",
    );
  runs.push(openGrepRun);
  runs.push(
    await runScanner("javascript-analysis", "JavaScript analysis", () =>
      adapters.javascriptAnalysis({
        root: spec.root,
        inventoryFiles: spec.inventoryFiles,
        rawOpenGrepCoverage: openGrepRun.pathCoverage!,
        runner: spec.runner,
        rulesRoot: spec.rulesRoot,
        policy: spec.policy,
        temporaryRoot: spec.temporaryRoot ?? tmpdir(),
        opengrepVersion: spec.pins.opengrep.version,
        ...(spec.executables?.opengrep === undefined
          ? {}
          : { opengrepExecutable: spec.executables.opengrep }),
      }),
    ),
  );
  runs.push(
    await runScanner("osv-scanner", "OSV-Scanner", () =>
      adapters.osv({
        root: spec.root,
        inputs: spec.classification.scannerInputs.osv,
        runner: spec.runner,
        version: spec.pins.osvScanner.version,
        ...executable(spec.executables, "osvScanner"),
        ...temporaryRoot(spec.temporaryRoot),
      }),
    ),
  );
  runs.push(
    await runScanner("zizmor", "zizmor", () =>
      adapters.zizmor({
        root: spec.root,
        inputs: spec.classification.scannerInputs.zizmor,
        runner: spec.runner,
        version: spec.pins.zizmor.version,
        ...executable(spec.executables, "zizmor"),
        ...temporaryRoot(spec.temporaryRoot),
      }),
    ),
  );
  runs.push(
    await runScanner("malcontent", "malcontent", () =>
      adapters.malcontent({
        root: spec.root,
        inputs: spec.classification.scannerInputs.malcontent,
        runner: spec.runner,
        version: spec.pins.malcontent.version,
        ...executable(spec.executables, "malcontent"),
        ...temporaryRoot(spec.temporaryRoot),
      }),
    ),
  );
  return runs;
}
