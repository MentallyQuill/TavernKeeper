import { createHash, randomUUID } from "node:crypto";
import {
  access,
  mkdir,
  readFile,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { basename, resolve, sep } from "node:path";

import { z } from "zod";

import type { ScannerPins, ScannerPolicyV2 } from "../config/policy.js";
import {
  buildScanPackage,
  RequiredScanPackageTools,
} from "../contracts/scan-package.js";
import { FindingSchema, ScanReportV4Schema } from "../contracts/reports.js";
import { FullShaSchema, TargetSchema } from "../contracts/targets.js";
import { checkoutExactTarget } from "../git/checkout.js";
import { planHistory } from "../git/history.js";
import { classifyInventory } from "../inventory/classify.js";
import { inventoryRepository } from "../inventory/inventory-handler.js";
import type { CommandRunner } from "../process/command-runner.js";
import { buildDeterministicReport } from "../report/deterministic-report.js";
import {
  runApplicableScanners,
  type ScannerExecutables,
} from "../scanners/run-scanners.js";
import {
  canonicalScannerRuns,
  classificationIsConsistent,
  inventoryIsConsistent,
  scanStructuralFiles,
  validateScannerRuns,
} from "./scan-handler.js";

const DigestSchema = z.string().regex(/^[0-9a-f]{64}$/u);
const VersionSchema = z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._-]{0,79}$/u);
const CountSchema = z.number().int().nonnegative();
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
const FileByteTotalsSchema = z.strictObject({
  files: CountSchema,
  bytes: CountSchema,
});
const ExcludedSchema = z.strictObject({
  dependency_lockfiles: FileByteTotalsSchema,
  vendored_dependencies: FileByteTotalsSchema,
  generated_bundles: FileByteTotalsSchema,
  minified_files: FileByteTotalsSchema,
  binaries: FileByteTotalsSchema,
  archives: FileByteTotalsSchema,
  oversized_files: FileByteTotalsSchema,
  unsafe_entries: FileByteTotalsSchema,
});
const InventoryFileSchema = z.strictObject({
  path: RepositoryPathSchema,
  bytes: CountSchema,
  sha256: DigestSchema,
  kind: z.enum(["text", "binary", "oversized"]),
  likely_minified: z.boolean(),
  executable: z.boolean(),
});
const PathListSchema = z
  .array(RepositoryPathSchema)
  .refine(
    (paths) =>
      paths.every((path, index) => index === 0 || paths[index - 1]! < path),
    "Prepared paths must be unique and sorted.",
  );
const PreparedSessionObjectSchema = z.strictObject({
  schema_version: z.literal(4),
  session_id: DigestSchema,
  target: TargetSchema,
  project_kinds: z.array(z.enum(["extension", "frontend", "preset"])).min(1),
  prepared_at: z.iso.datetime(),
  scanner_version: VersionSchema,
  scanner_policy_version: z.literal("2"),
  rule_catalog_version: z.literal("1"),
  report_version: z.number().int().positive(),
  supersedes_report_id: DigestSchema.nullable(),
  history: z.strictObject({
    base_sha: FullShaSchema.nullable(),
    commits: z.number().int().min(1).max(20),
  }),
  inventory: z.strictObject({
    root: z.literal("repository"),
    totals: FileByteTotalsSchema,
    files: z.array(InventoryFileSchema),
  }),
  classification: z.strictObject({
    first_party_text_paths: PathListSchema,
    applicability: z.strictObject({
      osv: z.boolean(),
      zizmor: z.boolean(),
      malcontent: z.boolean(),
    }),
    scanner_input_paths: z.strictObject({
      osv: PathListSchema,
      zizmor: PathListSchema,
      malcontent: PathListSchema,
    }),
    excluded: ExcludedSchema,
  }),
  tools: z.array(
    z.strictObject({
      name: z.enum(RequiredScanPackageTools),
      version: VersionSchema,
      status: z.enum(["completed", "not-applicable"]),
    }),
  ),
  findings: z.array(FindingSchema),
});

type PreparedSession = z.infer<typeof PreparedSessionObjectSchema>;

function runtimeInventory(prepared: PreparedSession) {
  return {
    root: prepared.inventory.root,
    files: prepared.inventory.files.map((file) => ({
      path: file.path,
      bytes: file.bytes,
      sha256: file.sha256,
      kind: file.kind,
      likelyMinified: file.likely_minified,
      executable: file.executable,
    })),
    totals: prepared.inventory.totals,
    totalBytes: prepared.inventory.totals.bytes,
  };
}

function runtimeClassification(
  prepared: PreparedSession,
  inventory: ReturnType<typeof runtimeInventory>,
) {
  const files = new Map(inventory.files.map((file) => [file.path, file]));
  const paths = (values: string[]) =>
    values.map((path) => {
      const file = files.get(path);
      if (file === undefined)
        throw new Error(
          `Prepared classification path is not inventoried: ${path}`,
        );
      return file;
    });
  return {
    firstPartyText: paths(prepared.classification.first_party_text_paths),
    applicability: prepared.classification.applicability,
    scannerInputs: {
      osv: paths(prepared.classification.scanner_input_paths.osv),
      zizmor: paths(prepared.classification.scanner_input_paths.zizmor),
      malcontent: paths(prepared.classification.scanner_input_paths.malcontent),
    },
    excluded: prepared.classification.excluded,
  };
}

function scanPackageFor(prepared: PreparedSession) {
  const inventory = runtimeInventory(prepared);
  const classification = runtimeClassification(prepared, inventory);
  if (
    !inventoryIsConsistent(inventory) ||
    !classificationIsConsistent(inventory, classification)
  )
    throw new Error("Prepared inventory evidence is inconsistent.");
  return buildScanPackage({
    target: prepared.target,
    history: {
      baseSha: prepared.history.base_sha,
      commits: prepared.history.commits,
    },
    scannerVersion: prepared.scanner_version,
    scannerPolicyVersion: prepared.scanner_policy_version,
    ruleCatalogVersion: prepared.rule_catalog_version,
    inventory,
    classification,
    tools: prepared.tools,
    findings: prepared.findings,
  });
}

export const PreparedSessionSchema = PreparedSessionObjectSchema.superRefine(
  (session, context) => {
    if (
      session.project_kinds.some(
        (kind, index) => index > 0 && session.project_kinds[index - 1]! >= kind,
      )
    )
      context.addIssue({
        code: "custom",
        path: ["project_kinds"],
        message: "Prepared project kinds must be unique and sorted.",
      });
    try {
      scanPackageFor(session);
    } catch (error) {
      context.addIssue({
        code: "custom",
        path: [],
        message:
          error instanceof Error
            ? error.message
            : "Prepared scanner evidence is invalid.",
      });
    }
  },
);

export class ScanPhaseError extends Error {
  constructor(
    readonly code: string,
    readonly scope: "repository" | "system",
    message: string,
  ) {
    super(message);
    this.name = "ScanPhaseError";
  }
}

function canonicalValue(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicalValue);
  if (value !== null && typeof value === "object")
    return Object.fromEntries(
      Object.entries(value)
        .sort(([left], [right]) => left.localeCompare(right))
        .map(([key, nested]) => [key, canonicalValue(nested)]),
    );
  return value;
}

export function preparedSessionIdentity(input: Record<string, unknown>) {
  const identityInput: Record<string, unknown> = { ...input };
  delete identityInput.session_id;
  const parsed = PreparedSessionObjectSchema.omit({ session_id: true }).parse(
    identityInput,
  );
  return createHash("sha256")
    .update(JSON.stringify(canonicalValue(parsed)))
    .digest("hex");
}

async function pathExists(path: string) {
  try {
    await access(path);
    return true;
  } catch (error) {
    if (
      error !== null &&
      typeof error === "object" &&
      "code" in error &&
      error.code === "ENOENT"
    )
      return false;
    throw error;
  }
}

function requireEphemeralPath(path: string, prefix: string) {
  const resolved = resolve(path);
  if (!basename(resolved).startsWith(prefix))
    throw new Error("Ephemeral scan path name is unsafe.");
  return resolved;
}

export async function prepareTargetSession({
  target: targetInput,
  projectKinds,
  checkoutRoot: checkoutRootInput,
  sessionRoot: sessionRootInput,
  previousReportShas,
  preparedAt,
  scannerVersion,
  scannerPolicyVersion,
  ruleCatalogVersion,
  reportVersion,
  supersedesReportId,
  policy,
  pins,
  rulesRoot,
  runner,
  executables,
  temporaryRoot,
}: {
  target: unknown;
  projectKinds: readonly ("extension" | "frontend" | "preset")[];
  checkoutRoot: string;
  sessionRoot: string;
  previousReportShas: string[];
  preparedAt: string;
  scannerVersion: string;
  scannerPolicyVersion: string;
  ruleCatalogVersion: string;
  reportVersion: number;
  supersedesReportId: string | null;
  policy: ScannerPolicyV2;
  pins: ScannerPins;
  rulesRoot: string;
  runner: CommandRunner;
  executables?: Partial<ScannerExecutables>;
  temporaryRoot?: string;
}) {
  const target = TargetSchema.parse(targetInput);
  if (
    scannerPolicyVersion !== policy.version ||
    policy.version !== "2" ||
    ruleCatalogVersion !== "1" ||
    projectKinds.length === 0
  )
    throw new ScanPhaseError(
      "INVALID_SCAN_SPEC",
      "system",
      "Prepared scanner policy does not match deterministic policy.",
    );
  const checkoutRoot = requireEphemeralPath(
    checkoutRootInput,
    "tavernkeeper-checkout-",
  );
  const sessionRoot = requireEphemeralPath(
    sessionRootInput,
    "tavernkeeper-session-",
  );
  if (
    checkoutRoot === sessionRoot ||
    (await pathExists(checkoutRoot)) ||
    (await pathExists(sessionRoot))
  )
    throw new Error("Ephemeral scan paths must be distinct and absent.");
  let checkoutCreated = false;
  let sessionCreated = false;
  try {
    checkoutCreated = true;
    const checkout = await checkoutExactTarget({
      target,
      destination: checkoutRoot,
      runner,
    });
    if (!checkout.ok)
      throw new ScanPhaseError(
        checkout.error.code,
        "repository",
        "Exact target checkout failed.",
      );
    const inventoryResult = await inventoryRepository({
      root: checkoutRoot,
      maxFiles: policy.inventory.maxFiles,
      maxTotalBytes: policy.inventory.maxTotalBytes,
      maxFileBytes: policy.inventory.maxFileBytes,
    });
    if (!inventoryResult.ok)
      throw new ScanPhaseError(
        inventoryResult.error.code,
        "repository",
        "Repository inventory failed.",
      );
    const inventory = inventoryResult.value;
    if (!inventoryIsConsistent(inventory))
      throw new ScanPhaseError(
        "INVENTORY_INVALID",
        "system",
        "Repository inventory totals are inconsistent.",
      );
    const classification = classifyInventory(inventory);
    if (!classificationIsConsistent(inventory, classification))
      throw new ScanPhaseError(
        "CLASSIFICATION_INVALID",
        "system",
        "Repository classification is incomplete.",
      );
    const history = await planHistory(checkoutRoot, previousReportShas, runner);
    if (!history.ok)
      throw new ScanPhaseError(
        history.error.code,
        "repository",
        "Repository history failed.",
      );
    const structuralFindings = await scanStructuralFiles(
      checkoutRoot,
      classification.firstPartyText,
    );
    const scannerRuns = await runApplicableScanners({
      root: checkoutRoot,
      history: {
        baseSha: history.value.baseSha,
        targetSha: target.target_sha,
        commits: history.value.historyCommits,
      },
      classification,
      structuralFiles: [],
      structuralFindings,
      runner,
      policy,
      pins,
      rulesRoot,
      ...(executables === undefined ? {} : { executables }),
      ...(temporaryRoot === undefined ? {} : { temporaryRoot }),
    });
    validateScannerRuns(scannerRuns, classification, structuralFindings, {
      "tavernkeeper-static": policy.version,
      gitleaks: pins.gitleaks.version,
      opengrep: pins.opengrep.version,
      "osv-scanner": pins.osvScanner.version,
      zizmor: pins.zizmor.version,
      malcontent: pins.malcontent.version,
    });
    const orderedRuns = canonicalScannerRuns(scannerRuns);
    const withoutIdentity = {
      schema_version: 4 as const,
      target,
      project_kinds: [...projectKinds].sort(),
      prepared_at: preparedAt,
      scanner_version: scannerVersion,
      scanner_policy_version: "2" as const,
      rule_catalog_version: "1" as const,
      report_version: reportVersion,
      supersedes_report_id: supersedesReportId,
      history: {
        base_sha: history.value.baseSha,
        commits: history.value.historyCommits,
      },
      inventory: {
        root: "repository" as const,
        totals: inventory.totals,
        files: inventory.files
          .map((file) => ({
            path: file.path,
            bytes: file.bytes,
            sha256: file.sha256,
            kind: file.kind,
            likely_minified: file.likelyMinified === true,
            executable: file.executable === true,
          }))
          .sort((left, right) => left.path.localeCompare(right.path)),
      },
      classification: {
        first_party_text_paths: classification.firstPartyText
          .map(({ path }) => path)
          .sort(),
        applicability: classification.applicability,
        scanner_input_paths: {
          osv: classification.scannerInputs.osv.map(({ path }) => path).sort(),
          zizmor: classification.scannerInputs.zizmor
            .map(({ path }) => path)
            .sort(),
          malcontent: classification.scannerInputs.malcontent
            .map(({ path }) => path)
            .sort(),
        },
        excluded: classification.excluded,
      },
      tools: [
        {
          name: "inventory" as const,
          version: scannerVersion,
          status: "completed" as const,
        },
        ...orderedRuns.map(({ name, version, status }) => ({
          name: name as (typeof RequiredScanPackageTools)[number],
          version,
          status,
        })),
      ],
      findings: orderedRuns
        .flatMap(({ findings }) => findings)
        .sort((left, right) =>
          left.fingerprint.localeCompare(right.fingerprint),
        ),
    };
    const prepared = PreparedSessionSchema.parse({
      ...withoutIdentity,
      session_id: preparedSessionIdentity(withoutIdentity),
    });
    await mkdir(sessionRoot, { recursive: true });
    sessionCreated = true;
    await writeFile(
      resolve(sessionRoot, "prepared.json"),
      `${JSON.stringify(prepared, null, 2)}\n`,
      { flag: "wx" },
    );
    return { prepared, checkoutRoot, sessionRoot };
  } catch (error) {
    if (sessionCreated) await rm(sessionRoot, { recursive: true, force: true });
    if (checkoutCreated)
      await rm(checkoutRoot, { recursive: true, force: true });
    throw error;
  }
}

async function loadPrepared(sessionRoot: string) {
  const prepared = PreparedSessionSchema.parse(
    JSON.parse(await readFile(resolve(sessionRoot, "prepared.json"), "utf8")),
  );
  if (prepared.session_id !== preparedSessionIdentity(prepared))
    throw new Error("Prepared session identity does not match its contents.");
  return prepared;
}

function safeSessionRoot(sessionRoot: string) {
  const root = resolve(sessionRoot);
  if (!basename(root).startsWith("tavernkeeper-session-"))
    throw new Error("Ephemeral session directory name is unsafe.");
  return root;
}

async function writeExclusive(path: string, value: unknown) {
  const destination = resolve(path);
  if (await pathExists(destination))
    throw new Error("Candidate output already exists.");
  const temporary = `${destination}.${randomUUID()}.tmp`;
  try {
    await writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`, {
      flag: "wx",
    });
    await rename(temporary, destination);
  } finally {
    await rm(temporary, { force: true });
  }
}

export async function finalizePreparedSession({
  sessionRoot: sessionRootInput,
  output,
  completedAt,
  verifyHead,
}: {
  sessionRoot: string;
  output: string;
  completedAt: string;
  verifyHead: (
    expectedSha: string,
  ) => Promise<
    | { ok: true; value: string }
    | { ok: false; error: { code?: string; message?: string } }
  >;
}): Promise<{
  status: "completed";
  candidate: { report: z.infer<typeof ScanReportV4Schema> };
}> {
  const sessionRoot = safeSessionRoot(sessionRootInput);
  const destination = resolve(output);
  if (
    destination === sessionRoot ||
    destination.startsWith(`${sessionRoot}${sep}`)
  )
    throw new Error("Candidate output must be outside the ephemeral session.");
  const prepared = await loadPrepared(sessionRoot);
  try {
    const verified = await verifyHead(prepared.target.target_sha);
    if (!verified.ok || verified.value !== prepared.target.target_sha)
      throw new ScanPhaseError(
        verified.ok
          ? "HEAD_MISMATCH"
          : (verified.error.code ?? "HEAD_MISMATCH"),
        "repository",
        "Checked-out commit changed before deterministic finalization.",
      );
    let scanPackage: ReturnType<typeof scanPackageFor>;
    try {
      scanPackage = scanPackageFor(prepared);
    } catch (error) {
      if (error instanceof ScanPhaseError) throw error;
      throw new ScanPhaseError(
        "SCAN_PACKAGE_FINALIZATION_FAILED",
        "system",
        "Prepared scanner evidence could not be finalized.",
      );
    }
    let report: z.infer<typeof ScanReportV4Schema>;
    try {
      report = buildDeterministicReport(scanPackage, {
        targetSha: prepared.target.target_sha,
        completedAt,
        reportVersion: prepared.report_version,
        supersedesReportId: prepared.supersedes_report_id,
      });
    } catch (error) {
      if (error instanceof ScanPhaseError) throw error;
      throw new ScanPhaseError(
        "REPORT_FINALIZATION_FAILED",
        "system",
        "Deterministic report construction failed.",
      );
    }
    const candidate = { report };
    await writeExclusive(destination, candidate);
    return { status: "completed", candidate };
  } finally {
    await rm(sessionRoot, { recursive: true, force: true });
  }
}
