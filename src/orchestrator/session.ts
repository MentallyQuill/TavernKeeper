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

import {
  CURRENT_SCANNER_POLICY_VERSION,
  type ScannerPins,
  type ScannerPolicyV5,
} from "../config/policy.js";
import {
  buildScanPackage,
  RequiredScanPackageTools,
  ScanPackageToolLimitationSchema,
  ScanPackageToolStatusSchema,
} from "../contracts/scan-package.js";
import {
  MAX_PREPARED_MANIFEST_BYTES,
  MAX_PREPARED_PAYLOAD_BYTES,
} from "../contracts/prepared-evidence-limits.js";
import { FindingSchema } from "../contracts/reports.js";
import { ScanReportV5Schema } from "../contracts/reports-v5.js";
import { FullShaSchema, TargetSchema } from "../contracts/targets.js";
import {
  buildEvidenceContextGroups,
  EvidenceContextGroupsSchema,
  extractHistoricalEvidenceSources,
  type EvidenceContextGroup,
} from "../context/evidence-context.js";
import { analyzeExecutionScopes } from "../triage/execution-scope.js";
import { checkoutExactTarget, verifyExactHead } from "../git/checkout.js";
import { planHistory } from "../git/history.js";
import { classifyInventory } from "../inventory/classify.js";
import { inventoryRepository } from "../inventory/inventory-handler.js";
import type { CommandRunner } from "../process/command-runner.js";
import { JavascriptAnalysisCoverageSchema } from "../scanners/javascript-analysis-types.js";
import { JAVASCRIPT_ANALYSIS_VERSION } from "../scanners/javascript-analysis.js";
import {
  CompletedContextualReviewSchema,
  ContextualReviewProgressError,
  ContextualReviewProgressSchema,
  reviewEvidenceGroups,
  type ContextualReviewPolicy,
  type ContextualReviewProvider,
  type ReviewEvidenceGroupsSpec,
} from "../model/contextual-review.js";
import {
  buildReviewCacheManifest,
  loadReusableReviewGroups,
  reviewInputDigest,
  type ReviewIdentity,
} from "../model/review-cache.js";
import type { JsonRepairProvider } from "../model/json-repair.js";
import { validateModelEndpoint } from "../model/openai-compatible-client.js";
import { sanitizeReportV5 } from "../publish/sanitize.js";
import { buildContextualReport } from "../report/contextual-report.js";
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
  schema_version: z.literal(5),
  session_id: DigestSchema,
  target: TargetSchema,
  project_kinds: z.array(z.enum(["extension", "frontend", "preset"])).min(1),
  prepared_at: z.iso.datetime(),
  scanner_version: VersionSchema,
  scanner_policy_version: z.literal(CURRENT_SCANNER_POLICY_VERSION),
  rule_catalog_version: z.literal("2"),
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
      status: ScanPackageToolStatusSchema,
      limitations: z
        .array(ScanPackageToolLimitationSchema)
        .min(1)
        .max(2)
        .optional(),
    }),
  ),
  javascript_analysis: JavascriptAnalysisCoverageSchema,
  findings: z.array(FindingSchema),
});

type PreparedSession = z.infer<typeof PreparedSessionObjectSchema>;

export const EvidenceContextBundleSchema = z.strictObject({
  schema_version: z.literal(1),
  session_id: DigestSchema,
  evidence_digest: DigestSchema,
  groups: EvidenceContextGroupsSchema,
});

const ReviewBundleSchema = z.strictObject({
  schema_version: z.literal(1),
  session_id: DigestSchema,
  evidence_digest: DigestSchema,
  review: CompletedContextualReviewSchema,
});

const ReviewProgressBundleSchema = z.strictObject({
  schema_version: z.literal(1),
  session_id: DigestSchema,
  evidence_digest: DigestSchema,
  progress: ContextualReviewProgressSchema,
});

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
    javascriptAnalysis: prepared.javascript_analysis,
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

export interface PrepareTargetSessionDependencies {
  checkout: typeof checkoutExactTarget;
  inventory: typeof inventoryRepository;
  classify: typeof classifyInventory;
  history: typeof planHistory;
  structuralScan: typeof scanStructuralFiles;
  scanners: typeof runApplicableScanners;
  extractHistorical: typeof extractHistoricalEvidenceSources;
  executionScopes: typeof analyzeExecutionScopes;
  buildEvidence: typeof buildEvidenceContextGroups;
  verifyHead: typeof verifyExactHead;
}

const defaultPrepareDependencies: PrepareTargetSessionDependencies = {
  checkout: checkoutExactTarget,
  inventory: inventoryRepository,
  classify: classifyInventory,
  history: planHistory,
  structuralScan: scanStructuralFiles,
  scanners: runApplicableScanners,
  extractHistorical: extractHistoricalEvidenceSources,
  executionScopes: analyzeExecutionScopes,
  buildEvidence: buildEvidenceContextGroups,
  verifyHead: verifyExactHead,
};

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

export function evidenceContextIdentity(input: {
  session_id: string;
  groups: readonly EvidenceContextGroup[];
}) {
  return createHash("sha256")
    .update(JSON.stringify(canonicalValue(input)))
    .digest("hex");
}

function serializedJsonBytes(value: unknown) {
  return Buffer.byteLength(`${JSON.stringify(value, null, 2)}\n`);
}

export async function buildBoundedEvidenceContext({
  prepared: preparedInput,
  maxEvidenceCharacters,
  buildGroups,
  maximumArtifactBytes = MAX_PREPARED_PAYLOAD_BYTES,
  manifestReserveBytes = MAX_PREPARED_MANIFEST_BYTES,
}: {
  prepared: unknown;
  maxEvidenceCharacters: number;
  buildGroups: (
    maximumCharacters: number,
  ) => Promise<readonly EvidenceContextGroup[]>;
  maximumArtifactBytes?: number;
  manifestReserveBytes?: number;
}) {
  const prepared = PreparedSessionSchema.parse(preparedInput);
  if (
    !Number.isSafeInteger(maxEvidenceCharacters) ||
    maxEvidenceCharacters < 1 ||
    !Number.isSafeInteger(maximumArtifactBytes) ||
    maximumArtifactBytes < 1 ||
    !Number.isSafeInteger(manifestReserveBytes) ||
    manifestReserveBytes < 0
  )
    throw new Error("Prepared evidence artifact budget is invalid.");
  const evidenceBudget =
    maximumArtifactBytes - manifestReserveBytes - serializedJsonBytes(prepared);
  if (evidenceBudget < 1)
    throw new Error("Prepared session metadata exceeds its artifact budget.");

  let maximumCharacters = maxEvidenceCharacters;
  for (let attempt = 0; attempt < 6; attempt += 1) {
    const groups = EvidenceContextGroupsSchema.parse(
      await buildGroups(maximumCharacters),
    );
    const bundle = EvidenceContextBundleSchema.parse({
      schema_version: 1,
      session_id: prepared.session_id,
      evidence_digest: evidenceContextIdentity({
        session_id: prepared.session_id,
        groups,
      }),
      groups,
    });
    const evidenceBytes = serializedJsonBytes(bundle);
    if (evidenceBytes <= evidenceBudget) {
      validatePreparedSessionEvidence(prepared, bundle);
      return bundle;
    }
    if (maximumCharacters === 1)
      throw new Error(
        "Prepared evidence metadata exceeds its artifact budget.",
      );
    maximumCharacters =
      attempt === 4
        ? 1
        : Math.max(
            1,
            Math.min(
              maximumCharacters - 1,
              Math.floor(
                maximumCharacters * (evidenceBudget / evidenceBytes) * 0.9,
              ),
            ),
          );
  }
  throw new Error("Prepared evidence metadata exceeds its artifact budget.");
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

export async function prepareTargetSession(
  {
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
    policy: ScannerPolicyV5;
    pins: ScannerPins;
    rulesRoot: string;
    runner: CommandRunner;
    executables?: Partial<ScannerExecutables>;
    temporaryRoot?: string;
  },
  dependencies: PrepareTargetSessionDependencies = defaultPrepareDependencies,
) {
  const target = TargetSchema.parse(targetInput);
  if (
    scannerPolicyVersion !== policy.version ||
    policy.version !== "5" ||
    ruleCatalogVersion !== "1" ||
    projectKinds.length === 0
  )
    throw new ScanPhaseError(
      "SCAN_POLICY_MISMATCH",
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
    const checkout = await dependencies.checkout({
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
    const inventoryResult = await dependencies.inventory({
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
    const classification = dependencies.classify(inventory);
    if (!classificationIsConsistent(inventory, classification))
      throw new ScanPhaseError(
        "CLASSIFICATION_INVALID",
        "system",
        "Repository classification is incomplete.",
      );
    const history = await dependencies.history(
      checkoutRoot,
      previousReportShas,
      runner,
    );
    if (!history.ok)
      throw new ScanPhaseError(
        history.error.code,
        "repository",
        "Repository history failed.",
      );
    const structuralFindings = await dependencies.structuralScan(
      checkoutRoot,
      classification.firstPartyText,
    );
    const scannerRuns = await dependencies.scanners({
      root: checkoutRoot,
      history: {
        baseSha: history.value.baseSha,
        targetSha: target.target_sha,
        commits: history.value.historyCommits,
      },
      classification,
      inventoryFiles: inventory.files,
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
      "javascript-analysis": JAVASCRIPT_ANALYSIS_VERSION,
      "osv-scanner": pins.osvScanner.version,
      zizmor: pins.zizmor.version,
      malcontent: pins.malcontent.version,
    });
    const orderedRuns = canonicalScannerRuns(scannerRuns);
    const findings = orderedRuns
      .flatMap(({ findings }) => findings)
      .sort((left, right) => left.fingerprint.localeCompare(right.fingerprint));
    const withoutIdentity = {
      schema_version: 5 as const,
      target,
      project_kinds: [...projectKinds].sort(),
      prepared_at: preparedAt,
      scanner_version: scannerVersion,
      scanner_policy_version: CURRENT_SCANNER_POLICY_VERSION,
      rule_catalog_version: "2" as const,
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
        ...orderedRuns.map(({ name, version, status, limitations }) => ({
          name: name as (typeof RequiredScanPackageTools)[number],
          version,
          status,
          ...(limitations === undefined ? {} : { limitations }),
        })),
      ],
      javascript_analysis: orderedRuns.find(
        ({ name }) => name === "javascript-analysis",
      )!.javascriptAnalysis!,
      findings,
    };
    const prepared = PreparedSessionSchema.parse({
      ...withoutIdentity,
      session_id: preparedSessionIdentity(withoutIdentity),
    });
    const historicalSources = await dependencies.extractHistorical({
      checkoutRoot,
      targetSha: target.target_sha,
      findings,
      runner,
      maxFileBytes: policy.inventory.maxFileBytes,
    });
    const executionScopes = await dependencies.executionScopes({
      root: checkoutRoot,
      files: inventory.files,
      limits: policy.executionScope,
    });
    const evidenceBundle = await buildBoundedEvidenceContext({
      prepared,
      maxEvidenceCharacters:
        policy.javascriptAnalysis.maxEvidenceCharactersPerFinding,
      buildGroups: (maxEvidenceCharactersPerFinding) =>
        dependencies.buildEvidence({
          checkoutRoot,
          target,
          projectKinds,
          findings,
          inventory,
          historicalSources,
          executionScopes,
          javascriptEvidenceHints: orderedRuns.flatMap(
            ({ evidenceHints }) => evidenceHints ?? [],
          ),
          maxEvidenceCharactersPerFinding,
        }),
    });
    const verifiedHead = await dependencies.verifyHead(
      checkoutRoot,
      target.target_sha,
      runner,
    );
    if (!verifiedHead.ok)
      throw new ScanPhaseError(
        verifiedHead.error.code,
        "repository",
        "Repository head changed before evidence persistence.",
      );
    await mkdir(sessionRoot, { recursive: true });
    sessionCreated = true;
    await writeFile(
      resolve(sessionRoot, "prepared.json"),
      `${JSON.stringify(prepared, null, 2)}\n`,
      { flag: "wx" },
    );
    await writeFile(
      resolve(sessionRoot, "evidence-context.json"),
      `${JSON.stringify(evidenceBundle, null, 2)}\n`,
      { flag: "wx" },
    );
    await rm(checkoutRoot, { recursive: true, force: true });
    checkoutCreated = false;
    return { prepared, sessionRoot };
  } catch (error) {
    if (sessionCreated) await rm(sessionRoot, { recursive: true, force: true });
    if (checkoutCreated)
      await rm(checkoutRoot, { recursive: true, force: true });
    throw error;
  }
}

export function validatePreparedSessionEvidence(
  preparedInput: unknown,
  evidenceInput: unknown,
) {
  const prepared = PreparedSessionSchema.parse(preparedInput);
  if (prepared.session_id !== preparedSessionIdentity(prepared))
    throw new Error("Prepared session identity does not match its contents.");
  const bundle = EvidenceContextBundleSchema.parse(evidenceInput);
  if (
    bundle.session_id !== prepared.session_id ||
    bundle.evidence_digest !==
      evidenceContextIdentity({
        session_id: bundle.session_id,
        groups: bundle.groups,
      })
  )
    throw new Error("Evidence context identity does not match the session.");
  const candidateIds = bundle.groups.flatMap((group) =>
    group.candidates.map((candidate) => candidate.candidate_id),
  );
  if (
    candidateIds.length !== prepared.findings.length ||
    new Set(candidateIds).size !== candidateIds.length ||
    prepared.findings.some(
      (finding) => !candidateIds.includes(finding.fingerprint),
    )
  )
    throw new Error("Evidence context does not cover prepared findings.");
  return { prepared, evidence: bundle };
}

async function loadPrepared(sessionRoot: string) {
  const prepared = PreparedSessionSchema.parse(
    JSON.parse(await readFile(resolve(sessionRoot, "prepared.json"), "utf8")),
  );
  if (prepared.session_id !== preparedSessionIdentity(prepared))
    throw new Error("Prepared session identity does not match its contents.");
  return prepared;
}

async function loadEvidenceContext(
  sessionRoot: string,
  prepared: PreparedSession,
) {
  const evidence = JSON.parse(
    await readFile(resolve(sessionRoot, "evidence-context.json"), "utf8"),
  );
  return validatePreparedSessionEvidence(prepared, evidence).evidence;
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

async function writeAtomic(path: string, value: unknown) {
  const destination = resolve(path);
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

export async function reviewPreparedSession({
  sessionRoot: sessionRootInput,
  repositoryRoot = process.cwd(),
  provider,
  jsonRepairProvider,
  policy,
  expandContext,
}: {
  sessionRoot: string;
  repositoryRoot?: string;
  provider: ContextualReviewProvider;
  jsonRepairProvider?: JsonRepairProvider;
  policy: ContextualReviewPolicy;
  expandContext?: ReviewEvidenceGroupsSpec["expandContext"];
}) {
  const sessionRoot = safeSessionRoot(sessionRootInput);
  const prepared = await loadPrepared(sessionRoot);
  const evidence = await loadEvidenceContext(sessionRoot, prepared);
  const endpoint = validateModelEndpoint(provider.endpoint);
  const reviewIdentity: ReviewIdentity = {
    scanner_version: prepared.scanner_version,
    scanner_policy_version: prepared.scanner_policy_version,
    rule_catalog_version: prepared.rule_catalog_version,
    tools: prepared.tools.map(({ name, version }) => ({ name, version })),
    contextual_policy_version: policy.version,
    prompt_version: policy.promptVersion,
    assessment_schema_version: policy.schemaVersion,
    provider: endpoint.hostname,
    endpoint_origin: endpoint.origin,
    model: provider.model,
  };
  const reviewInputDigests = new Map(
    evidence.groups.map((group) => [
      group.group_id,
      reviewInputDigest(group, reviewIdentity),
    ]),
  );
  const reusableGroups = await loadReusableReviewGroups({
    repositoryRoot,
    repositoryId: prepared.target.repository_id,
    repository: prepared.target.repository,
    groups: evidence.groups,
    reviewIdentity,
  });
  const progressPath = resolve(sessionRoot, "review-progress.json");
  const reviewPath = resolve(sessionRoot, "review.json");
  if (await pathExists(reviewPath)) {
    const existing = ReviewBundleSchema.parse(
      JSON.parse(await readFile(reviewPath, "utf8")),
    );
    if (
      existing.session_id !== prepared.session_id ||
      existing.evidence_digest !== evidence.evidence_digest
    )
      throw new ScanPhaseError(
        "CONTEXTUAL_REVIEW_INVALID",
        "repository",
        "Completed contextual review does not match prepared evidence.",
      );
    return { status: "reviewed" as const, review: existing.review };
  }
  let progress: z.infer<typeof ContextualReviewProgressSchema> | undefined;
  if (await pathExists(progressPath)) {
    let decodedProgress: unknown;
    try {
      decodedProgress = JSON.parse(await readFile(progressPath, "utf8"));
    } catch (error) {
      if (!(error instanceof SyntaxError)) throw error;
    }
    const progressBundle =
      ReviewProgressBundleSchema.safeParse(decodedProgress);
    if (
      !progressBundle.success ||
      progressBundle.data.session_id !== prepared.session_id ||
      progressBundle.data.evidence_digest !== evidence.evidence_digest
    )
      await rm(progressPath, { force: true });
    else progress = progressBundle.data.progress;
  }
  const reviewFrom = (checkpoint?: typeof progress) =>
    reviewEvidenceGroups({
      groups: evidence.groups,
      provider,
      jsonRepairProvider,
      policy,
      reviewInputDigests,
      reusableGroups,
      ...(checkpoint === undefined ? {} : { progress: checkpoint }),
      onProgress: async (nextProgress) =>
        writeAtomic(
          progressPath,
          ReviewProgressBundleSchema.parse({
            schema_version: 1,
            session_id: prepared.session_id,
            evidence_digest: evidence.evidence_digest,
            progress: nextProgress,
          }),
        ),
      ...(expandContext === undefined ? {} : { expandContext }),
    });
  let review;
  try {
    review = await reviewFrom(progress);
  } catch (error) {
    if (
      progress === undefined ||
      !(error instanceof ContextualReviewProgressError)
    )
      throw error;
    await rm(progressPath, { force: true });
    review = await reviewFrom();
  }
  const bundle = ReviewBundleSchema.parse({
    schema_version: 1,
    session_id: prepared.session_id,
    evidence_digest: evidence.evidence_digest,
    review,
  });
  await writeExclusive(reviewPath, bundle);
  return { status: "reviewed" as const, review };
}

export async function finalizePreparedSession({
  sessionRoot: sessionRootInput,
  output,
  completedAt,
}: {
  sessionRoot: string;
  output: string;
  completedAt: string;
}): Promise<{
  status: "completed";
  candidate: {
    report: z.infer<typeof ScanReportV5Schema>;
    review_cache: ReturnType<typeof buildReviewCacheManifest>;
  };
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
    const evidence = await loadEvidenceContext(sessionRoot, prepared);
    const reviewBundle = ReviewBundleSchema.parse(
      JSON.parse(await readFile(resolve(sessionRoot, "review.json"), "utf8")),
    );
    if (
      reviewBundle.session_id !== prepared.session_id ||
      reviewBundle.evidence_digest !== evidence.evidence_digest
    )
      throw new ScanPhaseError(
        "CONTEXTUAL_REVIEW_INVALID",
        "system",
        "Contextual review does not match prepared evidence.",
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
    let report: z.infer<typeof ScanReportV5Schema>;
    try {
      report = sanitizeReportV5(
        buildContextualReport(
          {
            scanPackage,
            review: reviewBundle.review,
            evidenceGroups: evidence.groups,
          },
          {
            targetSha: prepared.target.target_sha,
            completedAt,
            reportVersion: prepared.report_version,
            supersedesReportId: prepared.supersedes_report_id,
            limitations: [
              "This advisory review cannot prove the absence of unknown behavior.",
            ],
          },
        ),
      );
    } catch (error) {
      if (error instanceof ScanPhaseError) throw error;
      throw new ScanPhaseError(
        "REPORT_FINALIZATION_FAILED",
        "system",
        "Contextual report construction failed.",
      );
    }
    if (reviewBundle.review.review_units === undefined)
      throw new ScanPhaseError(
        "CONTEXTUAL_REVIEW_INVALID",
        "system",
        "Contextual review unit provenance is unavailable.",
      );
    const reviewIdentity: ReviewIdentity = {
      scanner_version: prepared.scanner_version,
      scanner_policy_version: prepared.scanner_policy_version,
      rule_catalog_version: prepared.rule_catalog_version,
      tools: prepared.tools.map(({ name, version }) => ({ name, version })),
      contextual_policy_version: reviewBundle.review.policy_version,
      prompt_version: reviewBundle.review.prompt_version,
      assessment_schema_version: reviewBundle.review.schema_version,
      provider: reviewBundle.review.provider,
      endpoint_origin: reviewBundle.review.endpoint_origin,
      model: reviewBundle.review.model,
    };
    const candidate = {
      report,
      review_cache: buildReviewCacheManifest({
        report,
        reviewIdentity,
        reviewUnits: reviewBundle.review.review_units,
      }),
    };
    await writeExclusive(destination, candidate);
    return { status: "completed", candidate };
  } finally {
    await rm(sessionRoot, { recursive: true, force: true });
  }
}
