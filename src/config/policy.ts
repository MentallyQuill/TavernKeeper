import { readFile } from "node:fs/promises";

import { z } from "zod";

export const CURRENT_SCANNER_POLICY_VERSION = "4" as const;
export const CURRENT_SCANNER_POLICY_PATH =
  "config/scanner-policy.v4.json" as const;
export const CURRENT_CONTEXTUAL_REVIEW_POLICY_VERSION = "4" as const;
export const CURRENT_CONTEXTUAL_REVIEW_POLICY_PATH =
  "config/contextual-review.v4.json" as const;

const scannerPolicyShape = {
  queue: z.strictObject({
    batchSize: z.literal(5),
    maxParallel: z.literal(2),
  }),
  history: z.strictObject({ maxCommits: z.literal(20) }),
  inventory: z.strictObject({
    maxFiles: z.literal(500_000),
    maxTotalBytes: z.literal(5_368_709_120),
    maxFileBytes: z.literal(268_435_456),
    maxArchiveDepth: z.literal(4),
    maxExpandedArchiveBytes: z.literal(1_073_741_824),
    maxCompressionRatio: z.literal(200),
  }),
  commands: z.strictObject({
    timeoutMs: z.literal(2_700_000),
    maxOutputBytes: z.literal(104_857_600),
  }),
  retry: z.strictObject({
    modelReplyMinutesFromInitialFailure: z.tuple([
      z.literal(5),
      z.literal(10),
      z.literal(15),
    ]),
    hoursFromInitialFailure: z.tuple([
      z.literal(1),
      z.literal(2),
      z.literal(3),
    ]),
  }),
};

export const ScannerPolicyV3Schema = z.strictObject({
  version: z.literal("3"),
  ...scannerPolicyShape,
});

export type ScannerPolicyV3 = z.infer<typeof ScannerPolicyV3Schema>;

export const JavascriptAnalysisPolicySchema = z.strictObject({
  maxCandidates: z.literal(10_000),
  maxCandidateBytes: z.literal(536_870_912),
  maxTransformInputBytes: z.literal(16_777_216),
  transformTimeoutMs: z.literal(30_000),
  maxWorkerOldGenerationMb: z.literal(512),
  maxDerivativeBytes: z.literal(16_777_216),
  maxDerivativeBytesPerCandidate: z.literal(67_108_864),
  maxTotalDerivativeBytes: z.literal(268_435_456),
  maxDerivativesPerCandidate: z.literal(64),
  maxRecursionDepth: z.literal(3),
  maxDecodedLiteralsPerRepresentation: z.literal(256),
  maxEvidenceCharactersPerFinding: z.literal(24_000),
  maxPreparedEvidenceBytes: z.literal(20_000_000),
  analysisTimeoutMs: z.literal(1_200_000),
});

export const ScannerPolicyV4Schema = z.strictObject({
  version: z.literal("4"),
  ...scannerPolicyShape,
  javascriptAnalysis: JavascriptAnalysisPolicySchema,
});

export type ScannerPolicyV4 = z.infer<typeof ScannerPolicyV4Schema>;
export type ScannerPolicy = ScannerPolicyV3 | ScannerPolicyV4;

export const ScannerPinsSchema = z.strictObject({
  gitleaks: z.strictObject({
    version: z.literal("8.30.1"),
    url: z.literal(
      "https://github.com/gitleaks/gitleaks/releases/download/v8.30.1/gitleaks_8.30.1_linux_x64.tar.gz",
    ),
    sha256: z.literal(
      "551f6fc83ea457d62a0d98237cbad105af8d557003051f41f3e7ca7b3f2470eb",
    ),
  }),
  opengrep: z.strictObject({
    version: z.literal("1.26.0"),
    url: z.literal(
      "https://github.com/opengrep/opengrep/releases/download/v1.26.0/opengrep_manylinux_x86",
    ),
    sha256: z.literal(
      "40c21299eeddabf743b856daa843d24f9d4a027130671cd45b3b21776fd9ab26",
    ),
  }),
  osvScanner: z.strictObject({
    version: z.literal("2.4.0"),
    url: z.literal(
      "https://github.com/google/osv-scanner/releases/download/v2.4.0/osv-scanner_linux_amd64",
    ),
    sha256: z.literal(
      "15314940c10d26af9c6649f150b8a47c1262e8fc7e17b1d1029b0e479e8ed8a0",
    ),
  }),
  zizmor: z.strictObject({
    version: z.literal("1.28.0"),
    url: z.literal(
      "https://github.com/zizmorcore/zizmor/releases/download/v1.28.0/zizmor-x86_64-unknown-linux-gnu.tar.gz",
    ),
    sha256: z.literal(
      "e87b67160194884e375a46a12c57ccc904f762b53845f254fab7f17d98809c09",
    ),
  }),
  malcontent: z.strictObject({
    version: z.literal("1.25.7"),
    image: z.literal(
      "cgr.dev/chainguard/malcontent@sha256:8c976e9536ded51e277f57946bb11e5ecd16989d1f767c5c2f1423722f5c0138",
    ),
  }),
});

export type ScannerPins = z.infer<typeof ScannerPinsSchema>;

export const ContextualReviewPolicySchema = z.strictObject({
  version: z.literal(CURRENT_CONTEXTUAL_REVIEW_POLICY_VERSION),
  promptVersion: z.literal("contextual-review-v7"),
  schemaVersion: z.literal("contextual-assessment-v2"),
  maxImmediateAttempts: z.literal(3),
  maxOutputTokens: z.literal(32_768),
  maxResponseBytes: z.literal(5_000_000),
  timeoutMs: z.literal(300_000),
});

export type ContextualReviewPolicy = z.infer<
  typeof ContextualReviewPolicySchema
>;

export async function loadScannerPolicy(path: string): Promise<ScannerPolicy> {
  return z
    .union([ScannerPolicyV4Schema, ScannerPolicyV3Schema])
    .parse(JSON.parse(await readFile(path, "utf8")));
}

export async function loadScannerPins(path: string): Promise<ScannerPins> {
  return ScannerPinsSchema.parse(JSON.parse(await readFile(path, "utf8")));
}

export async function loadContextualReviewPolicy(
  path: string,
): Promise<ContextualReviewPolicy> {
  return ContextualReviewPolicySchema.parse(
    JSON.parse(await readFile(path, "utf8")),
  );
}
