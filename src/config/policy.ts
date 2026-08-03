import { readFile } from "node:fs/promises";

import { z } from "zod";

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
    hoursFromInitialFailure: z.tuple([
      z.literal(1),
      z.literal(2),
      z.literal(3),
    ]),
  }),
};

export const ScannerPolicySchema = z.strictObject({
  version: z.literal("1"),
  ...scannerPolicyShape,
  model: z.strictObject({
    protocol: z.literal("openai-compatible-chat-completions"),
    chunkBytes: z.literal(524_288),
    chunkOverlapBytes: z.literal(8_192),
    maxChunkReviewCharacters: z.literal(12_000),
    chunkReviewPolicy: z.literal("chunk-review-v2"),
    synthesisPolicy: z.literal("repository-synthesis-v2"),
  }),
});

export type ScannerPolicy = z.infer<typeof ScannerPolicySchema>;

export const ScannerPolicyV2Schema = z.strictObject({
  version: z.literal("2"),
  ...scannerPolicyShape,
});

export type ScannerPolicyV2 = z.infer<typeof ScannerPolicyV2Schema>;

const AnyScannerPolicySchema = z.discriminatedUnion("version", [
  ScannerPolicySchema,
  ScannerPolicyV2Schema,
]);

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

export function loadScannerPolicy(
  path: "config/scanner-policy.v2.json",
): Promise<ScannerPolicyV2>;
export function loadScannerPolicy(path: string): Promise<ScannerPolicy>;
export async function loadScannerPolicy(
  path: string,
): Promise<ScannerPolicy | ScannerPolicyV2> {
  return AnyScannerPolicySchema.parse(JSON.parse(await readFile(path, "utf8")));
}

export async function loadScannerPins(path: string): Promise<ScannerPins> {
  return ScannerPinsSchema.parse(JSON.parse(await readFile(path, "utf8")));
}
