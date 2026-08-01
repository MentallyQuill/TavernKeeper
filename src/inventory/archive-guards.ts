import { validatePortablePaths } from "./inventory-handler.js";

export interface ArchiveEntry {
  path: string;
  compressed: number;
  expanded: number;
  depth: number;
  kind?: "file" | "directory" | "link";
}

export interface ArchiveGuardPolicy {
  maxEntries: number;
  maxDepth: number;
  maxExpandedBytes: number;
  maxCompressionRatio: number;
}

export interface ArchivePlan {
  entries: readonly ArchiveEntry[];
  compressedBytes: number;
  expandedBytes: number;
}

function isNonNegativeSafeInteger(value: number) {
  return Number.isSafeInteger(value) && value >= 0;
}

export function assertArchivePlan(
  entries: readonly ArchiveEntry[],
  policy: ArchiveGuardPolicy,
): ArchivePlan {
  if (
    !Number.isSafeInteger(policy.maxEntries) ||
    policy.maxEntries < 1 ||
    !Number.isSafeInteger(policy.maxDepth) ||
    policy.maxDepth < 0 ||
    !Number.isSafeInteger(policy.maxExpandedBytes) ||
    policy.maxExpandedBytes < 1 ||
    !Number.isFinite(policy.maxCompressionRatio) ||
    policy.maxCompressionRatio < 1
  ) {
    throw new Error("Archive guard policy is invalid.");
  }
  if (entries.length > policy.maxEntries) {
    throw new Error("archive ceiling exceeded.");
  }

  const pathResult = validatePortablePaths(entries.map((entry) => entry.path));
  if (!pathResult.ok) throw new Error("Archive contains an unsafe entry.");

  let compressedBytes = 0;
  let expandedBytes = 0;
  for (const entry of entries) {
    if (
      !isNonNegativeSafeInteger(entry.compressed) ||
      !isNonNegativeSafeInteger(entry.expanded) ||
      !isNonNegativeSafeInteger(entry.depth)
    ) {
      throw new Error("Archive entry metadata is invalid.");
    }
    if (entry.kind === "link") {
      throw new Error("Archive contains an unsafe entry.");
    }
    compressedBytes += entry.compressed;
    expandedBytes += entry.expanded;
    const entryRatio =
      entry.compressed === 0
        ? entry.expanded === 0
          ? 0
          : Number.POSITIVE_INFINITY
        : entry.expanded / entry.compressed;
    if (
      entry.depth > policy.maxDepth ||
      expandedBytes > policy.maxExpandedBytes ||
      entryRatio > policy.maxCompressionRatio ||
      !Number.isSafeInteger(compressedBytes) ||
      !Number.isSafeInteger(expandedBytes)
    ) {
      throw new Error("archive ceiling exceeded.");
    }
  }

  const aggregateRatio =
    compressedBytes === 0
      ? expandedBytes === 0
        ? 0
        : Number.POSITIVE_INFINITY
      : expandedBytes / compressedBytes;
  if (aggregateRatio > policy.maxCompressionRatio) {
    throw new Error("archive ceiling exceeded.");
  }

  return { entries, compressedBytes, expandedBytes };
}
