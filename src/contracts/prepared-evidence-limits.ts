export const MAX_PREPARED_EVIDENCE_BYTES = 20_000_000;
export const MAX_PREPARED_PAYLOAD_BYTES = 18_000_000;
export const MAX_PREPARED_MANIFEST_BYTES = 100_000;

export function assertPreparedEvidenceArtifactSize(
  bytes: number,
  maximumBytes = MAX_PREPARED_EVIDENCE_BYTES,
) {
  if (!Number.isSafeInteger(bytes) || bytes < 0 || bytes > maximumBytes)
    throw new Error("Prepared evidence artifact exceeded its size ceiling.");
}
