import { createHash } from "node:crypto";

export function targetIncidentKey(repositoryId: number, targetSha: string) {
  if (!Number.isSafeInteger(repositoryId) || repositoryId < 1)
    throw new Error("Target incident repository ID is invalid.");
  if (!/^[0-9a-f]{40}$/u.test(targetSha))
    throw new Error("Target incident SHA is invalid.");
  return createHash("sha256")
    .update(JSON.stringify(["target", repositoryId, targetSha]))
    .digest("hex");
}
