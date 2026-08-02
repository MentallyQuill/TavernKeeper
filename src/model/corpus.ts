import { createHash } from "node:crypto";
import { lstat, readFile } from "node:fs/promises";
import { join } from "node:path";

import type { InventoryClassification } from "../inventory/classify.js";
import type { InventoryFile } from "../inventory/inventory-handler.js";

export interface ModelCorpusFile extends InventoryFile {
  content: string;
}

function comparePath(left: string, right: string) {
  const leftIdentity = left.toLowerCase();
  const rightIdentity = right.toLowerCase();
  if (leftIdentity !== rightIdentity)
    return leftIdentity < rightIdentity ? -1 : 1;
  return left === right ? 0 : left < right ? -1 : 1;
}

export function selectModelCorpus({
  classification,
}: {
  classification: InventoryClassification;
}): InventoryFile[] {
  return classification.modelEligible.toSorted((left, right) =>
    comparePath(left.path, right.path),
  );
}

export async function loadModelCorpus(
  root: string,
  selected: InventoryFile[],
): Promise<ModelCorpusFile[]> {
  const corpus: ModelCorpusFile[] = [];
  for (const file of selected) {
    const path = join(root, ...file.path.split("/"));
    const metadata = await lstat(path);
    if (!metadata.isFile() || metadata.isSymbolicLink())
      throw new Error("Model corpus changed after safe inventory.");
    const bytes = await readFile(path);
    if (
      bytes.length !== file.bytes ||
      createHash("sha256").update(bytes).digest("hex") !== file.sha256
    )
      throw new Error("Model corpus changed after safe inventory.");
    let content: string;
    try {
      content = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    } catch {
      throw new Error("Model corpus contains invalid UTF-8 after inventory.");
    }
    if (content.includes("\0"))
      throw new Error("Model corpus contains binary data after inventory.");
    corpus.push({ ...file, content });
  }
  return corpus;
}
