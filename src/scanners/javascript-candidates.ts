import type { InventoryFile } from "../inventory/inventory-handler.js";

const javascriptExtensions = new Set(["js", "cjs", "mjs", "jsx"]);
const typescriptExtensions = new Set(["ts", "cts", "mts", "tsx"]);

export interface JavascriptCandidate extends InventoryFile {
  language: "javascript" | "typescript";
  requiresNormalization: boolean;
}

function extension(path: string) {
  const match = /\.([^.\/]+)$/u.exec(path);
  return match?.[1]?.toLowerCase() ?? "";
}

export function selectJavascriptCandidates(
  files: readonly InventoryFile[],
): JavascriptCandidate[] {
  const candidates: JavascriptCandidate[] = [];
  for (const file of files) {
    const suffix = extension(file.path);
    const language = javascriptExtensions.has(suffix)
      ? "javascript"
      : typescriptExtensions.has(suffix)
        ? "typescript"
        : null;
    if (language === null) continue;
    candidates.push({
      ...file,
      language,
      requiresNormalization: language === "javascript",
    });
  }
  return candidates.sort((left, right) => left.path.localeCompare(right.path));
}
