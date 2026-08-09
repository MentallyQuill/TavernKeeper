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

function bundleLikePath(path: string) {
  return /(?:^|[/._-])(?:bundle|min|packed|prod|production)(?:[/._-]|$)/iu.test(
    path,
  );
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
      requiresNormalization:
        language === "javascript" &&
        (file.likelyMinified === true || bundleLikePath(file.path)),
    });
  }
  return candidates.sort((left, right) => left.path.localeCompare(right.path));
}
