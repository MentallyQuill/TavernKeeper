import type { Inventory, InventoryFile } from "./inventory-handler.js";

export const excludedCategories = [
  "dependency_lockfiles",
  "vendored_dependencies",
  "generated_bundles",
  "minified_files",
  "binaries",
  "archives",
  "oversized_files",
  "unsafe_entries",
] as const;

export type ExcludedCategory = (typeof excludedCategories)[number];

export interface FileByteTotals {
  files: number;
  bytes: number;
}

export interface InventoryClassification {
  modelEligible: InventoryFile[];
  applicability: {
    osv: boolean;
    zizmor: boolean;
    malcontent: boolean;
  };
  scannerInputs: {
    osv: InventoryFile[];
    zizmor: InventoryFile[];
    malcontent: InventoryFile[];
  };
  excluded: Record<ExcludedCategory, FileByteTotals>;
}

const lockfiles = new Set([
  "bun.lock",
  "bun.lockb",
  "cargo.lock",
  "composer.lock",
  "conan.lock",
  "gemfile.lock",
  "mix.lock",
  "npm-shrinkwrap.json",
  "package-lock.json",
  "packages.lock.json",
  "pipfile.lock",
  "pnpm-lock.yaml",
  "poetry.lock",
  "pubspec.lock",
  "yarn.lock",
]);

const osvFiles = new Set([
  ...lockfiles,
  "cargo.toml",
  "composer.json",
  "gemfile",
  "go.mod",
  "package.json",
  "packages.config",
  "pyproject.toml",
  "requirements.txt",
]);

const vendoredSegments = new Set([
  ".venv",
  "bower_components",
  "deps",
  "node_modules",
  "site-packages",
  "third-party",
  "third_party",
  "vendor",
  "vendors",
]);

const generatedSegments = new Set([
  ".next",
  ".nuxt",
  "build",
  "coverage",
  "dist",
  "generated",
  "out",
]);

function basename(path: string) {
  return path.slice(path.lastIndexOf("/") + 1).toLowerCase();
}

function segments(path: string) {
  return path.toLowerCase().split("/");
}

function isArchive(path: string) {
  return /\.(?:7z|apk|bz2|deb|ear|gz|jar|rar|rpm|tar|tar\.bz2|tar\.gz|tar\.xz|tgz|war|xz|zip)$/iu.test(
    path,
  );
}

function isWorkflow(path: string) {
  const normalized = path.toLowerCase();
  return (
    /^\.github\/workflows\/[^/]+\.ya?ml$/u.test(normalized) ||
    /(?:^|\/)action\.ya?ml$/u.test(normalized)
  );
}

function isExecutable(file: InventoryFile) {
  return (
    file.executable === true ||
    /\.(?:bin|com|dll|dylib|exe|msi|scr|so)$/iu.test(file.path)
  );
}

function exclusionFor(file: InventoryFile): ExcludedCategory | null {
  const name = basename(file.path);
  const pathSegments = segments(file.path);
  if (file.kind === "oversized") return "oversized_files";
  if (isArchive(file.path)) return "archives";
  if (file.kind === "binary") return "binaries";
  if (lockfiles.has(name)) return "dependency_lockfiles";
  if (pathSegments.some((segment) => vendoredSegments.has(segment))) {
    return "vendored_dependencies";
  }
  if (
    pathSegments.some((segment) => generatedSegments.has(segment)) ||
    /(?:^|[.-])bundle(?:d)?[.-]/iu.test(name) ||
    name.endsWith(".map")
  ) {
    return "generated_bundles";
  }
  if (file.likelyMinified === true || /\.min\.[^.]+$/iu.test(name)) {
    return "minified_files";
  }
  return null;
}

export function classifyInventory(
  inventory: Inventory,
): InventoryClassification {
  const excluded = Object.fromEntries(
    excludedCategories.map((category) => [category, { files: 0, bytes: 0 }]),
  ) as Record<ExcludedCategory, FileByteTotals>;
  const modelEligible: InventoryFile[] = [];
  const scannerInputs: InventoryClassification["scannerInputs"] = {
    osv: [],
    zizmor: [],
    malcontent: [],
  };

  for (const file of inventory.files) {
    const name = basename(file.path);
    const category = exclusionFor(file);
    if (category) {
      excluded[category].files += 1;
      excluded[category].bytes += file.bytes;
    } else if (file.kind === "text") {
      modelEligible.push(file);
    }

    if (osvFiles.has(name)) scannerInputs.osv.push(file);
    if (isWorkflow(file.path)) scannerInputs.zizmor.push(file);
    if (isArchive(file.path) || file.kind === "binary" || isExecutable(file)) {
      scannerInputs.malcontent.push(file);
    }
  }

  return {
    modelEligible,
    applicability: {
      osv: scannerInputs.osv.length > 0,
      zizmor: scannerInputs.zizmor.length > 0,
      malcontent: scannerInputs.malcontent.length > 0,
    },
    scannerInputs,
    excluded,
  };
}
