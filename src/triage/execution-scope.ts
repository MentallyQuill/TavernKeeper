import { createHash } from "node:crypto";
import { lstat, readFile } from "node:fs/promises";
import { isAbsolute, posix, relative, resolve, sep } from "node:path";

import { z } from "zod";

import type { InventoryFile } from "../inventory/inventory-handler.js";

export const ExecutionScopeSchema = z.enum([
  "runtime",
  "install-update",
  "automation",
  "tooling-only",
  "test-documentation-data",
  "unknown",
]);

export type ExecutionScope = z.infer<typeof ExecutionScopeSchema>;

export interface ExecutionScopeLimits {
  maxFiles: number;
  maxTotalBytes: number;
  maxFileBytes: number;
}

interface LoadedSource {
  path: string;
  content: string;
}

const codeOrControlFile =
  /(?:^|\/)(?:package\.json|action\.ya?ml)$|\.(?:[cm]?[jt]sx?|json|ya?ml|py|sh|ps1)$/iu;
const importPattern =
  /(?:\b(?:import|export)\s+(?:[^;'"]{0,4096}?\s+from\s+)?|\brequire\s*\(\s*|\bimport\s*\(\s*)["']([^"']+)["']/gu;
const commandPathPattern =
  /(?:^|[\s"'])(\.?\/?[A-Za-z0-9_@.-]+(?:\/[A-Za-z0-9_@.-]+)*\.(?:[cm]?[jt]sx?|py|sh|ps1))(?:$|[\s"'])/giu;
const packageScriptPattern =
  /\b(?:npm\s+(?:run|run-script)\s+|pnpm\s+(?:run\s+)?|yarn\s+(?:run\s+)?)([A-Za-z0-9_.:@/-]+)/giu;
const actionEntrypointPattern =
  /^\s*(?:main|pre|post):\s*["']?([^\s"'#]+)["']?\s*$/gimu;
const computedModuleLoadPattern = /\b(?:import|require)\s*\(\s*(?!["'])/u;

function testDocumentationOrData(path: string) {
  const normalized = path.toLowerCase();
  const segments = normalized.split("/");
  const name = segments.at(-1) ?? normalized;
  return (
    segments.some((segment) =>
      ["test", "tests", "__tests__", "fixture", "fixtures", "docs"].includes(
        segment,
      ),
    ) ||
    /(?:^|\.)(?:test|spec)\.[^.]+$/u.test(name) ||
    /^(?:readme|license)(?:\.|$)/u.test(name) ||
    /\.(?:md|mdx|rst|txt)$/u.test(name)
  );
}

function toolingPath(path: string) {
  const normalized = path.toLowerCase();
  const segments = normalized.split("/");
  const name = segments.at(-1) ?? normalized;
  return (
    segments.includes("scripts") ||
    segments.includes("tools") ||
    segments.includes(".github") ||
    /(?:^|\.)(?:config|rc)\.[^.]+$/u.test(name)
  );
}

function workflowPath(path: string) {
  return (
    /^\.github\/workflows\/[^/]+\.ya?ml$/iu.test(path) ||
    /(?:^|\/)action\.ya?ml$/iu.test(path)
  );
}

function repositoryPath(root: string, path: string) {
  const repositoryRoot = resolve(root);
  const absolute = resolve(repositoryRoot, ...path.split("/"));
  const portable = relative(repositoryRoot, absolute);
  if (
    isAbsolute(path) ||
    portable === "" ||
    portable === ".." ||
    portable.startsWith(`..${sep}`)
  )
    return undefined;
  return { absolute, path: portable.split(sep).join("/") };
}

function validLimits(limits: ExecutionScopeLimits) {
  return (
    Number.isInteger(limits.maxFiles) &&
    limits.maxFiles > 0 &&
    Number.isInteger(limits.maxTotalBytes) &&
    limits.maxTotalBytes > 0 &&
    Number.isInteger(limits.maxFileBytes) &&
    limits.maxFileBytes > 0
  );
}

async function loadVerifiedSource(root: string, file: InventoryFile) {
  const target = repositoryPath(root, file.path);
  if (target === undefined || file.kind !== "text") return undefined;
  const metadata = await lstat(target.absolute);
  if (!metadata.isFile() || metadata.isSymbolicLink()) return undefined;
  const bytes = await readFile(target.absolute);
  if (
    bytes.length !== file.bytes ||
    createHash("sha256").update(bytes).digest("hex") !== file.sha256
  )
    return undefined;
  try {
    const content = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    return content.includes("\0") ? undefined : content;
  } catch {
    return undefined;
  }
}

function scalarPaths(value: unknown): string[] {
  if (typeof value === "string") return [value];
  if (Array.isArray(value)) return value.flatMap(scalarPaths);
  if (value !== null && typeof value === "object")
    return Object.values(value).flatMap(scalarPaths);
  return [];
}

function commandPaths(command: string) {
  return [...command.matchAll(commandPathPattern)].flatMap((match) =>
    match[1] === undefined ? [] : [match[1].replace(/^\.\//u, "")],
  );
}

function packageScriptNames(command: string) {
  return [...command.matchAll(packageScriptPattern)].flatMap((match) =>
    match[1] === undefined ? [] : [match[1]],
  );
}

function resolveSourcePath(
  from: string,
  specifier: string,
  sourcePaths: ReadonlySet<string>,
) {
  if (!specifier.startsWith(".")) return undefined;
  const base = posix.normalize(posix.join(posix.dirname(from), specifier));
  if (base === ".." || base.startsWith("../") || base.startsWith("/"))
    return undefined;
  const candidates = [
    base,
    ...["js", "mjs", "cjs", "ts", "tsx", "jsx", "json"].map(
      (extension) => `${base}.${extension}`,
    ),
    ...["js", "mjs", "cjs", "ts", "tsx", "jsx", "json"].map(
      (extension) => `${base}/index.${extension}`,
    ),
  ];
  return candidates.find((candidate) => sourcePaths.has(candidate));
}

function dependencies(source: LoadedSource, sourcePaths: ReadonlySet<string>) {
  return [...source.content.matchAll(importPattern)].flatMap((match) => {
    const target =
      match[1] === undefined
        ? undefined
        : resolveSourcePath(source.path, match[1], sourcePaths);
    return target === undefined ? [] : [target];
  });
}

function conventionalRuntimeRoots(sourcePaths: ReadonlySet<string>) {
  const candidates = [
    "index.js",
    "index.mjs",
    "index.cjs",
    "index.ts",
    "script.js",
    "server.js",
    "server.mjs",
    "src/index.js",
    "src/index.mjs",
    "src/index.ts",
  ];
  return candidates.filter((path) => sourcePaths.has(path));
}

function addResolvedRoot(
  roots: Set<string>,
  path: string,
  sourcePaths: ReadonlySet<string>,
) {
  const normalized = path.replace(/^\.\//u, "");
  const resolved = resolveSourcePath(
    "package.json",
    `./${normalized}`,
    sourcePaths,
  );
  if (resolved !== undefined) roots.add(resolved);
  else if (sourcePaths.has(normalized)) roots.add(normalized);
}

function addRelativeRoot(
  roots: Set<string>,
  from: string,
  path: string,
  sourcePaths: ReadonlySet<string>,
) {
  const resolved = resolveSourcePath(
    from,
    `./${path.replace(/^\.\//u, "")}`,
    sourcePaths,
  );
  if (resolved !== undefined) roots.add(resolved);
}

function addPackageScriptRoots(
  roots: Set<string>,
  names: readonly string[],
  scripts: ReadonlyMap<string, string>,
  sourcePaths: ReadonlySet<string>,
) {
  const pending = [...names];
  const visited = new Set<string>();
  while (pending.length > 0) {
    const name = pending.shift()!;
    if (visited.has(name)) continue;
    visited.add(name);
    const command = scripts.get(name);
    if (command === undefined) continue;
    for (const path of commandPaths(command))
      addResolvedRoot(roots, path, sourcePaths);
    pending.push(...packageScriptNames(command));
  }
}

function propagate(
  roots: ReadonlySet<string>,
  sourceByPath: ReadonlyMap<string, LoadedSource>,
) {
  const visited = new Set<string>();
  const pending = [...roots];
  const paths = new Set(sourceByPath.keys());
  while (pending.length > 0) {
    const path = pending.shift()!;
    if (visited.has(path)) continue;
    visited.add(path);
    const source = sourceByPath.get(path);
    if (source === undefined) continue;
    for (const dependency of dependencies(source, paths))
      if (!visited.has(dependency)) pending.push(dependency);
  }
  return visited;
}

export async function analyzeExecutionScopes(input: {
  root: string;
  files: readonly InventoryFile[];
  limits: ExecutionScopeLimits;
}): Promise<ReadonlyMap<string, ExecutionScope>> {
  if (!validLimits(input.limits))
    throw new Error("Execution-scope limits are invalid.");
  const ordered = [...input.files].sort((left, right) =>
    left.path.localeCompare(right.path),
  );
  const relevant = ordered.filter(
    (file) => file.kind === "text" && codeOrControlFile.test(file.path),
  );
  let remainingBytes = input.limits.maxTotalBytes;
  let analysisComplete = relevant.length <= input.limits.maxFiles;
  const sourceByPath = new Map<string, LoadedSource>();
  for (const file of relevant.slice(0, input.limits.maxFiles)) {
    if (file.bytes > input.limits.maxFileBytes || file.bytes > remainingBytes) {
      analysisComplete = false;
      continue;
    }
    remainingBytes -= file.bytes;
    const content = await loadVerifiedSource(input.root, file);
    if (content === undefined) {
      analysisComplete = false;
      continue;
    }
    sourceByPath.set(file.path, { path: file.path, content });
  }

  const sourcePaths = new Set(sourceByPath.keys());
  const runtimeRoots = new Set(conventionalRuntimeRoots(sourcePaths));
  const installRoots = new Set<string>();
  const automationRoots = new Set<string>();
  const packageScripts = new Map<string, string>();
  const packageSource = sourceByPath.get("package.json");
  if (packageSource !== undefined)
    try {
      const manifest = JSON.parse(packageSource.content) as {
        main?: unknown;
        module?: unknown;
        exports?: unknown;
        bin?: unknown;
        scripts?: Record<string, unknown>;
      };
      for (const path of [
        ...scalarPaths(manifest.main),
        ...scalarPaths(manifest.module),
        ...scalarPaths(manifest.exports),
        ...scalarPaths(manifest.bin),
      ])
        addResolvedRoot(runtimeRoots, path, sourcePaths);
      for (const [name, command] of Object.entries(manifest.scripts ?? {}))
        if (typeof command === "string") packageScripts.set(name, command);
      for (const [name, command] of packageScripts) {
        if (
          /^(?:preinstall|install|postinstall|update|upgrade|migrate|migration)$/iu.test(
            name,
          )
        ) {
          for (const path of commandPaths(command))
            addResolvedRoot(installRoots, path, sourcePaths);
          addPackageScriptRoots(
            installRoots,
            packageScriptNames(command),
            packageScripts,
            sourcePaths,
          );
        }
      }
    } catch {
      analysisComplete = false;
    }

  const extensionManifestSource = sourceByPath.get("manifest.json");
  if (extensionManifestSource !== undefined)
    try {
      const manifest = JSON.parse(extensionManifestSource.content) as {
        js?: unknown;
      };
      if (typeof manifest.js === "string")
        addResolvedRoot(runtimeRoots, manifest.js, sourcePaths);
      else if (manifest.js !== undefined) analysisComplete = false;
    } catch {
      analysisComplete = false;
    }

  for (const source of sourceByPath.values())
    if (workflowPath(source.path)) {
      automationRoots.add(source.path);
      for (const path of commandPaths(source.content))
        addResolvedRoot(automationRoots, path, sourcePaths);
      addPackageScriptRoots(
        automationRoots,
        packageScriptNames(source.content),
        packageScripts,
        sourcePaths,
      );
      if (/(?:^|\/)action\.ya?ml$/iu.test(source.path))
        for (const match of source.content.matchAll(actionEntrypointPattern))
          if (match[1] !== undefined)
            addRelativeRoot(
              automationRoots,
              source.path,
              match[1],
              sourcePaths,
            );
    }

  const runtime = propagate(runtimeRoots, sourceByPath);
  const install = propagate(installRoots, sourceByPath);
  const automation = propagate(automationRoots, sourceByPath);
  const reachable = new Set([...runtime, ...install, ...automation]);
  const inertClassificationComplete =
    analysisComplete &&
    [...reachable].every((path) => {
      const source = sourceByPath.get(path);
      return (
        source !== undefined && !computedModuleLoadPattern.test(source.content)
      );
    });
  const scopes = new Map<string, ExecutionScope>();
  for (const file of ordered) {
    let scope: ExecutionScope;
    if (runtime.has(file.path)) scope = "runtime";
    else if (install.has(file.path)) scope = "install-update";
    else if (automation.has(file.path)) scope = "automation";
    else if (testDocumentationOrData(file.path) && inertClassificationComplete)
      scope = "test-documentation-data";
    else if (
      toolingPath(file.path) &&
      inertClassificationComplete &&
      sourceByPath.has(file.path)
    )
      scope = "tooling-only";
    else scope = "unknown";
    scopes.set(file.path, scope);
  }
  return scopes;
}
