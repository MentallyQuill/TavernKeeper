import { createHash } from "node:crypto";
import { lstat, readFile, readdir } from "node:fs/promises";
import { relative, resolve, sep } from "node:path";

import { err, ok, type Result } from "../core/result.js";

export type InventoryErrorCode =
  | "INVALID_ROOT"
  | "FILE_BUDGET_EXCEEDED"
  | "BYTE_BUDGET_EXCEEDED"
  | "READ_FAILED";

export interface InventorySpec {
  root: string;
  maxFiles: number;
  maxTotalBytes: number;
  maxFileBytes: number;
}

export interface InventoryFile {
  path: string;
  bytes: number;
  sha256: string;
  kind: "text" | "binary" | "oversized";
  content: string | null;
}

export interface Inventory {
  root: string;
  files: InventoryFile[];
  totalBytes: number;
}

const ignoredDirectories = new Set([".git", "node_modules"]);

function portablePath(root: string, path: string) {
  return relative(root, path).split(sep).join("/");
}

function isText(buffer: Buffer) {
  return !buffer.subarray(0, Math.min(buffer.length, 8192)).includes(0);
}

export async function inventoryRepository(
  spec: InventorySpec,
): Promise<Result<Inventory, InventoryErrorCode>> {
  const root = resolve(spec.root);
  if (
    !Number.isInteger(spec.maxFiles) ||
    spec.maxFiles < 1 ||
    !Number.isInteger(spec.maxTotalBytes) ||
    spec.maxTotalBytes < 1 ||
    !Number.isInteger(spec.maxFileBytes) ||
    spec.maxFileBytes < 1
  ) {
    return err("INVALID_ROOT", "Inventory limits must be positive integers.");
  }

  try {
    if (!(await lstat(root)).isDirectory()) {
      return err("INVALID_ROOT", "Inventory root must be a directory.");
    }

    const paths: string[] = [];
    const pending = [root];
    while (pending.length > 0) {
      const directory = pending.pop();
      if (!directory) break;
      const entries = await readdir(directory, { withFileTypes: true });
      entries.sort((left, right) => left.name.localeCompare(right.name));
      for (const entry of entries) {
        if (entry.isSymbolicLink()) continue;
        const path = resolve(directory, entry.name);
        if (entry.isDirectory()) {
          if (!ignoredDirectories.has(entry.name)) pending.push(path);
        } else if (entry.isFile()) {
          paths.push(path);
          if (paths.length > spec.maxFiles) {
            return err(
              "FILE_BUDGET_EXCEEDED",
              `Repository contains more than ${spec.maxFiles} files.`,
            );
          }
        }
      }
    }

    paths.sort((left, right) =>
      portablePath(root, left).localeCompare(portablePath(root, right)),
    );
    const files: InventoryFile[] = [];
    let totalBytes = 0;
    for (const path of paths) {
      const stats = await lstat(path);
      totalBytes += stats.size;
      if (totalBytes > spec.maxTotalBytes) {
        return err(
          "BYTE_BUDGET_EXCEEDED",
          `Repository exceeds the ${spec.maxTotalBytes}-byte inventory limit.`,
        );
      }
      if (stats.size > spec.maxFileBytes) {
        files.push({
          path: portablePath(root, path),
          bytes: stats.size,
          sha256: "",
          kind: "oversized",
          content: null,
        });
        continue;
      }
      const buffer = await readFile(path);
      const text = isText(buffer);
      files.push({
        path: portablePath(root, path),
        bytes: stats.size,
        sha256: createHash("sha256").update(buffer).digest("hex"),
        kind: text ? "text" : "binary",
        content: text ? buffer.toString("utf8") : null,
      });
    }

    return ok({ root, files, totalBytes });
  } catch (error) {
    return err(
      "READ_FAILED",
      error instanceof Error ? error.message : "Repository inventory failed.",
    );
  }
}
