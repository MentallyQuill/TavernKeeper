import { createHash } from "node:crypto";
import { createReadStream } from "node:fs";
import { lstat, open, readdir } from "node:fs/promises";
import { posix, relative, resolve, sep, win32 } from "node:path";

import { err, ok, type Result } from "../core/result.js";

export type InventoryErrorCode =
  | "INVALID_ROOT"
  | "UNSAFE_LINK"
  | "AMBIGUOUS_PATH"
  | "UNSAFE_PATH"
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
  likelyMinified?: boolean;
  executable?: boolean;
}

export interface InventoryTotals {
  files: number;
  bytes: number;
}

export interface Inventory {
  root: string;
  files: InventoryFile[];
  totals: InventoryTotals;
  /** @deprecated Use totals.bytes. */
  totalBytes: number;
}

const ignoredDirectories = new Set([".git"]);

function portablePath(root: string, path: string) {
  return relative(root, path).split(sep).join("/");
}

function isText(buffer: Buffer, complete: boolean) {
  if (buffer.includes(0)) return false;
  try {
    new TextDecoder("utf-8", { fatal: true }).decode(buffer, {
      stream: !complete,
    });
    return true;
  } catch {
    return false;
  }
}

function isLikelyMinified(sample: Buffer, totalBytes: number) {
  if (totalBytes < 4096) return false;
  const lines = sample.toString("utf8").split(/\r?\n/u);
  return lines.some((line) => Buffer.byteLength(line, "utf8") >= 4096);
}

async function hashFile(path: string) {
  const hash = createHash("sha256");
  for await (const chunk of createReadStream(path)) hash.update(chunk);
  return hash.digest("hex");
}

async function readSample(path: string, bytes: number) {
  const handle = await open(path, "r");
  try {
    const sample = Buffer.alloc(Math.min(bytes, 8192));
    const { bytesRead } = await handle.read(sample, 0, sample.length, 0);
    return sample.subarray(0, bytesRead);
  } finally {
    await handle.close();
  }
}

export function validatePortablePaths(
  paths: readonly string[],
): Result<readonly string[], InventoryErrorCode> {
  const identities = new Set<string>();
  for (const path of paths) {
    const segments = path.split("/");
    const unsafeSegment = segments.some((segment) => {
      const deviceStem = segment.split(".", 1)[0]?.toUpperCase() ?? "";
      return (
        segment.length === 0 ||
        segment === "." ||
        segment === ".." ||
        /[. ]$/u.test(segment) ||
        /^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$/u.test(deviceStem)
      );
    });
    if (
      posix.isAbsolute(path) ||
      win32.isAbsolute(path) ||
      path.includes("\\") ||
      unsafeSegment ||
      /[\u0000-\u001F\u007F-\u009F\u202A-\u202E\u2066-\u2069]/u.test(path) ||
      /[\uD800-\uDFFF]/u.test(path)
    ) {
      return err("UNSAFE_PATH", "Repository contains an unsafe portable path.");
    }
    const identity = path.normalize("NFC").toLowerCase();
    if (identities.has(identity)) {
      return err(
        "AMBIGUOUS_PATH",
        `Repository paths collide under portable identity: ${path}`,
      );
    }
    identities.add(identity);
  }
  return ok(paths);
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
        if (entry.isSymbolicLink()) {
          return err(
            "UNSAFE_LINK",
            "Repository inventory contains a symbolic link or junction.",
          );
        }
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
    const portablePaths = paths.map((path) => portablePath(root, path));
    const portableValidation = validatePortablePaths(portablePaths);
    if (!portableValidation.ok) return portableValidation;
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
          sha256: await hashFile(path),
          kind: "oversized",
          executable: (stats.mode & 0o111) !== 0,
        });
        continue;
      }
      const sample = await readSample(path, stats.size);
      const text = isText(sample, stats.size <= sample.length);
      files.push({
        path: portablePath(root, path),
        bytes: stats.size,
        sha256: await hashFile(path),
        kind: text ? "text" : "binary",
        likelyMinified: text && isLikelyMinified(sample, stats.size),
        executable: (stats.mode & 0o111) !== 0,
      });
    }

    return ok({
      root,
      files,
      totals: { files: files.length, bytes: totalBytes },
      totalBytes,
    });
  } catch (error) {
    return err(
      "READ_FAILED",
      error instanceof Error ? error.message : "Repository inventory failed.",
    );
  }
}
