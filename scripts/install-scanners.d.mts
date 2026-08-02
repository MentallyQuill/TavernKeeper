import type { ScannerPins } from "../src/config/policy.js";
import type { CommandRunner } from "./verify-scanners.mjs";

export interface ReleaseDownload {
  name: string;
  version: string;
  url: string;
  sha256: string;
  format: "tar.gz" | "executable";
  executable: string;
}

export interface ScannerArchiveEntry {
  path: string;
  type: string;
  size: number;
}

export function releaseDownloads(pins: ScannerPins): ReleaseDownload[];
export function verifyDigest(bytes: Uint8Array, expected: string): string;
export function assertSafeArchiveEntries(entries: ScannerArchiveEntry[]): void;
export function malcontentContainerWrapper(image: string): string;
export function installMalcontentContainer(spec: {
  pins: ScannerPins;
  toolsDir: string;
  run?: CommandRunner;
  write?: (
    path: string,
    data: string,
    options: { flag: string; mode: number },
  ) => Promise<unknown>;
  chmodFile?: (path: string, mode: number) => Promise<unknown>;
}): Promise<void>;
export function installScannerToolchain(spec: {
  pins: ScannerPins;
  toolsDir: string;
  fetchImpl?: typeof fetch;
  download?: (spec: ReleaseDownload & { destination: string }) => Promise<void>;
  extractArchive?: (archive: string, destination: string) => Promise<void>;
  run?: CommandRunner;
}): Promise<{ toolsDir: string; binDir: string }>;
