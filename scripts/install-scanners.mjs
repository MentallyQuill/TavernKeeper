import { createHash } from "node:crypto";
import { createWriteStream } from "node:fs";
import {
  chmod,
  copyFile,
  lstat,
  mkdir,
  readdir,
  rename,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import {
  dirname,
  isAbsolute,
  join,
  posix,
  relative,
  resolve,
  win32,
} from "node:path";
import { Readable, Transform } from "node:stream";
import { pipeline } from "node:stream/promises";
import { fileURLToPath } from "node:url";

import { extract as extractTar, list as listTar } from "tar";

import { loadScannerPins } from "../src/config/policy.ts";
import { resolveToolsDirectory, runCommand } from "./verify-scanners.mjs";

const scriptPath = fileURLToPath(import.meta.url);
const repositoryRoot = resolve(dirname(scriptPath), "..");
const maximumDownloadBytes = 1_073_741_824;
const maximumArchiveEntries = 10_000;
const maximumExpandedBytes = 1_073_741_824;

/**
 * @param {import("../src/config/policy.js").ScannerPins} pins
 */
export function releaseDownloads(pins) {
  return [
    {
      name: "gitleaks",
      version: pins.gitleaks.version,
      url: pins.gitleaks.url,
      sha256: pins.gitleaks.sha256,
      format: "tar.gz",
      executable: "gitleaks",
    },
    {
      name: "opengrep",
      version: pins.opengrep.version,
      url: pins.opengrep.url,
      sha256: pins.opengrep.sha256,
      format: "executable",
      executable: "opengrep",
    },
    {
      name: "osv-scanner",
      version: pins.osvScanner.version,
      url: pins.osvScanner.url,
      sha256: pins.osvScanner.sha256,
      format: "executable",
      executable: "osv-scanner",
    },
    {
      name: "zizmor",
      version: pins.zizmor.version,
      url: pins.zizmor.url,
      sha256: pins.zizmor.sha256,
      format: "tar.gz",
      executable: "zizmor",
    },
  ];
}

/** @param {Uint8Array} bytes @param {string} expected */
export function verifyDigest(bytes, expected) {
  const actual = createHash("sha256").update(bytes).digest("hex");
  if (actual !== expected.toLowerCase()) {
    throw new Error("Scanner release digest does not match its pin.");
  }
  return actual;
}

function normalizeArchivePath(path, type) {
  let normalized = path;
  while (normalized.startsWith("./")) normalized = normalized.slice(2);
  if (type === "Directory") normalized = normalized.replace(/\/+$/u, "");
  return normalized;
}

export function assertSafeArchiveEntries(entries) {
  if (entries.length > maximumArchiveEntries) {
    throw new Error("Scanner archive exceeds its entry ceiling.");
  }
  const identities = new Set();
  let expandedBytes = 0;
  for (const entry of entries) {
    if (!Number.isSafeInteger(entry.size) || entry.size < 0) {
      throw new Error("Scanner archive contains invalid metadata.");
    }
    if (!["Directory", "File", "OldFile"].includes(entry.type)) {
      throw new Error("Scanner archive contains a link or unsupported entry.");
    }
    const path = normalizeArchivePath(entry.path, entry.type);
    if (!path && entry.type === "Directory") continue;
    const segments = path.split("/");
    const unsafeSegment = segments.some((segment) => {
      const stem = segment.split(".", 1)[0]?.toUpperCase() ?? "";
      return (
        !segment ||
        segment === "." ||
        segment === ".." ||
        /[. ]$/u.test(segment) ||
        /^(?:CON|PRN|AUX|NUL|COM[1-9]|LPT[1-9])$/u.test(stem)
      );
    });
    if (
      !path ||
      posix.isAbsolute(path) ||
      win32.isAbsolute(path) ||
      path.includes("\\") ||
      unsafeSegment ||
      segments.length > 20 ||
      /[\u0000-\u001F\u007F-\u009F\u202A-\u202E\u2066-\u2069]/u.test(path) ||
      /[\uD800-\uDFFF]/u.test(path)
    ) {
      throw new Error("Scanner archive contains an unsafe path.");
    }
    const identity = path.normalize("NFC").toLowerCase();
    if (identities.has(identity)) {
      throw new Error("Scanner archive contains ambiguous paths.");
    }
    identities.add(identity);
    expandedBytes += entry.size;
    if (
      !Number.isSafeInteger(expandedBytes) ||
      expandedBytes > maximumExpandedBytes
    ) {
      throw new Error("Scanner archive exceeds its expansion ceiling.");
    }
  }
}

async function downloadVerified({ url, sha256, destination, fetchImpl }) {
  const temporary = `${destination}.part`;
  await rm(temporary, { force: true });
  const response = await fetchImpl(url, {
    redirect: "follow",
    headers: { accept: "application/octet-stream" },
  });
  if (!response.ok || !response.body) {
    throw new Error(
      `Scanner release download failed with HTTP ${response.status}.`,
    );
  }
  const finalUrl = new URL(response.url || url);
  if (
    finalUrl.protocol !== "https:" ||
    !(
      finalUrl.hostname === "github.com" ||
      finalUrl.hostname.endsWith(".githubusercontent.com")
    )
  ) {
    throw new Error(
      "Scanner release redirected outside the GitHub asset boundary.",
    );
  }
  const hash = createHash("sha256");
  let bytes = 0;
  const digestStream = new Transform({
    transform(chunk, _encoding, callback) {
      bytes += chunk.length;
      if (bytes > maximumDownloadBytes) {
        callback(new Error("Scanner release exceeds its download ceiling."));
        return;
      }
      hash.update(chunk);
      callback(null, chunk);
    },
  });
  try {
    await pipeline(
      Readable.fromWeb(response.body),
      digestStream,
      createWriteStream(temporary, { flags: "wx", mode: 0o600 }),
    );
    const actual = hash.digest("hex");
    if (actual !== sha256.toLowerCase()) {
      throw new Error("Scanner release digest does not match its pin.");
    }
    await rename(temporary, destination);
  } catch (error) {
    await rm(temporary, { force: true });
    throw error;
  }
}

async function inspectAndExtractArchive(archivePath, destination) {
  const entries = [];
  await listTar({
    file: archivePath,
    strict: true,
    maxDecompressionRatio: 200,
    onReadEntry(entry) {
      entries.push({ path: entry.path, type: entry.type, size: entry.size });
    },
  });
  assertSafeArchiveEntries(entries);
  await mkdir(destination, { recursive: true });
  await extractTar({
    file: archivePath,
    cwd: destination,
    strict: true,
    preserveOwner: false,
    preservePaths: false,
    noMtime: true,
    chmod: false,
    unlink: true,
    maxDecompressionRatio: 200,
  });
}

async function findRegularExecutable(root, expectedName) {
  const matches = [];
  const pending = [root];
  while (pending.length > 0) {
    const directory = pending.pop();
    if (!directory) break;
    for (const entry of await readdir(directory, { withFileTypes: true })) {
      const path = join(directory, entry.name);
      if (entry.isSymbolicLink()) {
        throw new Error("Extracted scanner archive contains a link.");
      }
      if (entry.isDirectory()) pending.push(path);
      else if (entry.isFile() && entry.name === expectedName)
        matches.push(path);
    }
  }
  if (matches.length !== 1 || !(await lstat(matches[0])).isFile()) {
    throw new Error(
      `Scanner archive did not contain exactly one ${expectedName}.`,
    );
  }
  return matches[0];
}

async function installRelease({
  release,
  toolsDir,
  fetchImpl,
  download,
  extractArchive,
}) {
  const downloadsDir = join(toolsDir, "downloads");
  const binDir = join(toolsDir, "bin");
  await mkdir(downloadsDir, { recursive: true });
  await mkdir(binDir, { recursive: true });
  const downloadPath = join(
    downloadsDir,
    `${release.name}-${release.version}${release.format === "tar.gz" ? ".tar.gz" : ".bin"}`,
  );
  await download({
    ...release,
    destination: downloadPath,
    fetchImpl,
  });
  const destination = join(binDir, release.executable);
  if (release.format === "tar.gz") {
    const staging = join(toolsDir, "staging", release.name);
    await rm(staging, { recursive: true, force: true });
    await extractArchive(downloadPath, staging);
    await copyFile(
      await findRegularExecutable(staging, release.executable),
      destination,
    );
  } else {
    await copyFile(downloadPath, destination);
  }
  await chmod(destination, 0o755);
}

async function runChecked(run, spec, label) {
  const result = await run(spec);
  if (result.code !== 0) {
    const detail = `${result.stdout}\n${result.stderr}`
      .replace(/[\u0000-\u001F\u007F]/gu, " ")
      .trim()
      .slice(0, 2_000);
    throw new Error(`${label} failed${detail ? `: ${detail}` : "."}`);
  }
  return `${result.stdout}\n${result.stderr}`;
}

export function malcontentContainerWrapper(image) {
  return [
    "#!/bin/bash",
    "set -euo pipefail",
    `readonly image=${JSON.stringify(image)}`,
    "readonly docker=/usr/bin/docker",
    'readonly host_uid="$(/usr/bin/id -u)"',
    'readonly host_gid="$(/usr/bin/id -g)"',
    'if [[ ! -x "$docker" ]]; then',
    '  echo "The trusted Docker runtime is unavailable." >&2',
    "  exit 127",
    "fi",
    'if [[ "$#" -eq 1 && "$1" == "--version" ]]; then',
    '  exec "$docker" run --rm --pull=never --network=none --read-only --cap-drop=ALL --security-opt=no-new-privileges --pids-limit=512 --user="$host_uid:$host_gid" "$image" --version',
    "fi",
    'if [[ -z "${XDG_CACHE_HOME:-}" ]]; then',
    '  echo "The isolated Malcontent cache directory is unavailable." >&2',
    "  exit 2",
    "fi",
    '/bin/mkdir -p -- "$XDG_CACHE_HOME"',
    'exec "$docker" run --rm --pull=never --network=none --read-only --cap-drop=ALL --security-opt=no-new-privileges --pids-limit=512 --user="$host_uid:$host_gid" --tmpfs "/tmp:rw,noexec,nosuid,size=1073741824,uid=$host_uid,gid=$host_gid" --mount "type=bind,source=$PWD,target=$PWD,readonly" --mount "type=bind,source=$XDG_CACHE_HOME,target=$XDG_CACHE_HOME" --workdir "$PWD" --env NO_COLOR=1 --env "XDG_CACHE_HOME=$XDG_CACHE_HOME" "$image" "$@"',
    "",
  ].join("\n");
}

export async function installMalcontentContainer({
  pins,
  toolsDir,
  run = runCommand,
  write = writeFile,
  chmodFile = chmod,
}) {
  const executable = join(toolsDir, "bin", "malcontent");
  const home = join(toolsDir, "home");
  const temporary = join(toolsDir, "tmp");
  const env = {
    HOME: home,
    LANG: "C.UTF-8",
    LC_ALL: "C.UTF-8",
    PATH: process.env.PATH || "",
    TMP: temporary,
    TEMP: temporary,
    TMPDIR: temporary,
  };
  await mkdir(join(toolsDir, "bin"), { recursive: true });
  await mkdir(home, { recursive: true });
  await mkdir(temporary, { recursive: true });
  const docker = "/usr/bin/docker";
  await runChecked(
    run,
    {
      command: docker,
      args: ["pull", pins.malcontent.image],
      cwd: toolsDir,
      env,
      timeoutMs: 300_000,
      maxOutputBytes: 4_194_304,
    },
    "Malcontent pinned image pull",
  );
  const inspected = await runChecked(
    run,
    {
      command: docker,
      args: [
        "image",
        "inspect",
        "--format={{index .RepoDigests 0}}",
        pins.malcontent.image,
      ],
      cwd: toolsDir,
      env,
    },
    "Malcontent pinned image inspection",
  );
  if (inspected.trim() !== pins.malcontent.image) {
    throw new Error(
      "Malcontent image inspection did not match its digest pin.",
    );
  }
  await write(executable, malcontentContainerWrapper(pins.malcontent.image), {
    flag: "wx",
    mode: 0o700,
  });
  await chmodFile(executable, 0o755);
}

export async function installScannerToolchain({
  pins,
  toolsDir,
  fetchImpl = fetch,
  download = downloadVerified,
  extractArchive = inspectAndExtractArchive,
  run = runCommand,
}) {
  for (const release of releaseDownloads(pins)) {
    await installRelease({
      release,
      toolsDir,
      fetchImpl,
      download,
      extractArchive,
    });
  }
  await installMalcontentContainer({ pins, toolsDir, run });
  return { toolsDir, binDir: join(toolsDir, "bin") };
}

async function main() {
  if (process.platform !== "linux" || process.arch !== "x64") {
    throw new Error("Pinned scanner installation requires a Linux x64 runner.");
  }
  const pins = await loadScannerPins(
    join(repositoryRoot, "config", "scanners.v1.json"),
  );
  const toolsDir = resolveToolsDirectory();
  const temporaryRoot = resolve(process.env.RUNNER_TEMP || tmpdir());
  const child = relative(temporaryRoot, toolsDir);
  if (!child || child.startsWith("..") || isAbsolute(child)) {
    throw new Error(
      "Scanner installation directory escaped runner temporary storage.",
    );
  }
  await installScannerToolchain({ pins, toolsDir });
  process.stdout.write(`Installed pinned scanners in ${toolsDir}\n`);
}

if (process.argv[1] && resolve(process.argv[1]) === scriptPath) {
  main().catch((error) => {
    process.stderr.write(
      `${error instanceof Error ? error.message : "Scanner installation failed."}\n`,
    );
    process.exitCode = 1;
  });
}
