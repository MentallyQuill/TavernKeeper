import { randomUUID } from "node:crypto";
import { readFile, rename, rm, writeFile } from "node:fs/promises";
import { pathToFileURL } from "node:url";

import {
  classifyFailure,
  type FailureDescriptor,
  type FailureFallback,
} from "../operations/failure.js";

export async function readJsonFile(path: string): Promise<unknown> {
  return JSON.parse(await readFile(path, "utf8"));
}

export async function writeJsonFile(path: string, value: unknown) {
  const temporary = `${path}.${randomUUID()}.tmp`;
  try {
    await writeFile(temporary, `${JSON.stringify(value, null, 2)}\n`, {
      flag: "wx",
    });
    await rename(temporary, path);
  } finally {
    await rm(temporary, { force: true });
  }
}

export function requiredEnvironment(
  environment: NodeJS.ProcessEnv,
  name: string,
) {
  const value = environment[name];
  if (value === undefined || value.trim() === "")
    throw new Error(`Required environment setting is missing: ${name}`);
  return value;
}

export async function fetchFixedJson(url: string, maximumBytes = 10_000_000) {
  const response = await fetch(url, {
    redirect: "error",
    headers: { accept: "application/json" },
    signal: AbortSignal.timeout(60_000),
  });
  if (!response.ok) throw new Error("Trusted JSON endpoint did not respond.");
  const declared = Number(response.headers.get("content-length") ?? "0");
  if (Number.isFinite(declared) && declared > maximumBytes)
    throw new Error("Trusted JSON response exceeded its size ceiling.");
  const text = await response.text();
  if (Buffer.byteLength(text, "utf8") > maximumBytes)
    throw new Error("Trusted JSON response exceeded its size ceiling.");
  return JSON.parse(text) as unknown;
}

export function isDirectExecution(metaUrl: string) {
  return (
    process.argv[1] !== undefined &&
    pathToFileURL(process.argv[1]).href === metaUrl
  );
}

export function safeCliErrorRecord(
  error: unknown,
  fallback?: FailureFallback,
): FailureDescriptor {
  return classifyFailure(error, fallback);
}

export function runJsonCli(
  main: () => Promise<unknown>,
  fallback?: FailureFallback,
) {
  void main()
    .then((result) => {
      process.stdout.write(`${JSON.stringify(result)}\n`);
    })
    .catch(async (error: unknown) => {
      const record = safeCliErrorRecord(error, fallback);
      const failureOutput = process.env.TAVERNKEEPER_ERROR_OUTPUT;
      if (failureOutput !== undefined)
        try {
          await writeJsonFile(failureOutput, record);
        } catch {
          // The stderr record below remains deliberately body-free.
        }
      process.stderr.write(`${JSON.stringify(record)}\n`);
      process.exitCode = 1;
    });
}
