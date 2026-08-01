import { access, mkdir, readFile, writeFile } from "node:fs/promises";
import { join } from "node:path";
import { z } from "zod";

import {
  decodeTransportKey,
  decryptTransport,
  encryptTransport,
} from "../publish/encrypted-transport.js";
import { ScanTransitionSchema } from "./transition.js";
import {
  isDirectExecution,
  readJsonFile,
  requiredEnvironment,
  runJsonCli,
  writeJsonFile,
} from "./io.js";

const TransportPayloadSchema = z.strictObject({
  schema_version: z.literal(1),
  candidate: z.unknown().nullable(),
  transition: ScanTransitionSchema,
});

async function exists(path: string) {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

async function main() {
  const operation = process.argv[2];
  const key = decodeTransportKey(
    requiredEnvironment(process.env, "TAVERNKEEPER_ARTIFACT_KEY"),
  );
  if (operation === "encrypt") {
    const output = process.argv[3] ?? "outcome.enc";
    const candidatePath = process.argv[4] ?? "candidate.json";
    const transitionPath = process.argv[5] ?? "transition.json";
    const payload = TransportPayloadSchema.parse({
      schema_version: 1,
      candidate: (await exists(candidatePath))
        ? await readJsonFile(candidatePath)
        : null,
      transition: await readJsonFile(transitionPath),
    });
    await writeFile(output, encryptTransport(payload, key), { flag: "wx" });
    return { status: "encrypted" };
  }
  if (operation === "decrypt") {
    const input = process.argv[3] ?? "outcome.enc";
    const outputRoot = process.argv[4] ?? "artifacts/scan";
    const payload = TransportPayloadSchema.parse(
      decryptTransport(await readFile(input), key),
    );
    await mkdir(outputRoot, { recursive: true });
    await writeJsonFile(
      join(outputRoot, "transition.json"),
      payload.transition,
    );
    if (payload.candidate !== null)
      await writeJsonFile(
        join(outputRoot, "candidate.json"),
        payload.candidate,
      );
    return { status: "decrypted" };
  }
  throw new Error("Artifact transport operation must be encrypt or decrypt.");
}

if (isDirectExecution(import.meta.url)) runJsonCli(main);
