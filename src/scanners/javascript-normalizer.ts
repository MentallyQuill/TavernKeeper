import { createRequire } from "node:module";
import { pathToFileURL } from "node:url";
import { Worker } from "node:worker_threads";

export interface JavascriptNormalizerLimits {
  transformTimeoutMs: number;
  maxWorkerOldGenerationMb: number;
  maxDerivativeBytes: number;
  maxDerivativeBytesPerCandidate: number;
  maxDerivativesPerCandidate: number;
}

export interface NormalizedJavascriptDerivative {
  id: string;
  content: string;
  transform: "webcrack-normalized" | "webcrack-module";
}

export type JavascriptNormalizationLimitation =
  "parse" | "timeout" | "memory-limit" | "output-limit" | "unsupported";

export interface JavascriptNormalizationResult {
  derivatives: NormalizedJavascriptDerivative[];
  limitation?: JavascriptNormalizationLimitation;
}

interface WebcrackLikeResult {
  code: string;
  bundle:
    | {
        modules: Map<string, { code: string }>;
      }
    | undefined;
}

export type WebcrackImplementation = (
  source: string,
  options: {
    deobfuscate: false;
    unminify: true;
    unpack: true;
    jsx: false;
  },
) => Promise<WebcrackLikeResult>;

type WorkerReply =
  | {
      ok: true;
      code: string;
      modules: Array<{ id: string; code: string }>;
    }
  | {
      ok: false;
      reason: "parse" | "memory-limit" | "unsupported";
    };

const approvedOptions = {
  deobfuscate: false,
  unminify: true,
  unpack: true,
  jsx: false,
} as const;

const require = createRequire(import.meta.url);
const webcrackUrl = pathToFileURL(require.resolve("webcrack")).href;

const workerSource = `
import { parentPort, workerData } from "node:worker_threads";
const fail = (reason) => parentPort.postMessage({ ok: false, reason });
try {
  const { webcrack } = await import(workerData.webcrackUrl);
  const result = await webcrack(workerData.source, {
    deobfuscate: false,
    unminify: true,
    unpack: true,
    jsx: false,
  });
  const modules = result.bundle === undefined
    ? []
    : [...result.bundle.modules.entries()]
        .map(([id, module]) => ({ id, code: module.code }))
        .sort((left, right) => left.id.localeCompare(right.id));
  parentPort.postMessage({ ok: true, code: result.code, modules });
} catch (error) {
  const message = error instanceof Error ? error.message : String(error);
  if (/heap|memory|allocation/iu.test(message)) fail("memory-limit");
  else if (/parse|syntax|unexpected token|unterminated/iu.test(message)) fail("parse");
  else fail("unsupported");
}
`;

async function normalizeInWorker(
  source: string,
  limits: JavascriptNormalizerLimits,
): Promise<WorkerReply | { ok: false; reason: "timeout" }> {
  return new Promise((resolve) => {
    const worker = new Worker(
      new URL(`data:text/javascript,${encodeURIComponent(workerSource)}`),
      {
        workerData: {
          source,
          webcrackUrl,
        },
        resourceLimits: {
          maxOldGenerationSizeMb: limits.maxWorkerOldGenerationMb,
        },
      },
    );
    let settled = false;
    const finish = (reply: WorkerReply | { ok: false; reason: "timeout" }) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      resolve(reply);
    };
    const timer = setTimeout(() => {
      void worker.terminate();
      finish({ ok: false, reason: "timeout" });
    }, limits.transformTimeoutMs);
    worker.once("message", (reply: WorkerReply) => {
      void worker.terminate();
      finish(reply);
    });
    worker.once("error", (error) => {
      const message = error instanceof Error ? error.message : String(error);
      finish({
        ok: false,
        reason: /heap|memory|allocation/iu.test(message)
          ? "memory-limit"
          : "unsupported",
      });
    });
    worker.once("exit", (code) => {
      if (code !== 0) finish({ ok: false, reason: "unsupported" });
    });
  });
}

function validateLimits(limits: JavascriptNormalizerLimits) {
  if (
    Object.values(limits).some((value) => !Number.isInteger(value) || value < 1)
  )
    throw new Error(
      "JavaScript normalization limits must be positive integers.",
    );
}

export async function normalizeJavascript(
  source: string,
  limits: JavascriptNormalizerLimits,
  implementation?: WebcrackImplementation,
): Promise<JavascriptNormalizationResult> {
  validateLimits(limits);
  let reply: WorkerReply | { ok: false; reason: "timeout" };
  if (implementation === undefined) {
    reply = await normalizeInWorker(source, limits);
  } else {
    try {
      const result = await implementation(source, approvedOptions);
      reply = {
        ok: true,
        code: result.code,
        modules:
          result.bundle === undefined
            ? []
            : [...result.bundle.modules.entries()]
                .map(([id, module]) => ({ id, code: module.code }))
                .sort((left, right) => left.id.localeCompare(right.id)),
      };
    } catch (error) {
      const message = error instanceof Error ? error.message : String(error);
      reply = {
        ok: false,
        reason: /parse|syntax|unexpected token|unterminated/iu.test(message)
          ? "parse"
          : /heap|memory|allocation/iu.test(message)
            ? "memory-limit"
            : "unsupported",
      };
    }
  }

  if (!reply.ok) return { derivatives: [], limitation: reply.reason };
  const derivatives: NormalizedJavascriptDerivative[] = [
    {
      id: "normalized",
      content: reply.code,
      transform: "webcrack-normalized" as const,
    },
    ...reply.modules.map(({ id, code }) => ({
      id,
      content: code,
      transform: "webcrack-module" as const,
    })),
  ].sort((left, right) =>
    `${left.transform}\u0000${left.id}`.localeCompare(
      `${right.transform}\u0000${right.id}`,
    ),
  );

  let totalBytes = 0;
  const accepted: NormalizedJavascriptDerivative[] = [];
  let outputLimited = false;
  for (const derivative of derivatives) {
    const bytes = Buffer.byteLength(derivative.content, "utf8");
    if (
      accepted.length >= limits.maxDerivativesPerCandidate ||
      bytes > limits.maxDerivativeBytes ||
      totalBytes + bytes > limits.maxDerivativeBytesPerCandidate
    ) {
      outputLimited = true;
      continue;
    }
    totalBytes += bytes;
    accepted.push(derivative);
  }
  return {
    derivatives: accepted,
    ...(outputLimited ? { limitation: "output-limit" as const } : {}),
  };
}
