import { lookup } from "node:dns/promises";
import { isIP } from "node:net";

import { z } from "zod";

export interface ModelUsage {
  inputTokens: number;
  outputTokens: number;
  cacheReadTokens: number;
  reasoningTokens: number;
}

export interface ModelCompletionResult {
  completionId: string;
  endpointOrigin: string;
  provider: string;
  content: string;
  usage: ModelUsage;
}

export interface ProviderConnectivityRequest {
  endpoint: string;
  apiKey: string;
  model: string;
  fetchImpl?: typeof fetch;
  resolveAddresses?: (hostname: string) => Promise<string[]>;
  timeoutMs?: number;
}

export interface TextCompletionRequest extends ProviderConnectivityRequest {
  maxOutputTokens: number;
  systemContent: string;
  userContent: string;
  maxResponseBytes?: number;
}

export type ModelRequestErrorCode =
  | "MODEL_CONFIGURATION"
  | "MODEL_AUTHENTICATION"
  | "MODEL_AUTH_HEADER_MISMATCH"
  | "MODEL_QUOTA"
  | "MODEL_PROVIDER"
  | "MODEL_INVALID_RESPONSE"
  | "MODEL_EVIDENCE_INVALID"
  | "MODEL_CONTEXT_INCOMPLETE";

export type ModelResponseDiagnostic =
  | "output_limit"
  | "response_content"
  | "response_envelope"
  | "response_json"
  | "response_size"
  | "response_usage";

export class ModelRequestError extends Error {
  constructor(
    readonly code: ModelRequestErrorCode,
    readonly scope: "repository" | "system",
    message: string,
    readonly diagnostic?: ModelResponseDiagnostic,
    readonly httpStatus?: number,
    readonly usage?: ModelUsage,
  ) {
    super(message);
    this.name = "ModelRequestError";
  }
}

const NonNegativeIntegerSchema = z.number().int().nonnegative();
const CompletionIdSchema = z
  .string()
  .regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/u);
const ProviderUsageSchema = z.looseObject({
  prompt_tokens: NonNegativeIntegerSchema.optional(),
  input_tokens: NonNegativeIntegerSchema.optional(),
  completion_tokens: NonNegativeIntegerSchema.optional(),
  output_tokens: NonNegativeIntegerSchema.optional(),
  cache_read_input_tokens: NonNegativeIntegerSchema.optional(),
  reasoning_tokens: NonNegativeIntegerSchema.optional(),
  prompt_tokens_details: z
    .looseObject({ cached_tokens: NonNegativeIntegerSchema.optional() })
    .optional(),
  input_tokens_details: z
    .looseObject({ cached_tokens: NonNegativeIntegerSchema.optional() })
    .optional(),
  completion_tokens_details: z
    .looseObject({ reasoning_tokens: NonNegativeIntegerSchema.optional() })
    .optional(),
  output_tokens_details: z
    .looseObject({ reasoning_tokens: NonNegativeIntegerSchema.optional() })
    .optional(),
});
const ProviderEnvelopeSchema = z.looseObject({
  id: z.unknown(),
  model: z.unknown().optional(),
  choices: z
    .array(
      z.looseObject({
        message: z.looseObject({
          content: z.unknown(),
          function_call: z.unknown().optional(),
          tool_calls: z.unknown().optional(),
        }),
        finish_reason: z.unknown().optional(),
      }),
    )
    .min(1)
    .max(100),
  usage: z.unknown(),
});
const ContentPartSchema = z.looseObject({
  type: z.literal("text").optional(),
  text: z.string(),
});

function privateIpv4(address: string) {
  const octets = address.split(".").map(Number);
  if (octets.length !== 4 || octets.some((value) => !Number.isInteger(value)))
    return true;
  const [first, second] = octets as [number, number, number, number];
  return (
    first === 0 ||
    first === 10 ||
    first === 127 ||
    (first === 100 && second >= 64 && second <= 127) ||
    (first === 169 && second === 254) ||
    (first === 172 && second >= 16 && second <= 31) ||
    (first === 192 && second === 0) ||
    (first === 192 && second === 168) ||
    (first === 198 && (second === 18 || second === 19)) ||
    first >= 224
  );
}

function privateIp(address: string) {
  const normalized = address.replace(/^\[|\]$/gu, "").toLowerCase();
  const version = isIP(normalized);
  if (version === 4) return privateIpv4(normalized);
  if (version !== 6) return true;
  if (normalized.startsWith("::ffff:")) {
    const mapped = normalized.slice("::ffff:".length);
    return isIP(mapped) !== 4 || privateIpv4(mapped);
  }
  return (
    normalized === "::" ||
    normalized === "::1" ||
    normalized.startsWith("fc") ||
    normalized.startsWith("fd") ||
    /^fe[89ab]/u.test(normalized) ||
    normalized.startsWith("ff") ||
    normalized.startsWith("2001:db8:")
  );
}

export function validateModelEndpoint(endpoint: string) {
  let url: URL;
  try {
    url = new URL(endpoint);
  } catch {
    throw new ModelRequestError(
      "MODEL_CONFIGURATION",
      "system",
      "Configured model endpoint is not a valid URL.",
    );
  }
  const hostname = url.hostname.replace(/^\[|\]$/gu, "");
  if (
    url.protocol !== "https:" ||
    url.username !== "" ||
    url.password !== "" ||
    url.search !== "" ||
    url.hash !== "" ||
    url.hostname === "" ||
    url.hostname === "localhost" ||
    url.hostname.endsWith(".localhost") ||
    url.hostname.endsWith(".local") ||
    (isIP(hostname) !== 0 && privateIp(hostname))
  ) {
    throw new ModelRequestError(
      "MODEL_CONFIGURATION",
      "system",
      "Configured model endpoint violates the public HTTPS boundary.",
    );
  }
  return url;
}

async function defaultResolveAddresses(hostname: string) {
  return (await lookup(hostname, { all: true, verbatim: true })).map(
    ({ address }) => address,
  );
}

async function resolvePublicModelEndpoint(
  endpoint: URL,
  resolveAddresses?: (hostname: string) => Promise<string[]>,
) {
  let addresses: string[];
  try {
    addresses = await (resolveAddresses ?? defaultResolveAddresses)(
      endpoint.hostname,
    );
  } catch {
    throw new ModelRequestError(
      "MODEL_PROVIDER",
      "system",
      "Configured model endpoint could not be resolved.",
    );
  }
  if (addresses.length === 0 || addresses.some(privateIp)) {
    throw new ModelRequestError(
      "MODEL_CONFIGURATION",
      "system",
      "Configured model endpoint resolves outside the public network boundary.",
    );
  }
}

async function readBoundedResponse(response: Response, maximumBytes: number) {
  if (!response.body) return "";
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let bytes = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    bytes += value.byteLength;
    if (bytes > maximumBytes) {
      await reader.cancel();
      throw new ModelRequestError(
        "MODEL_INVALID_RESPONSE",
        "system",
        "Model response exceeded its byte ceiling.",
        "response_size",
      );
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString("utf8");
}

function usageFromResponse(
  usage: z.infer<typeof ProviderUsageSchema>,
): ModelUsage {
  const inputTokens = usage.prompt_tokens ?? usage.input_tokens;
  const outputTokens = usage.completion_tokens ?? usage.output_tokens;
  if (inputTokens === undefined || outputTokens === undefined) {
    throw new ModelRequestError(
      "MODEL_INVALID_RESPONSE",
      "system",
      "Model response omitted actual input or output usage.",
      "response_usage",
    );
  }
  return {
    inputTokens,
    outputTokens,
    cacheReadTokens:
      usage.cache_read_input_tokens ??
      usage.prompt_tokens_details?.cached_tokens ??
      usage.input_tokens_details?.cached_tokens ??
      0,
    reasoningTokens:
      usage.reasoning_tokens ??
      usage.completion_tokens_details?.reasoning_tokens ??
      usage.output_tokens_details?.reasoning_tokens ??
      0,
  };
}

function reportedUsage(value: unknown): ModelUsage | undefined {
  const parsed = ProviderUsageSchema.safeParse(value);
  if (!parsed.success) return undefined;
  try {
    return usageFromResponse(parsed.data);
  } catch {
    return undefined;
  }
}

function finalContent(value: unknown) {
  if (typeof value === "string" && value.trim() !== "") return value;
  if (Array.isArray(value)) {
    const parts = z.array(ContentPartSchema).safeParse(value);
    if (parts.success) {
      const content = parts.data.map((part) => part.text).join("");
      if (content.trim() !== "") return content;
    }
  }
  return null;
}

function validateConfiguration(request: ProviderConnectivityRequest) {
  const apiKey = request.apiKey.trim();
  const model = request.model.trim();
  if (apiKey === "" || model === "" || model.length > 200) {
    throw new ModelRequestError(
      "MODEL_CONFIGURATION",
      "system",
      "Configured model request is incomplete or invalid.",
    );
  }
  return { apiKey, model };
}

function classifyHttpError(response: Response): never {
  if (response.status >= 300 && response.status < 400) {
    throw new ModelRequestError(
      "MODEL_PROVIDER",
      "system",
      "Configured model endpoint attempted a redirect.",
    );
  }
  if (response.status === 401 || response.status === 403) {
    throw new ModelRequestError(
      "MODEL_AUTHENTICATION",
      "system",
      "Configured model rejected its credentials.",
    );
  }
  if (response.status === 402 || response.status === 429) {
    throw new ModelRequestError(
      "MODEL_QUOTA",
      "system",
      "Configured model quota is unavailable.",
    );
  }
  throw new ModelRequestError(
    "MODEL_PROVIDER",
    "system",
    `Configured model returned HTTP ${response.status}.`,
    undefined,
    response.status,
  );
}

export async function checkModelProviderConnectivity(
  request: ProviderConnectivityRequest,
) {
  const endpoint = validateModelEndpoint(request.endpoint);
  const { apiKey, model } = validateConfiguration(request);
  await resolvePublicModelEndpoint(endpoint, request.resolveAddresses);
  const body = JSON.stringify({
    model,
    messages: [{ role: "user", content: "Reply with OK." }],
    stream: false,
    temperature: 0,
    max_tokens: 1,
  });
  const send = async (headers: Record<string, string>) => {
    let response: Response;
    try {
      response = await (request.fetchImpl ?? fetch)(request.endpoint, {
        method: "POST",
        redirect: "manual",
        signal: AbortSignal.timeout(request.timeoutMs ?? 60_000),
        headers,
        body,
      });
    } catch {
      throw new ModelRequestError(
        "MODEL_PROVIDER",
        "system",
        "Configured model request failed.",
      );
    }
    await response.body?.cancel();
    return response;
  };
  let response = await send({
    Authorization: `Bearer ${apiKey}`,
    "Content-Type": "application/json",
  });
  if (response.status === 401 || response.status === 403) {
    response = await send({
      "Content-Type": "application/json",
      "x-api-key": apiKey,
    });
    if (response.ok) {
      throw new ModelRequestError(
        "MODEL_AUTH_HEADER_MISMATCH",
        "system",
        "Configured model accepts only the alternate API-key header.",
      );
    }
  }
  if (!response.ok) classifyHttpError(response);
  return { status: "passed" as const, authMode: "bearer" as const };
}

export async function requestTextCompletion(
  request: TextCompletionRequest,
): Promise<ModelCompletionResult> {
  const endpoint = validateModelEndpoint(request.endpoint);
  const { apiKey, model } = validateConfiguration(request);
  if (!Number.isInteger(request.maxOutputTokens) || request.maxOutputTokens < 1)
    throw new ModelRequestError(
      "MODEL_CONFIGURATION",
      "system",
      "Configured model output allowance is invalid.",
    );
  await resolvePublicModelEndpoint(endpoint, request.resolveAddresses);

  let response: Response;
  try {
    response = await (request.fetchImpl ?? fetch)(request.endpoint, {
      method: "POST",
      redirect: "manual",
      signal: AbortSignal.timeout(request.timeoutMs ?? 600_000),
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model,
        messages: [
          { role: "system", content: request.systemContent },
          { role: "user", content: request.userContent },
        ],
        stream: false,
        temperature: 0,
        max_tokens: request.maxOutputTokens,
      }),
    });
  } catch {
    throw new ModelRequestError(
      "MODEL_PROVIDER",
      "system",
      "Configured model request failed.",
    );
  }
  if (!response.ok) classifyHttpError(response);
  if (response.url !== "") {
    let responseOrigin: string;
    try {
      responseOrigin = new URL(response.url).origin;
    } catch {
      throw new ModelRequestError(
        "MODEL_INVALID_RESPONSE",
        "system",
        "Configured model returned an invalid response origin.",
        "response_envelope",
      );
    }
    if (responseOrigin !== endpoint.origin)
      throw new ModelRequestError(
        "MODEL_INVALID_RESPONSE",
        "system",
        "Configured model returned a response from an unexpected origin.",
        "response_envelope",
      );
  }

  let decoded: unknown;
  try {
    decoded = JSON.parse(
      await readBoundedResponse(
        response,
        request.maxResponseBytes ?? 5_000_000,
      ),
    );
  } catch (error) {
    if (error instanceof ModelRequestError) throw error;
    throw new ModelRequestError(
      "MODEL_INVALID_RESPONSE",
      "system",
      "Configured model returned malformed JSON.",
      "response_json",
    );
  }
  const envelope = ProviderEnvelopeSchema.safeParse(decoded);
  if (!envelope.success)
    throw new ModelRequestError(
      "MODEL_INVALID_RESPONSE",
      "system",
      "Configured model returned an invalid response envelope.",
      "response_envelope",
      undefined,
      decoded !== null && typeof decoded === "object" && "usage" in decoded
        ? reportedUsage(decoded.usage)
        : undefined,
    );
  const completionUsage = reportedUsage(envelope.data.usage);
  const parsedId = CompletionIdSchema.safeParse(envelope.data.id);
  if (!parsedId.success)
    throw new ModelRequestError(
      "MODEL_INVALID_RESPONSE",
      "system",
      "Configured model returned an invalid completion identity.",
      "response_envelope",
      undefined,
      completionUsage,
    );
  if (envelope.data.model !== undefined && envelope.data.model !== model)
    throw new ModelRequestError(
      "MODEL_INVALID_RESPONSE",
      "system",
      "Configured model returned an unexpected model identity.",
      "response_envelope",
      undefined,
      completionUsage,
    );
  const choice = envelope.data.choices[0]!;
  if (
    choice.finish_reason !== undefined &&
    choice.finish_reason !== null &&
    choice.finish_reason !== "stop"
  ) {
    if (["length", "max_tokens"].includes(String(choice.finish_reason)))
      throw new ModelRequestError(
        "MODEL_INVALID_RESPONSE",
        "system",
        "Configured model exhausted its output allowance.",
        "output_limit",
        undefined,
        completionUsage,
      );
    throw new ModelRequestError(
      "MODEL_INVALID_RESPONSE",
      "system",
      "Configured model returned an unsuccessful finish state.",
      "response_envelope",
      undefined,
      completionUsage,
    );
  }
  if (
    choice.message.tool_calls !== undefined ||
    choice.message.function_call !== undefined
  )
    throw new ModelRequestError(
      "MODEL_INVALID_RESPONSE",
      "system",
      "Configured model returned an unsupported tool call.",
      "response_envelope",
      undefined,
      completionUsage,
    );
  const content = finalContent(choice.message.content);
  if (content === null)
    throw new ModelRequestError(
      "MODEL_INVALID_RESPONSE",
      "system",
      "Configured model omitted its final completion content.",
      "response_content",
      undefined,
      completionUsage,
    );
  const parsedUsage = ProviderUsageSchema.safeParse(envelope.data.usage);
  if (!parsedUsage.success)
    throw new ModelRequestError(
      "MODEL_INVALID_RESPONSE",
      "system",
      "Configured model returned invalid usage metadata.",
      "response_usage",
    );
  return {
    completionId: parsedId.data,
    endpointOrigin: endpoint.origin,
    provider: endpoint.hostname,
    content,
    usage: usageFromResponse(parsedUsage.data),
  };
}
