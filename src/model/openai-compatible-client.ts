import { lookup } from "node:dns/promises";
import { isIP } from "node:net";

import { z } from "zod";

export interface ModelUsage {
  inputTokens: number;
  outputTokens: number;
  cacheReadTokens: number;
  reasoningTokens: number;
}

export interface StructuredCompletionResult {
  completionId: string;
  endpointOrigin: string;
  provider: string;
  content: string;
  usage: ModelUsage;
}

export interface StructuredCompletionRequest {
  endpoint: string;
  apiKey: string;
  model: string;
  systemContent: string;
  userContent: string;
  maxOutputTokens: number;
  schemaName: string;
  jsonSchema: Record<string, unknown>;
  fetchImpl?: typeof fetch;
  resolveAddresses?: (hostname: string) => Promise<string[]>;
  timeoutMs?: number;
  maxResponseBytes?: number;
}

export type RequestStructuredCompletion = (
  request: StructuredCompletionRequest,
) => Promise<StructuredCompletionResult>;

export type ModelRequestErrorCode =
  | "MODEL_CONFIGURATION"
  | "MODEL_AUTHENTICATION"
  | "MODEL_QUOTA"
  | "MODEL_PROVIDER"
  | "MODEL_INVALID_RESPONSE";

export class ModelRequestError extends Error {
  constructor(
    readonly code: ModelRequestErrorCode,
    readonly scope: "system",
    message: string,
  ) {
    super(message);
    this.name = "ModelRequestError";
  }
}

const NonNegativeIntegerSchema = z.number().int().nonnegative();
const ProviderResponseSchema = z.looseObject({
  id: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/u),
  choices: z
    .array(
      z.looseObject({
        message: z.looseObject({ content: z.string() }),
      }),
    )
    .min(1)
    .max(100),
  usage: z.looseObject({
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
  }),
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
  if (normalized.startsWith("::ffff:"))
    return privateIpv4(normalized.slice("::ffff:".length));
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
    (isIP(url.hostname.replace(/^\[|\]$/gu, "")) !== 0 &&
      privateIp(url.hostname))
  )
    throw new ModelRequestError(
      "MODEL_CONFIGURATION",
      "system",
      "Configured model endpoint violates the public HTTPS boundary.",
    );
  return url;
}

async function defaultResolveAddresses(hostname: string) {
  return (await lookup(hostname, { all: true, verbatim: true })).map(
    ({ address }) => address,
  );
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
      );
    }
    chunks.push(value);
  }
  return Buffer.concat(chunks).toString("utf8");
}

function usageFromResponse(
  usage: z.infer<typeof ProviderResponseSchema>["usage"],
): ModelUsage {
  const inputTokens = usage.prompt_tokens ?? usage.input_tokens;
  const outputTokens = usage.completion_tokens ?? usage.output_tokens;
  if (inputTokens === undefined || outputTokens === undefined)
    throw new ModelRequestError(
      "MODEL_INVALID_RESPONSE",
      "system",
      "Model response omitted actual input or output usage.",
    );
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

export async function requestStructuredCompletion(
  request: StructuredCompletionRequest,
): Promise<StructuredCompletionResult> {
  const endpoint = validateModelEndpoint(request.endpoint);
  if (
    request.apiKey.trim() === "" ||
    request.model.trim() === "" ||
    request.model.length > 200 ||
    !Number.isInteger(request.maxOutputTokens) ||
    request.maxOutputTokens < 1 ||
    !/^[A-Za-z0-9][A-Za-z0-9_-]{0,63}$/u.test(request.schemaName)
  )
    throw new ModelRequestError(
      "MODEL_CONFIGURATION",
      "system",
      "Configured model request is incomplete or invalid.",
    );

  let addresses: string[];
  try {
    addresses = await (request.resolveAddresses ?? defaultResolveAddresses)(
      endpoint.hostname,
    );
  } catch {
    throw new ModelRequestError(
      "MODEL_PROVIDER",
      "system",
      "Configured model endpoint could not be resolved.",
    );
  }
  if (addresses.length === 0 || addresses.some(privateIp))
    throw new ModelRequestError(
      "MODEL_CONFIGURATION",
      "system",
      "Configured model endpoint resolves outside the public network boundary.",
    );

  let response: Response;
  try {
    response = await (request.fetchImpl ?? fetch)(request.endpoint, {
      method: "POST",
      redirect: "manual",
      signal: AbortSignal.timeout(request.timeoutMs ?? 600_000),
      headers: {
        Authorization: `Bearer ${request.apiKey}`,
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        model: request.model,
        messages: [
          { role: "system", content: request.systemContent },
          { role: "user", content: request.userContent },
        ],
        stream: false,
        temperature: 0,
        max_tokens: request.maxOutputTokens,
        response_format: {
          type: "json_schema",
          json_schema: {
            name: request.schemaName,
            strict: true,
            schema: request.jsonSchema,
          },
        },
      }),
    });
  } catch (error) {
    if (error instanceof ModelRequestError) throw error;
    throw new ModelRequestError(
      "MODEL_PROVIDER",
      "system",
      "Configured model request failed.",
    );
  }
  if (response.status >= 300 && response.status < 400)
    throw new ModelRequestError(
      "MODEL_PROVIDER",
      "system",
      "Configured model endpoint attempted a redirect.",
    );
  if (response.status === 401 || response.status === 403)
    throw new ModelRequestError(
      "MODEL_AUTHENTICATION",
      "system",
      "Configured model rejected its credentials.",
    );
  if (response.status === 402 || response.status === 429)
    throw new ModelRequestError(
      "MODEL_QUOTA",
      "system",
      "Configured model quota is unavailable.",
    );
  if (!response.ok)
    throw new ModelRequestError(
      "MODEL_PROVIDER",
      "system",
      `Configured model returned HTTP ${response.status}.`,
    );

  let parsed: z.infer<typeof ProviderResponseSchema>;
  try {
    parsed = ProviderResponseSchema.parse(
      JSON.parse(
        await readBoundedResponse(
          response,
          request.maxResponseBytes ?? 5_000_000,
        ),
      ),
    );
  } catch (error) {
    if (error instanceof ModelRequestError) throw error;
    throw new ModelRequestError(
      "MODEL_INVALID_RESPONSE",
      "system",
      "Configured model returned malformed structured output.",
    );
  }
  return {
    completionId: parsed.id,
    endpointOrigin: endpoint.origin,
    provider: endpoint.hostname,
    content: parsed.choices[0]!.message.content,
    usage: usageFromResponse(parsed.usage),
  };
}
