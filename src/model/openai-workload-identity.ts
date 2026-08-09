import OpenAI from "openai";
import { SubjectTokenProviderError } from "openai";
import type { SubjectTokenProvider, WorkloadIdentity } from "openai/auth/types";
import { z } from "zod";

import type { ContextualReviewProvider } from "./contextual-review.js";
import {
  ModelRequestError,
  type ModelCompletionResult,
  type TextCompletionRequest,
} from "./openai-compatible-client.js";

export const OPENAI_REVIEW_ENDPOINT =
  "https://api.openai.com/v1/chat/completions" as const;
export const OPENAI_REVIEW_MODEL = "gpt-5.6-luna" as const;

const CompletionSchema = z.looseObject({
  id: z.string().regex(/^[A-Za-z0-9][A-Za-z0-9._:-]{0,199}$/u),
  choices: z
    .array(
      z.looseObject({
        finish_reason: z.string().nullable(),
        message: z.looseObject({ content: z.string().nullable() }),
      }),
    )
    .length(1),
  usage: z
    .looseObject({
      prompt_tokens: z.number().int().nonnegative(),
      completion_tokens: z.number().int().nonnegative(),
      prompt_tokens_details: z
        .looseObject({ cached_tokens: z.number().int().nonnegative() })
        .optional(),
      completion_tokens_details: z
        .looseObject({ reasoning_tokens: z.number().int().nonnegative() })
        .optional(),
    })
    .optional(),
});

interface OpenAIChatClient {
  chat: {
    completions: {
      create: (
        body: Record<string, unknown>,
        options: { timeout: number },
      ) => Promise<unknown>;
    };
  };
}

interface OpenAIProviderDependencies {
  createClient?: (workloadIdentity: WorkloadIdentity) => OpenAIChatClient;
  fetchImpl?: typeof fetch;
}

function requiredEnvironment(
  environment: NodeJS.ProcessEnv,
  name: string,
): string {
  const value = environment[name]?.trim();
  if (value === undefined || value === "")
    throw new ModelRequestError(
      "MODEL_CONFIGURATION",
      "system",
      `${name} is required for OpenAI workload identity.`,
    );
  return value;
}

function githubOidcUrl(environment: NodeJS.ProcessEnv) {
  const raw = requiredEnvironment(environment, "ACTIONS_ID_TOKEN_REQUEST_URL");
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw new ModelRequestError(
      "MODEL_CONFIGURATION",
      "system",
      "GitHub Actions supplied an invalid OIDC request URL.",
    );
  }
  if (
    url.protocol !== "https:" ||
    !(
      url.hostname === "actions.githubusercontent.com" ||
      url.hostname.endsWith(".actions.githubusercontent.com")
    )
  )
    throw new ModelRequestError(
      "MODEL_CONFIGURATION",
      "system",
      "GitHub Actions supplied an untrusted OIDC request URL.",
    );
  url.searchParams.set(
    "audience",
    requiredEnvironment(environment, "OPENAI_WIF_AUDIENCE"),
  );
  return url;
}

export function createGithubActionsSubjectTokenProvider(
  environment: NodeJS.ProcessEnv,
  fetchImpl: typeof fetch = fetch,
): SubjectTokenProvider {
  const requestUrl = githubOidcUrl(environment);
  const requestToken = requiredEnvironment(
    environment,
    "ACTIONS_ID_TOKEN_REQUEST_TOKEN",
  );
  return {
    tokenType: "jwt",
    getToken: async () => {
      try {
        const response = await fetchImpl(requestUrl, {
          method: "GET",
          redirect: "error",
          signal: AbortSignal.timeout(30_000),
          headers: { Authorization: `Bearer ${requestToken}` },
        });
        if (!response.ok) {
          await response.body?.cancel();
          throw new Error(`GitHub OIDC returned HTTP ${response.status}.`);
        }
        const text = await response.text();
        if (Buffer.byteLength(text) > 100_000)
          throw new Error("GitHub OIDC response exceeded its size limit.");
        const parsed = z
          .strictObject({ value: z.string().trim().min(1).max(100_000) })
          .parse(JSON.parse(text) as unknown);
        return parsed.value;
      } catch (error) {
        if (error instanceof SubjectTokenProviderError) throw error;
        throw new SubjectTokenProviderError(
          "GitHub Actions OIDC token acquisition failed.",
          "github-actions",
          error instanceof Error ? error : undefined,
        );
      }
    },
  };
}

function errorStatus(error: unknown) {
  if (error === null || typeof error !== "object") return undefined;
  const status = Reflect.get(error, "status");
  return typeof status === "number" ? status : undefined;
}

function providerError(error: unknown): ModelRequestError {
  if (error instanceof ModelRequestError) return error;
  const status = errorStatus(error);
  if (status === 401 || status === 403)
    return new ModelRequestError(
      "MODEL_AUTHENTICATION",
      "system",
      "OpenAI rejected the GitHub workload identity.",
      undefined,
      status,
    );
  if (status === 402 || status === 429)
    return new ModelRequestError(
      "MODEL_QUOTA",
      "system",
      "OpenAI review quota is unavailable.",
      undefined,
      status,
    );
  return new ModelRequestError(
    "MODEL_PROVIDER",
    "system",
    status === undefined
      ? "OpenAI contextual review request failed."
      : `OpenAI contextual review returned HTTP ${status}.`,
    undefined,
    status,
  );
}

export function createOpenAIRequestCompletion(client: OpenAIChatClient) {
  return async (
    request: TextCompletionRequest,
  ): Promise<ModelCompletionResult> => {
    if (
      request.endpoint !== OPENAI_REVIEW_ENDPOINT ||
      request.model !== OPENAI_REVIEW_MODEL ||
      request.responseJsonSchema === undefined
    )
      throw new ModelRequestError(
        "MODEL_CONFIGURATION",
        "system",
        "OpenAI contextual review requires the fixed Luna endpoint, model, and JSON Schema.",
      );
    let raw: unknown;
    try {
      raw = await client.chat.completions.create(
        {
          model: OPENAI_REVIEW_MODEL,
          messages: [
            { role: "system", content: request.systemContent },
            { role: "user", content: request.userContent },
          ],
          stream: false,
          store: false,
          reasoning_effort: "low",
          max_completion_tokens: request.maxOutputTokens,
          response_format: {
            type: "json_schema",
            json_schema: {
              name: request.responseJsonSchema.name,
              strict: true,
              schema: request.responseJsonSchema.schema,
            },
          },
        },
        { timeout: request.timeoutMs ?? 120_000 },
      );
    } catch (error) {
      throw providerError(error);
    }
    if (
      Buffer.byteLength(JSON.stringify(raw)) >
      (request.maxResponseBytes ?? 5_000_000)
    )
      throw new ModelRequestError(
        "MODEL_INVALID_RESPONSE",
        "system",
        "OpenAI contextual review response exceeded its size limit.",
        "response_size",
      );
    const parsed = CompletionSchema.safeParse(raw);
    if (!parsed.success)
      throw new ModelRequestError(
        "MODEL_INVALID_RESPONSE",
        "system",
        "OpenAI returned an invalid contextual review envelope.",
        "response_envelope",
      );
    const choice = parsed.data.choices[0]!;
    const usage = parsed.data.usage;
    if (choice.finish_reason !== "stop")
      throw new ModelRequestError(
        "MODEL_INVALID_RESPONSE",
        "repository",
        "OpenAI did not finish the contextual review response.",
        "output_limit",
      );
    if (choice.message.content === null || choice.message.content.trim() === "")
      throw new ModelRequestError(
        "MODEL_INVALID_RESPONSE",
        "repository",
        "OpenAI returned an empty contextual review response.",
        "response_content",
      );
    return {
      completionId: parsed.data.id,
      endpointOrigin: "https://api.openai.com",
      provider: "api.openai.com",
      content: choice.message.content,
      usage: {
        inputTokens: usage?.prompt_tokens ?? 0,
        outputTokens: usage?.completion_tokens ?? 0,
        cacheReadTokens: usage?.prompt_tokens_details?.cached_tokens ?? 0,
        reasoningTokens:
          usage?.completion_tokens_details?.reasoning_tokens ?? 0,
      },
    };
  };
}

export function createOpenAIWorkloadIdentityProvider(
  environment: NodeJS.ProcessEnv,
  dependencies: OpenAIProviderDependencies = {},
): ContextualReviewProvider {
  const workloadIdentity: WorkloadIdentity = {
    identityProviderId: requiredEnvironment(
      environment,
      "OPENAI_IDENTITY_PROVIDER_ID",
    ),
    serviceAccountId: requiredEnvironment(
      environment,
      "OPENAI_SERVICE_ACCOUNT_ID",
    ),
    provider: createGithubActionsSubjectTokenProvider(
      environment,
      dependencies.fetchImpl,
    ),
  };
  const client = dependencies.createClient
    ? dependencies.createClient(workloadIdentity)
    : (new OpenAI({
        workloadIdentity,
        maxRetries: 0,
      }) as unknown as OpenAIChatClient);
  return {
    endpoint: OPENAI_REVIEW_ENDPOINT,
    apiKey: "github-actions-oidc",
    model: OPENAI_REVIEW_MODEL,
    requestCompletion: createOpenAIRequestCompletion(client),
  };
}
