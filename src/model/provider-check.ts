import {
  checkModelProviderConnectivity,
  ModelRequestError,
  requestStructuredCompletion,
  type ProviderConnectivityRequest,
} from "./openai-compatible-client.js";
import { roleJsonSchemas, sanitizeRolePayload } from "./role-contracts.js";

export async function checkModelProviderCompatibility(
  request: ProviderConnectivityRequest,
) {
  const connectivity = await checkModelProviderConnectivity(request);
  const completion = await requestStructuredCompletion({
    ...request,
    systemContent:
      "This is a provider compatibility check. Return only the required JSON. Do not invent assessments or discoveries.",
    userContent: JSON.stringify({
      deterministic_findings: [],
      segments: [],
      relationships: [],
    }),
    maxOutputTokens: 8_192,
    schemaName: "tavernkeeper_analyzer_check",
    jsonSchema: roleJsonSchemas.analyzer,
  });
  try {
    sanitizeRolePayload("analyzer", completion.content, []);
  } catch {
    throw new ModelRequestError(
      "MODEL_INVALID_RESPONSE",
      "system",
      "Configured model did not satisfy the analyzer response contract.",
      "role_schema_analyzer",
    );
  }
  return {
    ...connectivity,
    structuredOutput: "passed" as const,
  };
}
