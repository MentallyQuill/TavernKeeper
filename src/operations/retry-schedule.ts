const repositoryModelReplyFailureCodes = new Set([
  "MODEL_INVALID_RESPONSE",
  "MODEL_CONTEXT_INCOMPLETE",
  "MODEL_EVIDENCE_INVALID",
]);

export function isRepositoryModelReplyFailure(
  scope: "repository" | "system",
  code: string,
) {
  return scope === "repository" && repositoryModelReplyFailureCodes.has(code);
}

function addMinutes(value: string, minutes: number) {
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds)) throw new Error("Retry time is invalid.");
  return new Date(milliseconds + minutes * 60 * 1_000).toISOString();
}

export function scheduledRetryAt(input: {
  initialFailedAt: string;
  attempt: number;
  scope: "repository" | "system";
  code: string;
}) {
  const minutes = isRepositoryModelReplyFailure(input.scope, input.code)
    ? input.attempt * 5
    : input.attempt * 60;
  return addMinutes(input.initialFailedAt, minutes);
}

export function legacyHourlyRetryAt(initialFailedAt: string, attempt: number) {
  return addMinutes(initialFailedAt, attempt * 60);
}
