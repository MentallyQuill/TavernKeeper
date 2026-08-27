const targetRetryMinutes = [5, 30, 120] as const;
const sharedProbeMinutes = [5, 15, 30, 60, 180] as const;
const scanRetryMinutes = [5, 30, 120, 360] as const;
const targetCooldownMinutes = 7 * 24 * 60;

function addMinutes(value: string, minutes: number) {
  const milliseconds = Date.parse(value);
  if (!Number.isFinite(milliseconds)) throw new Error("Retry time is invalid.");
  return new Date(milliseconds + minutes * 60 * 1_000).toISOString();
}

export function targetRetryAt(initialFailedAt: string, attempt: number) {
  const minutes = targetRetryMinutes[attempt - 1];
  if (minutes === undefined)
    throw new Error("Target retry attempt is not schedulable.");
  return addMinutes(initialFailedAt, minutes);
}

export function targetRetryNotBefore(
  lastFailedAt: string,
  consecutiveFailures: number,
) {
  if (!Number.isSafeInteger(consecutiveFailures) || consecutiveFailures < 1)
    throw new Error("Target failure count is invalid.");
  if (consecutiveFailures === 1) {
    if (!Number.isFinite(Date.parse(lastFailedAt)))
      throw new Error("Retry time is invalid.");
    return null;
  }
  if (consecutiveFailures === 2)
    return addMinutes(lastFailedAt, targetCooldownMinutes);
  throw new Error("Terminal target failure has no retry deadline.");
}

export function sharedProbeAt(lastFailedAt: string, consecutive: number) {
  if (!Number.isInteger(consecutive) || consecutive < 1)
    throw new Error("Shared failure count is invalid.");
  const minutes =
    sharedProbeMinutes[Math.min(consecutive, sharedProbeMinutes.length) - 1]!;
  return addMinutes(lastFailedAt, minutes);
}

export function scanRetryAt(lastFailedAt: string, consecutive: number) {
  if (!Number.isSafeInteger(consecutive) || consecutive < 1)
    throw new Error("Scan failure count is invalid.");
  const minutes =
    scanRetryMinutes[Math.min(consecutive, scanRetryMinutes.length) - 1]!;
  return addMinutes(lastFailedAt, minutes);
}
