import { createHash } from "node:crypto";

function marker(secret: string) {
  const digest = createHash("sha256").update(secret).digest("hex").slice(0, 12);
  return `[REDACTED_SECRET:${digest}]`;
}

function preserveNewlines(value: string, replacement: string) {
  const newlines = value.match(/\r?\n/gu) ?? [];
  return replacement + newlines.join("");
}

const literalPatterns = [
  /\bgh[pousr]_[A-Za-z0-9_]{20,}\b/gu,
  /\bgithub_pat_[A-Za-z0-9_]{20,}\b/gu,
  /\bsk-[A-Za-z0-9_-]{20,}\b/gu,
  /\bAKIA[0-9A-Z]{16}\b/gu,
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b/gu,
] as const;

export function redactSource(source: string): string {
  let redacted = source.replace(
    /-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----/gu,
    (secret) => preserveNewlines(secret, marker(secret)),
  );
  redacted = redacted.replace(
    /(\b(?:api[_-]?key|access[_-]?token|auth[_-]?token|client[_-]?secret|password|private[_-]?key)\b\s*[:=]\s*["'])([^"'\r\n]{12,})(["'])/giu,
    (_match, prefix: string, secret: string, suffix: string) =>
      `${prefix}${marker(secret)}${suffix}`,
  );
  for (const pattern of literalPatterns)
    redacted = redacted.replace(pattern, (secret) => marker(secret));
  return redacted.replace(
    /(\bBearer\s+)([A-Za-z0-9._~+/=-]{16,})/giu,
    (_match, prefix: string, secret: string) => `${prefix}${marker(secret)}`,
  );
}
