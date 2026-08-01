import { createHash } from "node:crypto";

import { describe, expect, test } from "vitest";

import { redactSource } from "../src/model/redaction.js";

describe("model source redaction", () => {
  test("replaces secret-like literals with stable hash markers and preserves line count", () => {
    const secret = "ghp_abcdefghijklmnopqrstuvwxyz1234567890";
    const source = [
      `const api_key = "${secret}";`,
      `const second = "${secret}";`,
      'const unrelated = "visible";',
    ].join("\n");
    const prefix = createHash("sha256")
      .update(secret)
      .digest("hex")
      .slice(0, 12);

    const redacted = redactSource(source);

    expect(redacted).not.toContain(secret);
    expect(
      redacted.match(new RegExp(`\\[REDACTED_SECRET:${prefix}\\]`, "gu")),
    ).toHaveLength(2);
    expect(redacted).toContain('const unrelated = "visible";');
    expect(redacted.split("\n")).toHaveLength(source.split("\n").length);
    expect(redactSource(source)).toBe(redacted);
  });

  test("redacts private key bodies without collapsing their newlines", () => {
    const source = [
      "-----BEGIN PRIVATE KEY-----",
      "c2VjcmV0LWtleS1tYXRlcmlhbA==",
      "-----END PRIVATE KEY-----",
      "after();",
    ].join("\n");

    const redacted = redactSource(source);

    expect(redacted).not.toContain("c2VjcmV0LWtleS1tYXRlcmlhbA==");
    expect(redacted).toContain("[REDACTED_SECRET:");
    expect(redacted).toContain("after();");
    expect(redacted.split("\n")).toHaveLength(source.split("\n").length);
  });
});
