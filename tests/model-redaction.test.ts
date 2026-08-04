import { describe, expect, test } from "vitest";

import { redactSource } from "../src/model/redaction.js";

describe("model source redaction", () => {
  test("removes credential literals while retaining security-relevant data flow", () => {
    const nanoKey = `sk-nano-${"a".repeat(32)}`;
    const githubToken = `ghp_${"b".repeat(36)}`;
    const source = [
      `const hardCoded = "${nanoKey}";`,
      `const github = "${githubToken}";`,
      "const configured = process.env.SECRET;",
      "-----BEGIN PRIVATE KEY-----",
      "c2VjcmV0LWtleS1tYXRlcmlhbA==",
      "-----END PRIVATE KEY-----",
    ].join("\n");

    const redacted = redactSource(source);

    expect(redacted).not.toContain(nanoKey);
    expect(redacted).not.toContain(githubToken);
    expect(redacted).not.toContain("c2VjcmV0LWtleS1tYXRlcmlhbA==");
    expect(redacted).toContain("process.env.SECRET");
    expect(redacted).toContain("[REDACTED_SECRET:");
    expect(redacted.split("\n")).toHaveLength(source.split("\n").length);
  });

  test("redacts generic secret assignments rejected by public reports", () => {
    const source = [
      "token: fixturetoken123",
      "secret = fixturesecret456",
      "api key: fixtureapikey789",
      "password = fixturepassword123",
    ].join("\n");

    const redacted = redactSource(source);

    expect(redacted).not.toContain("fixturetoken123");
    expect(redacted).not.toContain("fixturesecret456");
    expect(redacted).not.toContain("fixtureapikey789");
    expect(redacted).not.toContain("fixturepassword123");
    expect(redacted.match(/\[REDACTED_SECRET:/gu)).toHaveLength(4);
  });
});
