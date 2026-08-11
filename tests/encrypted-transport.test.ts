import { randomBytes } from "node:crypto";

import { describe, expect, test } from "vitest";

import {
  decryptTransport,
  encryptTransport,
} from "../src/publish/encrypted-transport.js";

describe("authenticated scan-artifact transport", () => {
  test("round trips candidate and transition JSON without exposing plaintext", () => {
    const key = randomBytes(32);
    const payload = {
      schema_version: 1,
      candidate: { report: { report_id: "a".repeat(64) } },
      transition: { status: "completed", repository: "owner/private-name" },
    };

    const encrypted = encryptTransport(payload, key);

    expect(encrypted.toString("utf8")).not.toContain("owner/private-name");
    expect(decryptTransport(encrypted, key)).toEqual(payload);
  });

  test("rejects the wrong key and ciphertext tampering", () => {
    const key = randomBytes(32);
    const encrypted = encryptTransport({ secret: "sanitized" }, key);
    const tampered = Buffer.from(encrypted);
    tampered[tampered.length - 1] = tampered[tampered.length - 1]! ^ 1;

    expect(() => decryptTransport(encrypted, randomBytes(32))).toThrow();
    expect(() => decryptTransport(tampered, key)).toThrow();
  });

  test("requires a full 256-bit key", () => {
    expect(() => encryptTransport({}, randomBytes(31))).toThrow(/32 bytes/iu);
  });

  test("binds an encrypted payload to caller-supplied authenticated context", () => {
    const key = randomBytes(32);
    const encrypted = encryptTransport(
      { phase: "reviewing" },
      key,
      "checkpoint:repository-41:sha-a",
    );

    expect(
      decryptTransport(encrypted, key, "checkpoint:repository-41:sha-a"),
    ).toEqual({ phase: "reviewing" });
    expect(() =>
      decryptTransport(encrypted, key, "checkpoint:repository-41:sha-b"),
    ).toThrow();
    expect(() => decryptTransport(encrypted, key)).toThrow();
  });
});
