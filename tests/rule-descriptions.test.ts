import { describe, expect, test } from "vitest";

import {
  classifyFinding,
  describeFinding,
  OWNED_RULE_TRIAGE,
  RULE_CATALOG_VERSION,
} from "../src/policy/rule-descriptions.js";

const finding = {
  origin: "tavernkeeper",
  rule_id: "credential-exfiltration",
  category: "credential-theft",
  severity: "high" as const,
  confidence: "high" as const,
  path: "src/index.ts",
};

describe("deterministic finding policy", () => {
  test("classifies only medium-or-higher and medium-confidence findings as reportable", () => {
    for (const [severity, confidence] of [
      ["medium", "medium"],
      ["high", "medium"],
      ["critical", "high"],
    ] as const)
      expect(classifyFinding({ severity, confidence })).toBe("reportable");

    for (const [severity, confidence] of [
      ["medium", "low"],
      ["low", "high"],
      ["info", "high"],
    ] as const)
      expect(classifyFinding({ severity, confidence })).toBe("informational");
  });

  test("uses exact static descriptions and versioned external fallbacks", () => {
    expect(RULE_CATALOG_VERSION).toBe("2");
    expect(describeFinding(finding)).toEqual({
      title: "Credential access and network transmission in one file",
      explanation:
        "A credential source and an outbound network operation were detected in the same file.",
      remediation:
        "Review the data flow, remove unintended credential transmission, and restrict any required destination.",
    });
    expect(
      describeFinding({
        ...finding,
        origin: "osv-scanner",
        rule_id: "GHSA-abcd-1234-efgh",
        category: "dependency-vulnerability",
      }),
    ).toEqual({
      title: "Dependency advisory GHSA-abcd-1234-efgh applies",
      explanation:
        "OSV-Scanner matched advisory GHSA-abcd-1234-efgh to a dependency declared by this repository.",
      remediation:
        "Review the advisory and update or replace the affected dependency when a fixed version is available.",
    });
    expect(
      describeFinding({
        ...finding,
        origin: "javascript-analysis",
        rule_id: "javascript.xray.unsafe-stmt",
        category: "code-execution",
      }),
    ).toEqual({
      title: "JavaScript analysis reported javascript.xray.unsafe-stmt",
      explanation:
        "JavaScript analysis matched static JavaScript security signal javascript.xray.unsafe-stmt in this repository.",
      remediation:
        "Review the correlated source behavior and remove unsafe execution, credential access, persistence, or network activity that is not required.",
    });
  });

  test("declares triage behavior for every owned scanner rule", () => {
    expect(OWNED_RULE_TRIAGE).toMatchObject({
      "credential-exfiltration": "correlation-only",
      "network-install-hook": "correlation-only",
      "unicode-bidi-control": "deterministic",
      "tavernkeeper.encoded-payload.javascript-decode-to-execution":
        "correlation-only",
      "tavernkeeper.encoded-payload.powershell-command": "contextual",
      "tavernkeeper.download-and-execute.shell-pipeline": "correlation-only",
      "tavernkeeper.install-hook.network-capable-command": "correlation-only",
      "tavernkeeper.persistence.startup-modification": "correlation-only",
      "tavernkeeper.dynamic-execution.javascript-eval": "contextual",
      "tavernkeeper.dynamic-execution.node-shell": "contextual",
      "tavernkeeper.dynamic-execution.python-eval-or-shell": "contextual",
      "tavernkeeper.credential-exfiltration.javascript-secret-to-network":
        "correlation-only",
      "tavernkeeper.credential-exfiltration.python-secret-to-network":
        "correlation-only",
      "tavernkeeper.reconnaissance-transmission.javascript-host-data-to-network":
        "contextual",
      "tavernkeeper.reconnaissance-transmission.python-host-data-to-network":
        "contextual",
    });
    expect(Object.keys(OWNED_RULE_TRIAGE)).toHaveLength(15);
  });

  test("rejects unsupported origins and unsafe dynamic identifiers", () => {
    expect(() => describeFinding({ ...finding, origin: "unknown" })).toThrow(
      "unsupported finding origin",
    );
    expect(() =>
      describeFinding({
        ...finding,
        origin: "gitleaks",
        rule_id: "sk-abcdefghijklmnopqrstuvwxyz123456",
      }),
    ).toThrow("unsafe rule identifier");
  });
});
