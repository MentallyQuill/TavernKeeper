import { createHash } from "node:crypto";

import { describe, expect, test } from "vitest";

import type {
  EvidenceCandidate,
  EvidenceContextGroup,
} from "../src/context/evidence-context.js";
import { ContextualAssessmentSchema } from "../src/model/contextual-review-contract.js";
import { triageEvidenceGroups } from "../src/triage/review-triage.js";
import type { ExecutionScope } from "../src/triage/execution-scope.js";

function digest(value: string) {
  return createHash("sha256").update(value).digest("hex");
}

function candidate(
  ruleId: string,
  overrides: Partial<EvidenceCandidate> = {},
): EvidenceCandidate {
  const id = digest(`${ruleId}:${JSON.stringify(overrides)}`);
  return {
    candidate_id: id,
    evidence_id: digest(`evidence:${id}`),
    origin: "javascript-analysis",
    rule_id: ruleId,
    category: "supply-chain-risk",
    scanner_severity: "medium",
    scanner_confidence: "medium",
    title: `Scanner signal ${ruleId}`,
    explanation: `The scanner reported ${ruleId}.`,
    line_start: 10,
    line_end: 10,
    ...overrides,
  };
}

function group(input: {
  candidates: EvidenceCandidate[];
  execution_scope?: ExecutionScope;
  path?: string;
  source?: string;
  representations?: EvidenceContextGroup["context"]["representations"];
}): EvidenceContextGroup {
  const path = input.path ?? "scripts/check.mjs";
  return {
    group_id: digest(`group:${path}`),
    repository: "owner/project",
    project_kinds: ["extension"],
    path,
    file_role: "tooling",
    execution_scope: input.execution_scope ?? "tooling-only",
    target_sha: "a".repeat(40),
    evidence_sha: "a".repeat(40),
    source_kind: "text",
    source_bytes: 100,
    source_sha256: digest(`source:${path}`),
    ecosystem_context_version: "sillytavern-community-v1",
    ecosystem_context: "Trusted ecosystem context.",
    candidates: input.candidates,
    context: {
      imports: "",
      source: input.source ?? "    10 | const value = true;",
      expansions: [],
      representations: input.representations ?? [
        {
          stage: "raw",
          sha256: digest(`raw:${path}`),
          transform_depth: 0,
        },
      ],
      project_purpose: "A local roleplay extension.",
    },
  };
}

describe("policy v5 deterministic review triage", () => {
  test("hard escalator keeps the entire behavior case contextual", () => {
    const plan = triageEvidenceGroups([
      group({
        candidates: [
          candidate("javascript.xray.unsafe-regex"),
          candidate("javascript.credential-to-network"),
        ],
      }),
    ]);

    expect(plan.deterministicAssessments).toHaveLength(0);
    expect(plan.contextualGroups).toHaveLength(1);
    expect(plan.contextualGroups[0]?.candidates).toHaveLength(2);
    expect(plan.decisions.map((item) => item.reason_code)).toEqual([
      "hard-dangerous-correlation",
      "hard-dangerous-correlation",
    ]);
  });

  test.each<
    [
      ruleId: string,
      scope: ExecutionScope,
      expected: string,
      reasonCode: string,
      overrides?: Partial<EvidenceCandidate>,
    ]
  >([
    [
      "javascript.xray.unsafe-regex",
      "tooling-only",
      "expected_behavior",
      "javascript-unsafe-regex-inert",
    ],
    [
      "javascript.xray.unsafe-regex",
      "runtime",
      "minor_weakness",
      "javascript-unsafe-regex-runtime-low",
    ],
    [
      "javascript.xray.serialize-environment",
      "tooling-only",
      "expected_behavior",
      "javascript-xray-inert-tooling",
    ],
    [
      "javascript.xray.serialize-environment",
      "runtime",
      "contextual-review",
      "runtime-cross-boundary-signal",
    ],
    [
      "javascript.xray.shady-link",
      "test-documentation-data",
      "expected_behavior",
      "javascript-xray-inert-content",
    ],
    [
      "RUSTSEC-2024-0414:pkg:e12ed7daa8c1d8360f101be8",
      "runtime",
      "material_vulnerability",
      "osv-structured-advisory",
      {
        origin: "osv-scanner",
        category: "dependency-advisory",
        scanner_severity: "high",
        scanner_confidence: "high",
        line_start: null,
        line_end: null,
      },
    ],
    [
      "unknown.future-rule",
      "tooling-only",
      "contextual-review",
      "unknown-rule",
    ],
  ])(
    "maps %s in %s to %s",
    (ruleId, scope, expected, reasonCode, overrides = {}) => {
      const plan = triageEvidenceGroups([
        group({
          execution_scope: scope,
          candidates: [candidate(ruleId, overrides)],
        }),
      ]);

      expect(plan.decisions[0]?.reason_code).toBe(reasonCode);
      if (expected === "contextual-review") {
        expect(plan.contextualGroups).toHaveLength(1);
        expect(plan.deterministicAssessments).toHaveLength(0);
      } else {
        expect(plan.contextualGroups).toHaveLength(0);
        expect(plan.deterministicAssessments).toHaveLength(1);
        expect(plan.deterministicAssessments[0]?.disposition).toBe(expected);
      }
    },
  );

  const xrayRuntimeLow = ["synchronous-io", "log-usage"];
  const xrayStructuredWeakness = [
    "crypto.weak-algorithm",
    "crypto.weak-scrypt",
    "crypto.unsafe-prehash",
    "crypto.weak-bcrypt",
    "crypto.password-shucking",
    "sql-injection",
    "monkey-patch",
    "prototype-pollution",
  ];
  const xrayAmbiguous = [
    "unsafe-stmt",
    "short-identifiers",
    "suspicious-literal",
    "suspicious-file",
    "obfuscated-code",
    "shady-link",
    "unsafe-command",
    "unsafe-import",
    "serialize-environment",
    "data-exfiltration",
    "unsafe-vm-context",
  ];

  test.each([
    ...["runtime", "install-update", "automation"].flatMap((scope) => [
      ...xrayRuntimeLow.map(
        (rule): [string, ExecutionScope, "deterministic"] => [
          rule,
          scope as ExecutionScope,
          "deterministic",
        ],
      ),
      ...xrayStructuredWeakness.map(
        (rule): [string, ExecutionScope, "deterministic"] => [
          rule,
          scope as ExecutionScope,
          "deterministic",
        ],
      ),
      ...xrayAmbiguous.map((rule): [string, ExecutionScope, "contextual"] => [
        rule,
        scope as ExecutionScope,
        "contextual",
      ]),
    ]),
    ...["tooling-only", "test-documentation-data"].flatMap((scope) =>
      [...xrayRuntimeLow, ...xrayStructuredWeakness, ...xrayAmbiguous].map(
        (rule): [string, ExecutionScope, "deterministic"] => [
          rule,
          scope as ExecutionScope,
          "deterministic",
        ],
      ),
    ),
    ...[
      ...xrayRuntimeLow,
      ...xrayStructuredWeakness,
      ...xrayAmbiguous,
      "encoded-literal",
    ].map((rule): [string, ExecutionScope, "contextual"] => [
      rule,
      "unknown",
      "contextual",
    ]),
  ] as const)("maps X-Ray %s in %s to %s", (warning, scope, destination) => {
    const plan = triageEvidenceGroups([
      group({
        execution_scope: scope,
        candidates: [candidate(`javascript.xray.${warning}`)],
      }),
    ]);

    expect(plan.decisions[0]?.destination).toBe(destination);
    if (scope === "unknown")
      expect(plan.decisions[0]?.reason_code).toBe("unknown-execution-scope");
  });

  test("keeps unresolved encoded literals deterministic only in proven inert scopes", () => {
    const inert = triageEvidenceGroups([
      group({
        execution_scope: "tooling-only",
        candidates: [candidate("javascript.xray.encoded-literal")],
      }),
    ]);
    const runtime = triageEvidenceGroups([
      group({
        execution_scope: "runtime",
        candidates: [candidate("javascript.xray.encoded-literal")],
      }),
    ]);

    expect(inert.decisions[0]).toMatchObject({
      destination: "deterministic",
      reason_code: "javascript-xray-inert-tooling",
    });
    expect(runtime.decisions[0]).toMatchObject({
      destination: "contextual",
      reason_code: "javascript-encoded-literal-unresolved",
    });
  });

  test.each([
    "runtime",
    "install-update",
    "automation",
    "tooling-only",
    "test-documentation-data",
  ] as const)(
    "resolves decoded isolated literals in %s without a model call",
    (scope) => {
      const path = "src/encoded.js";
      const plan = triageEvidenceGroups([
        group({
          path,
          execution_scope: scope,
          candidates: [candidate("javascript.xray.encoded-literal")],
          representations: [
            {
              stage: "raw",
              sha256: digest(`raw:${path}`),
              transform_depth: 0,
            },
            {
              stage: "decoded",
              sha256: digest(`decoded:${path}`),
              transform_depth: 1,
            },
          ],
        }),
      ]);

      expect(plan.decisions[0]).toMatchObject({
        destination: "deterministic",
        reason_code: "javascript-encoded-literal-decoded",
      });
    },
  );

  test.each<
    [
      name: string,
      ruleId: string,
      scope: ExecutionScope,
      destination: "deterministic" | "contextual",
      reasonCode: string,
      overrides: Partial<EvidenceCandidate>,
      source?: string,
    ]
  >([
    [
      "placeholder secret fixture",
      "generic-api-key",
      "test-documentation-data",
      "deterministic",
      "gitleaks-inert-placeholder",
      { origin: "gitleaks", category: "credential-exposure" },
      '    10 | const token = "example-placeholder";',
    ],
    [
      "plausible runtime secret",
      "generic-api-key",
      "runtime",
      "contextual",
      "gitleaks-credential-ambiguity",
      { origin: "gitleaks", category: "credential-exposure" },
    ],
    [
      "known workflow weakness",
      "template-injection",
      "automation",
      "deterministic",
      "zizmor-known-workflow-rule",
      { origin: "zizmor", category: "workflow-security" },
    ],
    [
      "unknown workflow rule",
      "future-zizmor-rule",
      "automation",
      "contextual",
      "unknown-rule",
      { origin: "zizmor", category: "workflow-security" },
    ],
    [
      "bidirectional source control",
      "unicode-bidi-control",
      "runtime",
      "deterministic",
      "owned-structured-weakness",
      { origin: "tavernkeeper", category: "source-integrity" },
    ],
    [
      "owned runtime dynamic execution",
      "tavernkeeper.dynamic-execution.javascript-eval",
      "runtime",
      "contextual",
      "owned-context-dependent-rule",
      { origin: "opengrep", category: "dynamic-execution" },
    ],
    [
      "inert owned dynamic execution",
      "javascript.opengrep.tavernkeeper.dynamic-execution.javascript-eval",
      "tooling-only",
      "deterministic",
      "owned-inert-tooling",
      { origin: "javascript-analysis", category: "dynamic-execution" },
    ],
    [
      "runtime binary capability",
      "execution-process",
      "runtime",
      "contextual",
      "malcontent-runtime-capability",
      { origin: "malcontent", category: "binary-analysis" },
    ],
    [
      "inert binary capability",
      "execution-process",
      "test-documentation-data",
      "deterministic",
      "malcontent-inert-asset",
      { origin: "malcontent", category: "binary-analysis" },
    ],
  ])(
    "handles $name",
    (_name, ruleId, scope, destination, reasonCode, overrides, source) => {
      const plan = triageEvidenceGroups([
        group({
          execution_scope: scope,
          candidates: [candidate(ruleId, overrides)],
          ...(source === undefined ? {} : { source }),
        }),
      ]);

      expect(plan.decisions[0]).toMatchObject({
        destination,
        reason_code: reasonCode,
      });
    },
  );

  test("distinguishes incomplete test key markers from complete private keys", () => {
    const incomplete = triageEvidenceGroups([
      group({
        path: "tools/scripts/test-cards.mjs",
        execution_scope: "tooling-only",
        candidates: [
          candidate("private-key", {
            origin: "gitleaks",
            category: "credential-exposure",
          }),
        ],
        source:
          '    10 | const marker = "-----BEGIN PRIVATE KEY----- TESTKEY";',
      }),
    ]);
    const complete = triageEvidenceGroups([
      group({
        path: "tools/scripts/test-cards.mjs",
        execution_scope: "tooling-only",
        candidates: [
          candidate("private-key", {
            origin: "gitleaks",
            category: "credential-exposure",
          }),
        ],
        source: [
          '    10 | const key = "-----BEGIN PRIVATE KEY-----',
          "    11 | MIIEvQIBADANBgkqhkiG9w0BAQEFAASC",
          '    12 | -----END PRIVATE KEY-----";',
        ].join("\n"),
      }),
    ]);

    expect(incomplete.decisions[0]).toMatchObject({
      destination: "deterministic",
      reason_code: "gitleaks-inert-placeholder",
    });
    expect(complete.decisions[0]).toMatchObject({
      destination: "contextual",
      reason_code: "gitleaks-credential-ambiguity",
    });
  });

  test("correlates active dynamic execution and network signals before benign rules", () => {
    const plan = triageEvidenceGroups([
      group({
        execution_scope: "runtime",
        candidates: [
          candidate("javascript.xray.unsafe-stmt", {
            category: "code-execution",
          }),
          candidate("javascript.xray.shady-link", {
            category: "network-access",
          }),
        ],
      }),
    ]);

    expect(plan.contextualGroups[0]?.candidates).toHaveLength(2);
    expect(plan.decisions.map(({ reason_code }) => reason_code)).toEqual([
      "hard-dangerous-correlation",
      "hard-dangerous-correlation",
    ]);
  });

  test("partitions every candidate once with valid local assessments and reconciled counts", () => {
    const candidates = [
      candidate("javascript.xray.unsafe-regex"),
      candidate("RUSTSEC-2024-0414:pkg:e12ed7daa8c1d8360f101be8", {
        origin: "osv-scanner",
        category: "dependency-advisory",
        line_start: null,
        line_end: null,
      }),
      candidate("unknown.future-rule"),
    ];
    const plan = triageEvidenceGroups([
      group({ execution_scope: "runtime", candidates }),
    ]);
    const assessed = plan.deterministicAssessments.map(
      ({ candidate_id }) => candidate_id,
    );
    const contextual = plan.contextualGroups.flatMap(({ candidates }) =>
      candidates.map(({ candidate_id }) => candidate_id),
    );

    expect([...assessed, ...contextual].sort()).toEqual(
      candidates.map(({ candidate_id }) => candidate_id).sort(),
    );
    expect(new Set([...assessed, ...contextual])).toHaveProperty(
      "size",
      candidates.length,
    );
    for (const assessment of plan.deterministicAssessments) {
      expect(ContextualAssessmentSchema.safeParse(assessment).success).toBe(
        true,
      );
      expect(assessment.locations[0]?.path).toBe("scripts/check.mjs");
    }
    expect(plan.counts.candidates).toEqual({
      total: 3,
      deterministic: 2,
      contextual: 1,
    });
    expect(
      plan.counts.reasons.reduce((total, { count }) => total + count, 0),
    ).toBe(3);
  });
});
