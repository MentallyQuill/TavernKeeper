import { describe, expect, test } from "vitest";

import type { Finding } from "../src/contracts/reports.js";
import {
  validateArbiterDecision,
  type EvidenceMap,
} from "../src/model/evidence-validator.js";

const targetSha = "a".repeat(40);
const fingerprint = "b".repeat(64);
const evidence = {
  path: "src/index.ts",
  line_start: 7,
  line_end: 9,
  segment_id: "c".repeat(64),
  content_digest: "d".repeat(64),
  target_sha: targetSha,
};
const finding: Finding = {
  origin: "opengrep",
  rule_id: "credential-exfiltration",
  category: "credential-theft",
  severity: "high",
  confidence: "high",
  path: evidence.path,
  line_start: evidence.line_start,
  line_end: evidence.line_end,
  evidence_sha: null,
  title: "Credential access followed by network transmission",
  explanation: "A deterministic scanner matched this flow.",
  fingerprint,
  disposition: "active",
};
const evidenceMap: EvidenceMap = new Map([
  [
    fingerprint,
    {
      finding,
      evidence,
      automatedReview: {
        analyzer_policy: "analyzer-v1",
        challenger_policy: "challenger-v1",
        arbiter_policy: "arbiter-v1",
      },
    },
  ],
]);
const decision = {
  fingerprint,
  evidence,
  disposition: "confirmed" as const,
  rationale: "The exact evidence supports the normalized claim.",
};

describe("arbiter evidence validation", () => {
  test("constructs a public finding only from exact immutable evidence", () => {
    expect(
      validateArbiterDecision(decision, evidenceMap, targetSha),
    ).toMatchObject({
      fingerprint,
      disposition: "confirmed",
      automated_review: {
        analyzer_policy: "analyzer-v1",
        challenger_policy: "challenger-v1",
        arbiter_policy: "arbiter-v1",
      },
    });
  });

  test.each([
    ["path mismatch", { path: "src/other.ts" }],
    ["line-range escape", { line_end: 10 }],
    ["wrong segment digest", { content_digest: "e".repeat(64) }],
    ["wrong SHA", { target_sha: "f".repeat(40) }],
    ["invented segment", { segment_id: "0".repeat(64) }],
  ])("rejects %s", (_name, mutation) => {
    expect(() =>
      validateArbiterDecision(
        { ...decision, evidence: { ...evidence, ...mutation } },
        evidenceMap,
        targetSha,
      ),
    ).toThrow(
      expect.objectContaining({
        code: "MODEL_EVIDENCE_INVALID",
        scope: "repository",
      }),
    );
  });

  test("rejects an altered or missing fingerprint", () => {
    expect(() =>
      validateArbiterDecision(
        { ...decision, fingerprint: "0".repeat(64) },
        evidenceMap,
        targetSha,
      ),
    ).toThrow(
      expect.objectContaining({
        code: "MODEL_EVIDENCE_INVALID",
        scope: "repository",
      }),
    );
  });
});
