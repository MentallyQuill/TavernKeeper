import { describe, expect, test } from "vitest";

import type { ModelChunkSegment } from "../src/model/chunker.js";
import {
  RepositorySynthesisSchema,
  sanitizePrivateChunkReview,
} from "../src/model/review-contracts.js";

describe("repository synthesis contracts", () => {
  test("accepts clean and concerning completed reports", () => {
    const clean = RepositorySynthesisSchema.parse({
      assessment: "no_concerning_evidence",
      recap: "All required reviews completed without a review-level concern.",
      concerns: [],
    });

    const concerning = RepositorySynthesisSchema.parse({
      assessment: "concerning",
      recap:
        "The reviewed code transmits a stored API key to an unrelated host.",
      concerns: [
        {
          title: "Stored API key transmission",
          category: "credential-theft",
          severity: "high",
          confidence: "high",
          explanation: "The outbound request includes a stored credential.",
          evidence_ids: ["source-000001", "tool-000001"],
        },
      ],
    });

    expect(clean.assessment).toBe("no_concerning_evidence");
    expect(concerning.concerns).toHaveLength(1);
  });

  test("rejects duplicate evidence identifiers within a concern", () => {
    expect(() =>
      RepositorySynthesisSchema.parse({
        assessment: "concerning",
        recap: "The review found a credential transmission concern.",
        concerns: [
          {
            title: "Stored API key transmission",
            category: "credential-theft",
            severity: "high",
            confidence: "high",
            explanation: "The outbound request includes a stored credential.",
            evidence_ids: ["source-000001", "source-000001"],
          },
        ],
      }),
    ).toThrow();
  });

  test("rejects concerns paired with no concerning evidence", () => {
    expect(() =>
      RepositorySynthesisSchema.parse({
        assessment: "no_concerning_evidence",
        recap: "The review claims both a clean result and a concern.",
        concerns: [
          {
            title: "Stored API key transmission",
            category: "credential-theft",
            severity: "high",
            confidence: "high",
            explanation: "The outbound request includes a stored credential.",
            evidence_ids: ["source-000001"],
          },
        ],
      }),
    ).toThrow();
  });

  test("requires a credible medium-or-higher concern for a concerning assessment", () => {
    expect(() =>
      RepositorySynthesisSchema.parse({
        assessment: "concerning",
        recap: "The review found only a low-confidence informational concern.",
        concerns: [
          {
            title: "Weak signal",
            category: "credential-theft",
            severity: "info",
            confidence: "low",
            explanation: "The evidence does not establish review-level risk.",
            evidence_ids: ["source-000001"],
          },
        ],
      }),
    ).toThrow();
  });

  test("rejects malformed completed-report fields", () => {
    const base = {
      assessment: "no_concerning_evidence",
      recap: "Completed review.",
      concerns: [],
    };

    expect(() =>
      RepositorySynthesisSchema.parse({ ...base, extra: true }),
    ).toThrow();
    expect(() =>
      RepositorySynthesisSchema.parse({ ...base, assessment: "inconclusive" }),
    ).toThrow();
    expect(() =>
      RepositorySynthesisSchema.parse({ ...base, recap: "  " }),
    ).toThrow();
    expect(() =>
      RepositorySynthesisSchema.parse({
        assessment: "concerning",
        recap: "Invalid category.",
        concerns: [
          {
            title: "Concern",
            category: "Invalid Category!",
            severity: "high",
            confidence: "high",
            explanation: "Explanation.",
            evidence_ids: ["source-000001"],
          },
        ],
      }),
    ).toThrow();
  });

  test("sanitizes private chunk prose and always returns bounded text", () => {
    const submittedLine = "const transmittedSecret = storedApiKey;";
    const segments: ModelChunkSegment[] = [
      {
        path: "src/index.ts",
        line_start: 1,
        line_end: 1,
        content: submittedLine,
        bytes: submittedLine.length,
        overlap_bytes: 0,
        content_hash: "a".repeat(64),
        source_sha256: "b".repeat(64),
      },
    ];
    const secret = "ghp_abcdefghijklmnopqrstuvwxyz123456";

    const sanitized = sanitizePrivateChunkReview(
      `  ${submittedLine}\u0000  token ${secret}  `,
      segments,
      80,
    );

    expect(sanitized).not.toContain(submittedLine);
    expect(sanitized).not.toContain(secret);
    expect(sanitized).not.toMatch(/[\u0000-\u001f\u007f]/u);
    expect(sanitized.length).toBeLessThanOrEqual(80);
    expect(sanitizePrivateChunkReview("\u0000 \n", [], 8)).not.toBe("");
  });
});
