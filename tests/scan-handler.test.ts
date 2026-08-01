import { describe, expect, test } from "vitest";

import { scanRepository } from "../src/orchestrator/scan-handler.js";
import type { Inventory } from "../src/inventory/inventory-handler.js";
import type { ExternalToolRun } from "../src/scanners/external-tools.js";

const fullSha = "a".repeat(40);
const inventory: Inventory = {
  root: "C:/scan/repository",
  totalBytes: 100,
  files: [
    {
      path: "README.md",
      bytes: 100,
      sha256: "b".repeat(64),
      kind: "text",
      content: "A normal project.",
    },
  ],
};

describe("scan orchestration", () => {
  test("publishes no report when required scanner or model coverage is incomplete", async () => {
    const externalRuns: ExternalToolRun[] = [
      {
        name: "gitleaks",
        status: "unavailable",
        version: null,
        detail: "Executable not found.",
        findings: [],
      },
    ];
    const result = await scanRepository(
      {
        target: {
          source_id: "github-42",
          provider: "github",
          repository_id: 42,
          repository: "owner/repo",
          target_sha: fullSha,
          canonical_url: "https://github.com/owner/repo",
        },
        root: inventory.root,
        historyCommits: 5,
        scannedAt: "2026-07-31T12:00:00.000Z",
        scannerVersion: "0.1.0",
        mode: "standard",
        model: {
          enabled: false,
          apiKey: null,
          baseUrl: "https://api.minimax.io/v1",
          model: "MiniMax-M3",
        },
      },
      {
        inventory: async () => ({ ok: true, value: inventory }),
        staticScan: () => [],
        externalScan: async () => externalRuns,
        review: async () => ({
          ok: true,
          value: {
            status: "disabled",
            provider: null,
            model: null,
            findings: [],
          },
        }),
      },
    );

    expect(result).toMatchObject({
      ok: false,
      error: { code: "REQUIRED_COVERAGE_INCOMPLETE" },
    });
  });

  test("publishes no transitional report before complete report assembly exists", async () => {
    const result = await scanRepository(
      {
        target: {
          source_id: "github-42",
          provider: "github",
          repository_id: 42,
          repository: "owner/repo",
          target_sha: fullSha,
          canonical_url: "https://github.com/owner/repo",
        },
        root: inventory.root,
        historyCommits: 5,
        scannedAt: "2026-07-31T12:00:00.000Z",
        scannerVersion: "0.1.0",
        mode: "standard",
        model: {
          enabled: true,
          apiKey: "test-key",
          baseUrl: "https://api.minimax.io/v1",
          model: "MiniMax-M3",
        },
      },
      {
        inventory: async () => ({ ok: true, value: inventory }),
        staticScan: () => [],
        externalScan: async () => [
          {
            name: "gitleaks",
            status: "completed",
            version: "8.30.1",
            findings: [],
          },
        ],
        review: async () => ({
          ok: true,
          value: {
            status: "completed",
            provider: "minimax",
            model: "MiniMax-M3",
            findings: [],
          },
        }),
      },
    );

    expect(result).toMatchObject({
      ok: false,
      error: { code: "REPORT_ASSEMBLY_PENDING" },
    });
  });
});
