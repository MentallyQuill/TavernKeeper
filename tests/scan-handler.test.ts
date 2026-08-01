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
  test("marks missing optional scanners incomplete without inventing findings", async () => {
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
      ok: true,
      value: {
        status: "incomplete",
        summary: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
        findings: [],
        coverage: {
          complete: false,
          tools: [
            { name: "built-in", status: "completed" },
            { name: "gitleaks", status: "unavailable" },
          ],
          model: { status: "disabled" },
        },
      },
    });
  });
});
