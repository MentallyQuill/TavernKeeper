import { mkdtemp, readFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, test } from "vitest";

import type { InventoryFile } from "../src/inventory/inventory-handler.js";
import { runMalcontent } from "../src/scanners/malcontent.js";
import { runOsv } from "../src/scanners/osv.js";
import { runZizmor } from "../src/scanners/zizmor.js";
import type {
  CommandExecutionResult,
  CommandOptions,
  CommandRunner,
} from "../src/process/command-runner.js";

function file(path: string): InventoryFile {
  return {
    path,
    bytes: 100,
    sha256: "a".repeat(64),
    kind: "text",
  };
}

class JsonRunner implements CommandRunner {
  calls: Array<{ command: string; args: string[]; options: CommandOptions }> =
    [];

  constructor(
    private readonly stdout: string,
    private readonly exitCode = 0,
  ) {}

  async run(
    command: string,
    args: string[],
    options: CommandOptions,
  ): Promise<CommandExecutionResult> {
    this.calls.push({ command, args, options });
    return {
      ok: true,
      value: { exitCode: this.exitCode, stdout: this.stdout, stderr: "" },
    };
  }
}

describe("conditional scanner adapters", () => {
  test("OSV scans only classified manifests with target configuration overridden", async () => {
    const runner = new JsonRunner(
      JSON.stringify({
        results: [
          {
            source: {
              path: "C:/scan/repository/package-lock.json",
              type: "lockfile",
            },
            packages: [
              {
                package: {
                  name: "example",
                  version: "1.0.0",
                  ecosystem: "npm",
                },
                vulnerabilities: [
                  {
                    id: "GHSA-aaaa-bbbb-cccc",
                    database_specific: { severity: "HIGH" },
                  },
                ],
              },
            ],
          },
        ],
      }),
      1,
    );
    const temporaryRoot = await mkdtemp(
      join(tmpdir(), "tavernkeeper-osv-test-"),
    );
    const run = await runOsv({
      root: "C:/scan/repository",
      inputs: [file("package-lock.json")],
      runner,
      executable: "C:/trusted/osv-scanner",
      version: "2.4.0",
      temporaryRoot,
    });

    expect(runner.calls).toHaveLength(1);
    expect(runner.calls[0]?.args).toEqual([
      "scan",
      "source",
      "--format=json",
      "--verbosity=error",
      "--no-resolve",
      expect.stringMatching(/^--config=/u),
      "--lockfile=C:\\scan\\repository\\package-lock.json",
    ]);
    expect(runner.calls[0]?.args).not.toContain("--recursive");
    const configPath = runner.calls[0]?.args
      .find((value) => value.startsWith("--config="))
      ?.slice("--config=".length);
    expect(configPath).toBeDefined();
    await expect(readFile(configPath!, "utf8")).rejects.toMatchObject({
      code: "ENOENT",
    });
    expect(run).toMatchObject({
      name: "osv-scanner",
      version: "2.4.0",
      status: "completed",
      findings: [
        expect.objectContaining({
          origin: "osv-scanner",
          rule_id: "GHSA-aaaa-bbbb-cccc",
          category: "dependency-vulnerability",
          severity: "high",
          confidence: "high",
          path: "package-lock.json",
        }),
      ],
    });
  });

  test("OSV is not applicable without a supported manifest", async () => {
    const runner = new JsonRunner("{}");
    await expect(
      runOsv({
        root: "C:/scan/repository",
        inputs: [],
        runner,
        version: "2.4.0",
      }),
    ).resolves.toEqual({
      name: "osv-scanner",
      version: "2.4.0",
      status: "not-applicable",
      findings: [],
    });
    expect(runner.calls).toHaveLength(0);
  });

  test("OSV rejects no-package exit 128 instead of reporting partial coverage", async () => {
    const runner = new JsonRunner(JSON.stringify({ results: [] }), 128);
    const temporaryRoot = await mkdtemp(
      join(tmpdir(), "tavernkeeper-osv-test-"),
    );

    await expect(
      runOsv({
        root: "C:/scan/repository",
        inputs: [file("package-lock.json")],
        runner,
        version: "2.4.0",
        temporaryRoot,
      }),
    ).rejects.toMatchObject({
      code: "SCANNER_FAILED",
      scope: "repository",
    });
  });

  test("zizmor audits only classified workflow files offline with ignores disabled", async () => {
    const sourceFragment = "echo ${{ secrets.API_KEY }}";
    const runner = new JsonRunner(
      JSON.stringify([
        {
          ident: "template-injection",
          desc: "code injection via template expansion",
          determinations: {
            confidence: "High",
            severity: "High",
            persona: "Regular",
          },
          locations: [
            {
              symbolic: {
                key: {
                  Local: {
                    verbatim_path: "./.github/workflows/scan.yml",
                  },
                },
                kind: "Primary",
              },
              concrete: {
                location: {
                  start_point: { row: 6, column: 4 },
                  end_point: { row: 7, column: 0 },
                },
                feature: sourceFragment,
              },
            },
          ],
          ignored: false,
        },
      ]),
      14,
    );
    const temporaryRoot = await mkdtemp(
      join(tmpdir(), "tavernkeeper-zizmor-test-"),
    );
    const run = await runZizmor({
      root: "C:/scan/repository",
      inputs: [file(".github/workflows/scan.yml")],
      runner,
      executable: "C:/trusted/zizmor",
      version: "1.28.0",
      temporaryRoot,
    });

    expect(runner.calls[0]?.args).toEqual([
      "--format=json-v1",
      "--no-progress",
      "--color=never",
      "--offline",
      "--no-ignores",
      "--strict-collection",
      "--persona=regular",
      "--cache-dir",
      expect.stringMatching(/zizmor-cache$/u),
      "C:\\scan\\repository\\.github\\workflows\\scan.yml",
    ]);
    expect(run).toMatchObject({
      name: "zizmor",
      version: "1.28.0",
      status: "completed",
      findings: [
        expect.objectContaining({
          origin: "zizmor",
          rule_id: "template-injection",
          category: "workflow-security",
          severity: "high",
          confidence: "high",
          path: ".github/workflows/scan.yml",
          line_start: 7,
          line_end: 8,
        }),
      ],
    });
    expect(JSON.stringify(run.findings)).not.toContain(sourceFragment);
  });

  test("zizmor is not applicable without workflow or action files", async () => {
    const runner = new JsonRunner("[]");
    await expect(
      runZizmor({
        root: "C:/scan/repository",
        inputs: [],
        runner,
        version: "1.28.0",
      }),
    ).resolves.toMatchObject({
      name: "zizmor",
      status: "not-applicable",
      findings: [],
    });
    expect(runner.calls).toHaveLength(0);
  });

  test("malcontent scans only classified local artifacts without registry credentials", async () => {
    const sourceFragment = "token=ghp_abcdefghijklmnopqrstuvwxyz1234567890";
    const runner = new JsonRunner(
      JSON.stringify({
        Files: {
          "bin/helper.exe": {
            Path: "bin/helper.exe",
            SHA256: "b".repeat(64),
            Size: 2048,
            Behaviors: [
              {
                Description: "downloads and executes content",
                MatchStrings: [sourceFragment],
                RiskScore: 3,
                RiskLevel: "HIGH",
                ID: "execution/download-and-execute",
                RuleName: "download_and_execute",
              },
            ],
            RiskScore: 3,
            RiskLevel: "HIGH",
          },
        },
      }),
    );
    const run = await runMalcontent({
      root: "C:/scan/repository",
      inputs: [file("bin/helper.exe")],
      runner,
      executable: "C:/trusted/malcontent",
      version: "1.25.7",
    });

    expect(runner.calls[0]?.args).toEqual([
      "scan",
      "--format=json",
      "--exit-extraction",
      "--max-depth=4",
      "--max-files=500000",
      "--max-image-size=1073741824",
      "--min-risk=high",
      "--jobs=2",
      "C:\\scan\\repository\\bin\\helper.exe",
    ]);
    expect(runner.calls[0]?.args).not.toContain("--oci-auth");
    expect(
      Object.keys(runner.calls[0]?.options.environment ?? {}).some((name) =>
        name.startsWith("MALCONTENT_REGISTRY_"),
      ),
    ).toBe(false);
    expect(run).toMatchObject({
      name: "malcontent",
      version: "1.25.7",
      status: "completed",
      findings: [
        expect.objectContaining({
          origin: "malcontent",
          rule_id: "execution/download-and-execute",
          category: "binary-analysis",
          severity: "high",
          confidence: "high",
          path: "bin/helper.exe",
        }),
      ],
    });
    expect(JSON.stringify(run.findings)).not.toContain(sourceFragment);
  });

  test("malcontent is not applicable without binary, archive, or executable inputs", async () => {
    const runner = new JsonRunner("{}");
    await expect(
      runMalcontent({
        root: "C:/scan/repository",
        inputs: [],
        runner,
        version: "1.25.7",
      }),
    ).resolves.toMatchObject({
      name: "malcontent",
      status: "not-applicable",
      findings: [],
    });
    expect(runner.calls).toHaveLength(0);
  });

  test("malcontent rejects malformed JSON instead of returning empty coverage", async () => {
    const runner = new JsonRunner("not-json");

    await expect(
      runMalcontent({
        root: "C:/scan/repository",
        inputs: [file("bin/helper.exe")],
        runner,
        version: "1.25.7",
      }),
    ).rejects.toMatchObject({
      code: "MALFORMED_SCANNER_OUTPUT",
      scope: "system",
    });
  });
});
