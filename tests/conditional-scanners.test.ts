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

const repositoryRoot = join(tmpdir(), "tavernkeeper-scan-repository");

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
              path: join(repositoryRoot, "package-lock.json"),
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
                    summary: "UNTRUSTED ADVISORY PROSE MUST NOT BE PUBLISHED",
                    details:
                      "Visit https://attacker.example/advisory for details.",
                    references: [
                      { type: "WEB", url: "https://attacker.example/raw" },
                    ],
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
      root: repositoryRoot,
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
      `--lockfile=${join(repositoryRoot, "package-lock.json")}`,
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
          rule_id: expect.stringMatching(
            /^GHSA-aaaa-bbbb-cccc:pkg:[a-f0-9]{24}$/u,
          ),
          category: "dependency-vulnerability",
          severity: "high",
          confidence: "high",
          path: "package-lock.json",
          evidence_sha: null,
          title: "Known vulnerable npm dependency: example@1.0.0",
          explanation:
            "OSV-Scanner matched a known advisory for npm package example at resolved version 1.0.0.",
        }),
      ],
    });
    expect(JSON.stringify(run.findings)).not.toContain(
      "UNTRUSTED ADVISORY PROSE",
    );
    expect(JSON.stringify(run.findings)).not.toContain("attacker.example");
  });

  test("OSV is not applicable without a supported manifest", async () => {
    const runner = new JsonRunner("{}");
    await expect(
      runOsv({
        root: repositoryRoot,
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

  test("OSV accepts and safely renders a v2.4 commit-addressed package", async () => {
    const commit = "b8da07095979310818f0efde2ef3c69ea70d62c5";
    const runner = new JsonRunner(
      JSON.stringify({
        results: [
          {
            source: { path: "deps_flatten.txt", type: "lockfile" },
            packages: [
              {
                package: {
                  name: "https://fuchsia.googlesource.com/third_party/perfetto",
                  version: "",
                  ecosystem: "",
                  commit,
                },
                vulnerabilities: [{ id: "OSV-2023-72" }],
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
      root: repositoryRoot,
      inputs: [file("deps_flatten.txt")],
      runner,
      version: "2.4.0",
      temporaryRoot,
    });

    expect(run.findings).toEqual([
      expect.objectContaining({
        rule_id: expect.stringMatching(/^OSV-2023-72:pkg:[a-f0-9]{24}$/u),
        title: `Known vulnerable commit dependency: ${commit}`,
        explanation: `OSV-Scanner matched a known advisory for a commit-addressed dependency at commit ${commit}.`,
      }),
    ]);
    expect(JSON.stringify(run.findings)).not.toContain(
      "fuchsia.googlesource.com",
    );
  });

  test("OSV never publishes git repository names when a commit is present", async () => {
    const packages = [
      {
        name: "https://github.com/sfackler/rust-openssl",
        commit: "0f428d190410263e4daa65b917c0e84707a9c0ef",
        version: "openssl-v0.8.1",
        ecosystem: "GIT",
      },
      {
        name: "git://github.com/boostorg/boost",
        commit: "1a9dda41fbfb0dfbec17ab6afeba8138265395f7",
        version: "boost-1.67.0",
        ecosystem: "GIT",
      },
      {
        name: "github.com/boostorg/boost",
        commit: "1a9dda41fbfb0dfbec17ab6afeba8138265395f7",
        version: "boost-1.67.0",
        ecosystem: "GIT",
      },
    ];
    const runner = new JsonRunner(
      JSON.stringify({
        results: [
          {
            source: { path: "osv-scanner.json", type: "lockfile" },
            packages: packages.map((identity) => ({
              package: identity,
              vulnerabilities: [{ id: "OSV-2023-72" }],
            })),
          },
        ],
      }),
      1,
    );
    const temporaryRoot = await mkdtemp(
      join(tmpdir(), "tavernkeeper-osv-test-"),
    );

    const run = await runOsv({
      root: repositoryRoot,
      inputs: [file("osv-scanner.json")],
      runner,
      version: "2.4.0",
      temporaryRoot,
    });

    expect(run.findings).toHaveLength(3);
    expect(run.findings.map(({ title }) => title).sort()).toEqual(
      packages
        .map(
          ({ commit, version }) =>
            `Known vulnerable git dependency: ${version}@${commit}`,
        )
        .sort(),
    );
    expect(JSON.stringify(run.findings)).not.toContain("github.com");
  });

  test("OSV bounds git finding titles at maximum identity lengths", async () => {
    const commit = "a".repeat(64);
    const runner = new JsonRunner(
      JSON.stringify({
        results: [
          {
            source: { path: "osv-scanner.json", type: "lockfile" },
            packages: [
              {
                package: {
                  name: "https://github.com/example/repository",
                  version: `v${"1".repeat(159)}`,
                  ecosystem: "GIT",
                  commit,
                },
                vulnerabilities: [{ id: "OSV-2023-72" }],
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
      root: repositoryRoot,
      inputs: [file("osv-scanner.json")],
      runner,
      version: "2.4.0",
      temporaryRoot,
    });

    expect(run.findings).toEqual([
      expect.objectContaining({
        title: `Known vulnerable git dependency: ${commit}`,
      }),
    ]);
    expect(run.findings[0]!.title.length).toBeLessThanOrEqual(200);
  });

  test("OSV preserves package-specific findings deterministically", async () => {
    const packages: Array<{
      name: string;
      version: string;
      ecosystem: string;
      commit?: string;
    }> = [
      { name: "example", version: "1.0.0", ecosystem: "npm" },
      { name: "example", version: "2.0.0", ecosystem: "npm" },
      { name: "example", version: "1.0.0", ecosystem: "PyPI" },
      { name: "different", version: "1.0.0", ecosystem: "npm" },
      {
        name: "https://example.invalid/repository",
        version: "v1.0.0",
        ecosystem: "",
        commit: "a".repeat(40),
      },
      {
        name: "https://example.invalid/repository",
        version: "v1.0.0",
        ecosystem: "",
        commit: "b".repeat(40),
      },
    ];
    const report = (orderedPackages: typeof packages) =>
      JSON.stringify({
        results: [
          {
            source: { path: "package-lock.json", type: "lockfile" },
            packages: orderedPackages.map((identity) => ({
              package: identity,
              vulnerabilities: [{ id: "GHSA-aaaa-bbbb-cccc" }],
            })),
          },
        ],
      });
    const temporaryRoot = await mkdtemp(
      join(tmpdir(), "tavernkeeper-osv-test-"),
    );
    const forward = await runOsv({
      root: repositoryRoot,
      inputs: [file("package-lock.json")],
      runner: new JsonRunner(report(packages), 1),
      version: "2.4.0",
      temporaryRoot,
    });
    const reverse = await runOsv({
      root: repositoryRoot,
      inputs: [file("package-lock.json")],
      runner: new JsonRunner(report([...packages].reverse()), 1),
      version: "2.4.0",
      temporaryRoot,
    });

    expect(forward.findings).toHaveLength(6);
    expect(
      new Set(forward.findings.map(({ fingerprint }) => fingerprint)).size,
    ).toBe(6);
    expect(forward.findings.map(({ title }) => title).sort()).toEqual(
      packages
        .map(({ commit, ecosystem, name, version }) =>
          commit !== undefined
            ? `Known vulnerable git dependency: ${version}@${commit}`
            : `Known vulnerable ${ecosystem} dependency: ${name}@${version}`,
        )
        .sort(),
    );
    expect(reverse.findings).toEqual(forward.findings);
  });

  test.each([
    ["a missing resolved version", { name: "example", ecosystem: "npm" }],
    [
      "an overlong package name",
      { name: "x".repeat(161), version: "1.0.0", ecosystem: "npm" },
    ],
    [
      "a bidirectional control",
      { name: "exam\u202eple", version: "1.0.0", ecosystem: "npm" },
    ],
    [
      "a URL-shaped version",
      {
        name: "example",
        version: "https://attacker.example/payload",
        ecosystem: "npm",
      },
    ],
  ])("OSV rejects package identity containing %s", async (_label, identity) => {
    const runner = new JsonRunner(
      JSON.stringify({
        results: [
          {
            source: { path: "package-lock.json", type: "lockfile" },
            packages: [
              {
                package: identity,
                vulnerabilities: [{ id: "GHSA-aaaa-bbbb-cccc" }],
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

    await expect(
      runOsv({
        root: repositoryRoot,
        inputs: [file("package-lock.json")],
        runner,
        version: "2.4.0",
        temporaryRoot,
      }),
    ).rejects.toMatchObject({
      code: "MALFORMED_SCANNER_OUTPUT",
      scope: "system",
    });
  });

  test("OSV rejects no-package exit 128 instead of reporting partial coverage", async () => {
    const runner = new JsonRunner(JSON.stringify({ results: [] }), 128);
    const temporaryRoot = await mkdtemp(
      join(tmpdir(), "tavernkeeper-osv-test-"),
    );

    await expect(
      runOsv({
        root: repositoryRoot,
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
      root: repositoryRoot,
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
      join(repositoryRoot, ".github", "workflows", "scan.yml"),
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
        root: repositoryRoot,
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
      root: repositoryRoot,
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
      join(repositoryRoot, "bin", "helper.exe"),
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
          rule_id: "execution-download-and-execute",
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
        root: repositoryRoot,
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

  test("malcontent accepts a clean report with the omitted empty Files field", async () => {
    const runner = new JsonRunner("{}");

    await expect(
      runMalcontent({
        root: repositoryRoot,
        inputs: [file("bin/clean-helper.exe")],
        runner,
        version: "1.25.7",
      }),
    ).resolves.toMatchObject({
      name: "malcontent",
      status: "completed",
      findings: [],
    });
  });

  test("malcontent rejects malformed JSON instead of returning empty coverage", async () => {
    const runner = new JsonRunner("not-json");

    await expect(
      runMalcontent({
        root: repositoryRoot,
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
