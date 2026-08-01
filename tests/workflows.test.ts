import { execFile as execFileCallback } from "node:child_process";
import {
  mkdtemp,
  mkdir,
  readFile,
  readdir,
  rm,
  writeFile,
} from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";

import { parse } from "yaml";
import { describe, expect, test } from "vitest";

type Workflow = Record<string, any>;
const execFile = promisify(execFileCallback);
const repositoryRoot = fileURLToPath(new URL("../", import.meta.url));
const workflowPolicyScript = fileURLToPath(
  new URL("../scripts/check-workflow-policy.mjs", import.meta.url),
);

async function workflow(name: string): Promise<Workflow> {
  return parse(
    await readFile(
      new URL(`../.github/workflows/${name}`, import.meta.url),
      "utf8",
    ),
  ) as Workflow;
}

async function expectPolicyFailure(
  mutate: (workflow: string) => string,
  expected: RegExp,
) {
  const root = await mkdtemp(join(tmpdir(), "tavernkeeper-workflow-policy-"));
  try {
    await mkdir(join(root, ".github", "workflows"), { recursive: true });
    await mkdir(join(root, "config"), { recursive: true });
    await writeFile(
      join(root, ".github", "workflows", "reconcile.yml"),
      mutate(
        await readFile(
          new URL("../.github/workflows/reconcile.yml", import.meta.url),
          "utf8",
        ),
      ),
    );
    await writeFile(
      join(root, "config", "scanner-policy.v1.json"),
      JSON.stringify({ queue: { batchSize: 5, maxParallel: 2 } }),
    );

    await expect(
      execFile(process.execPath, [workflowPolicyScript], {
        cwd: root,
      }),
    ).rejects.toMatchObject({ stderr: expect.stringMatching(expected) });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

describe("least-privilege GitHub Actions orchestration", () => {
  test("reconcile uses bounded automatic and input-free internal triggers", async () => {
    const value = await workflow("reconcile.yml");

    expect(value.on.schedule).toEqual([{ cron: "13 */6 * * *" }]);
    expect(value.on.workflow_dispatch).toBeNull();
    expect(value.on.workflow_call).toBeNull();
    expect(value.jobs.scan.strategy["max-parallel"]).toBe(2);
    expect(value.jobs.scan.permissions.contents).toBe("read");
    expect(value.jobs.publish.permissions.contents).toBe("write");
    expect(JSON.stringify(value.on)).not.toMatch(
      /issue_comment|issues|pull_request_target/iu,
    );
  });

  test("automatic retry is hourly and exposes no manual inputs", async () => {
    const value = await workflow("retry.yml");

    expect(value.on.schedule).toEqual([{ cron: "17 * * * *" }]);
    expect(value.on.workflow_dispatch).toBeUndefined();
  });

  test("model secrets appear only on the configured-model review step", async () => {
    const value = await workflow("reconcile.yml");
    const scanText = JSON.stringify(value.jobs.scan);
    const secretSteps = value.jobs.scan.steps.filter((step: Workflow) =>
      JSON.stringify(step).match(
        /TAVERNKEEPER_API_(?:ENDPOINT|KEY)|TAVERNKEEPER_MODEL/u,
      ),
    );

    expect(scanText).toMatch(/tavernkeeper-scanner/u);
    expect(secretSteps).toHaveLength(1);
    expect(secretSteps[0].name).toBe("Review with configured model");
  });

  test("workflow policy rejects a reviewed write scope when it moves to another job", async () => {
    await expectPolicyFailure(
      (text) =>
        text.replace(
          "permissions:\n      contents: read\n    strategy:",
          "permissions:\n      contents: read\n      actions: write\n    strategy:",
        ),
      /reconcile\.yml: scan permissions changed/u,
    );
  });

  test("workflow policy rejects model secrets outside review-step environment", async () => {
    await expectPolicyFailure(
      (text) =>
        text.replace(
          "  scan:\n",
          "  scan:\n    env:\n      TAVERNKEEPER_MODEL: ${{ secrets.TAVERNKEEPER_MODEL }}\n",
        ),
      /reconcile\.yml: model secret appears outside the review-step env/u,
    );
  });

  test("workflow policy permits non-secret configured-model cache locations", async () => {
    await expect(
      execFile(process.execPath, [workflowPolicyScript], {
        cwd: repositoryRoot,
      }),
    ).resolves.toMatchObject({
      stdout: expect.stringMatching(/Workflow policy passed/u),
    });
  });

  test("staff scan and adjudication workflows have only protected manual triggers", async () => {
    for (const name of [
      "deep-scan.yml",
      "policy-rescan.yml",
      "adjudicate.yml",
    ]) {
      const value = await workflow(name);
      expect(Object.keys(value.on)).toEqual(["workflow_dispatch"]);
      expect(JSON.stringify(value.jobs)).toMatch(/tavernkeeper-staff/u);
      expect(JSON.stringify(value.on)).not.toMatch(
        /clone_url|model|token|budget|command/iu,
      );
    }
  });

  test("all external Actions are pinned to full commit SHAs", async () => {
    const names = (
      await readdir(new URL("../.github/workflows/", import.meta.url))
    ).filter((name) => /\.ya?ml$/u.test(name));
    const texts = await Promise.all(
      names.map((name) =>
        readFile(
          new URL(`../.github/workflows/${name}`, import.meta.url),
          "utf8",
        ),
      ),
    );
    const uses = texts.flatMap((text) =>
      [...text.matchAll(/^\s*uses:\s*([^\s#]+).*$/gmu)].map(
        (match) => match[1]!,
      ),
    );

    expect(uses.length).toBeGreaterThan(0);
    expect(
      uses.every(
        (value) =>
          value.startsWith("./.github/workflows/") ||
          /@[0-9a-f]{40}$/u.test(value),
      ),
    ).toBe(true);
  });

  test("Pages deploy verifies an exact main SHA before waking Tavernary without scan inputs", async () => {
    const text = await readFile(
      new URL("../.github/workflows/deploy-pages.yml", import.meta.url),
      "utf8",
    );

    expect(text).toMatch(/merge-base --is-ancestor/iu);
    expect(text).toMatch(/reports\/index\.json/iu);
    expect(text).toMatch(/actions\/workflows\/.+\/dispatches/iu);
    expect(text).not.toMatch(
      /report_url|target_sha|token_budget|priority|mode:/iu,
    );
  });
});
