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
const publisherAction =
  "actions/create-github-app-token@fee1f7d63c2ff003460e3d139729b119787bc349";
const mutationJobs = {
  "reconcile.yml": "publish",
  "deep-scan.yml": "scan",
  "adjudicate.yml": "adjudicate",
  "policy-rescan.yml": "schedule",
  "staff-operations.yml": "operate",
} as const;
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
    expect(value.jobs.publish.permissions.contents).toBe("read");
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

  test("mutation jobs use only a protected Publisher App token for direct pushes", async () => {
    for (const [name, jobName] of Object.entries(mutationJobs)) {
      const value = await workflow(name);
      const job = value.jobs[jobName];
      const effectivePermissions = {
        ...value.permissions,
        ...job.permissions,
      };

      expect(effectivePermissions.contents, `${name} contents`).toBe("read");
      expect(job.environment, `${name} environment`).toMatch(
        /^tavernkeeper-(?:scanner|staff)$/u,
      );

      const publisherSteps = job.steps.filter((step: Workflow) =>
        JSON.stringify(step).match(
          /TAVERNKEEPER_PUBLISHER_APP_(?:ID|PRIVATE_KEY)/u,
        ),
      );
      expect(publisherSteps, `${name} Publisher secret steps`).toHaveLength(1);
      expect(publisherSteps[0]).toMatchObject({
        name: "Create TavernKeeper Publisher token",
        id: "publisher-token",
        uses: publisherAction,
        with: {
          "app-id": "${{ secrets.TAVERNKEEPER_PUBLISHER_APP_ID }}",
          "private-key":
            "${{ secrets.TAVERNKEEPER_PUBLISHER_APP_PRIVATE_KEY }}",
          owner: "MentallyQuill",
          repositories: "TavernKeeper",
          "permission-contents": "write",
        },
      });

      const checkoutSteps = job.steps.filter(
        (step: Workflow) =>
          typeof step.uses === "string" &&
          step.uses.startsWith("actions/checkout@"),
      );
      expect(checkoutSteps.length, `${name} checkout count`).toBeGreaterThan(0);
      expect(
        checkoutSteps.every(
          (step: Workflow) => step.with?.["persist-credentials"] === false,
        ),
        `${name} checkout credentials`,
      ).toBe(true);

      const pushSteps = job.steps.filter(
        (step: Workflow) =>
          typeof step.run === "string" &&
          step.run.includes("git push origin HEAD:main"),
      );
      expect(pushSteps, `${name} push steps`).toHaveLength(1);
      expect(pushSteps[0].env?.GH_TOKEN, `${name} push token`).toBe(
        "${{ steps.publisher-token.outputs.token }}",
      );
      expect(pushSteps[0].run, `${name} Git authentication`).toMatch(
        /gh auth setup-git/u,
      );
    }
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

  test("workflow policy rejects a direct push authenticated by github.token", async () => {
    await expectPolicyFailure(
      (text) =>
        text.replace(
          "GH_TOKEN: ${{ steps.publisher-token.outputs.token }}",
          "GH_TOKEN: ${{ github.token }}",
        ),
      /reconcile\.yml: direct push does not use the Publisher App token/u,
    );
  });

  test("workflow policy rejects Publisher secrets outside the token step", async () => {
    await expectPolicyFailure(
      (text) =>
        text.replace(
          "  scan:\n",
          "  scan:\n    env:\n      TAVERNKEEPER_PUBLISHER_APP_ID: ${{ secrets.TAVERNKEEPER_PUBLISHER_APP_ID }}\n",
        ),
      /reconcile\.yml: Publisher App secret appears outside the reviewed token step/u,
    );
  });

  test("workflow policy rejects an Actions dispatch in the Publisher push step", async () => {
    await expectPolicyFailure(
      (text) =>
        text.replace(
          "git push origin HEAD:main",
          "git push origin HEAD:main\n            gh workflow run reconcile.yml --ref main",
        ),
      /reconcile\.yml: direct push step also dispatches Actions/u,
    );
  });

  test("workflow policy rejects an additional Publisher token consumer", async () => {
    await expectPolicyFailure(
      (text) =>
        text.replace(
          "      - name: Commit reports and state\n",
          "      - name: Unreviewed Publisher mutation\n        env:\n          GH_TOKEN: ${{ steps.publisher-token.outputs.token }}\n        run: gh api --method PATCH repos/MentallyQuill/TavernKeeper/git/refs/heads/main -f force=true\n      - name: Commit reports and state\n",
        ),
      /reconcile\.yml: Publisher App token is consumed outside the reviewed commit step/u,
    );
  });

  test("workflow policy rejects an additional force push from the Publisher step", async () => {
    await expectPolicyFailure(
      (text) =>
        text.replace(
          "git push origin HEAD:main",
          "git push origin HEAD:main\n            git push --force origin HEAD:main",
        ),
      /reconcile\.yml: Publisher-authenticated commit script changed from the reviewed contract/u,
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
