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
const publisherAction =
  "actions/create-github-app-token@fee1f7d63c2ff003460e3d139729b119787bc349";

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
    const names = await readdir(
      new URL("../.github/workflows/", import.meta.url),
    );
    await Promise.all(
      names
        .filter((name) => /\.ya?ml$/u.test(name))
        .map(async (name) =>
          writeFile(
            join(root, ".github", "workflows", name),
            name === "scan-and-publish.yml"
              ? mutate(
                  await readFile(
                    new URL(`../.github/workflows/${name}`, import.meta.url),
                    "utf8",
                  ),
                )
              : await readFile(
                  new URL(`../.github/workflows/${name}`, import.meta.url),
                  "utf8",
                ),
          ),
        ),
    );
    await writeFile(
      join(root, "config", "scanner-policy.v1.json"),
      JSON.stringify({ queue: { batchSize: 5, maxParallel: 2 } }),
    );

    await expect(
      execFile(process.execPath, [workflowPolicyScript], { cwd: root }),
    ).rejects.toMatchObject({ stderr: expect.stringMatching(expected) });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

describe("least-privilege GitHub Actions orchestration", () => {
  test("provider compatibility checks are staff-authorized and non-mutating", async () => {
    const value = await workflow("provider-check.yml");
    const text = await readFile(
      new URL("../.github/workflows/provider-check.yml", import.meta.url),
      "utf8",
    );
    const secretSteps = Object.values(value.jobs).flatMap((job: any) =>
      (job.steps ?? []).filter((step: Workflow) =>
        JSON.stringify(step).match(
          /TAVERNKEEPER_API_(?:ENDPOINT|KEY)|TAVERNKEEPER_MODEL/u,
        ),
      ),
    );

    expect(value.on.workflow_dispatch).toBeNull();
    expect(value.permissions).toEqual({ contents: "read" });
    expect(value.concurrency).toEqual({
      group: "tavernkeeper-provider-check",
      "cancel-in-progress": false,
    });
    expect(value.jobs.authorize).toMatchObject({
      environment: "tavernkeeper-staff",
      permissions: {},
    });
    expect(value.jobs.check).toMatchObject({
      needs: "authorize",
      environment: "tavernkeeper-scanner",
      permissions: { contents: "read" },
    });
    expect(secretSteps).toHaveLength(1);
    expect(secretSteps[0]?.name).toBe("Check configured model provider");
    expect(text).not.toMatch(
      /operations\/state|reports\/|deploy-pages|git push|gh workflow run|TAVERNKEEPER_ARTIFACT_KEY|TAVERNKEEPER_PUBLISHER/iu,
    );
  });

  test("ordinary reconciliation plans five targets and calls one reusable path", async () => {
    const value = await workflow("reconcile.yml");

    expect(value.on.schedule).toEqual([{ cron: "13 */6 * * *" }]);
    expect(value.on.workflow_dispatch).toBeNull();
    expect(value.on.workflow_call).toBeNull();
    expect(value.jobs.run.uses).toBe(
      "./.github/workflows/scan-and-publish.yml",
    );
    expect(value.jobs.run.with.requests_json).toBe(
      "${{ needs.plan.outputs.requests_json }}",
    );
    expect(JSON.stringify(value.on)).not.toMatch(
      /issue_comment|issues|pull_request_target/iu,
    );
  });

  test("reconciliation restores a committed Pages index before planning scans", async () => {
    const value = await workflow("reconcile.yml");
    const plan = value.jobs.plan;
    const planStep = plan.steps.find(
      (step: Workflow) =>
        step.name === "Plan deployment recovery or bounded batch",
    );

    expect(plan.outputs).toMatchObject({
      requests_json: "${{ steps.plan.outputs.requests_json }}",
      remaining: "${{ steps.plan.outputs.remaining }}",
      deploy_required: "${{ steps.plan.outputs.deploy_required }}",
      source_sha: "${{ steps.plan.outputs.source_sha }}",
    });
    expect(String(planStep?.run)).toMatch(
      /reports\/index\.json[\s\S]*live-index\.json[\s\S]*deploy_required=true[\s\S]*requests_json=\[\]/u,
    );
    expect(value.jobs["recover-pages"]).toMatchObject({
      needs: "plan",
      if: "${{ needs.plan.outputs.deploy_required == 'true' }}",
      uses: "./.github/workflows/deploy-pages.yml",
      with: { source_sha: "${{ needs.plan.outputs.source_sha }}" },
      secrets: "inherit",
    });
    expect(value.jobs.run.if).toContain(
      "needs.plan.outputs.deploy_required == 'false'",
    );
    expect(String(value.jobs["resume-after-recovery"].steps[0].run)).toContain(
      'gh workflow run reconcile.yml --repo "$GITHUB_REPOSITORY" --ref main',
    );
  });

  test("every reconciliation dispatch names its repository explicitly", async () => {
    const names = [
      "reconcile.yml",
      "policy-rescan.yml",
      "scan-and-publish.yml",
      "staff-operations.yml",
    ];
    const texts = await Promise.all(
      names.map((name) =>
        readFile(
          new URL(`../.github/workflows/${name}`, import.meta.url),
          "utf8",
        ),
      ),
    );
    const dispatches = texts.flatMap((text) =>
      [
        ...text.matchAll(/^\s*run:\s*(gh workflow run reconcile\.yml.*)$/gmu),
      ].map((match) => match[1]!),
    );

    expect(dispatches).toHaveLength(4);
    expect(dispatches).toEqual(
      Array(4).fill(
        'gh workflow run reconcile.yml --repo "$GITHUB_REPOSITORY" --ref main',
      ),
    );
  });

  test("automatic retry is hourly and reuses ordinary reconciliation", async () => {
    const value = await workflow("retry.yml");

    expect(value.on.schedule).toEqual([{ cron: "17 * * * *" }]);
    expect(value.on.workflow_dispatch).toBeUndefined();
    expect(value.jobs.reconcile.uses).toBe("./.github/workflows/reconcile.yml");
  });

  test("all scan entry points converge on the reusable automatic publisher", async () => {
    const [deep, targeted] = await Promise.all([
      workflow("deep-scan.yml"),
      workflow("targeted-scan.yml"),
    ]);

    expect(deep.jobs.scan.uses).toBe(
      "./.github/workflows/scan-and-publish.yml",
    );
    expect(targeted.jobs.scan.uses).toBe(
      "./.github/workflows/scan-and-publish.yml",
    );
    for (const value of [deep, targeted])
      expect(JSON.stringify(value.jobs)).not.toMatch(
        /approve|adjudicat|manual review/iu,
      );
  });

  test("targeted scans accept only a repository ID from the Tavernary wake App", async () => {
    const value = await workflow("targeted-scan.yml");
    const inputs = value.on.workflow_dispatch.inputs;
    const text = JSON.stringify(value);

    expect(Object.keys(inputs)).toEqual(["repository_id"]);
    expect(inputs.repository_id).toMatchObject({
      type: "number",
      required: true,
    });
    expect(value.jobs.resolve.if).toContain("github.actor_id");
    expect(value.jobs.resolve.if).toContain("vars.TAVERNARY_WAKE_APP_BOT_ID");
    expect(value.jobs.resolve.permissions).toEqual({
      contents: "read",
      actions: "read",
    });
    expect(text).toMatch(
      /actions\/runs\/\$\{GITHUB_RUN_ID\}[\s\S]*TAVERNKEEPER_REQUEST_CREATED_AT/u,
    );
    expect(text).toMatch(/tavernkeeper-targets\.json/u);
    expect(text).toMatch(/targeted-scan/u);
    expect(text).not.toMatch(
      /clone_url|repository_url|branch|token_budget|priority|mode.*inputs/iu,
    );
  });

  test("the reusable path bounds concurrency and isolates model credentials", async () => {
    const value = await workflow("scan-and-publish.yml");
    const secretSteps = value.jobs.scan.steps.filter((step: Workflow) =>
      JSON.stringify(step).match(
        /TAVERNKEEPER_API_(?:ENDPOINT|KEY)|TAVERNKEEPER_MODEL/u,
      ),
    );

    expect(Object.keys(value.on)).toEqual(["workflow_call"]);
    expect(value.jobs.scan.strategy["max-parallel"]).toBe(2);
    expect(value.jobs.scan.strategy["fail-fast"]).toBe(true);
    expect(value.jobs.scan.permissions.contents).toBe("read");
    expect(secretSteps).toHaveLength(1);
    expect(secretSteps[0].name).toBe("Review with configured model");
    expect(JSON.stringify(value.jobs.scan.steps)).toMatch(
      /Stop pending repositories after a system failure/u,
    );
  });

  test("uploads only authenticated ciphertext and exposes the key only to transport steps", async () => {
    const value = await workflow("scan-and-publish.yml");
    const steps = value.jobs.scan.steps as Workflow[];
    const upload = steps.find((step) =>
      String(step.uses).startsWith("actions/upload-artifact@"),
    );
    const transportKeySteps = [
      ...steps,
      ...(value.jobs.publish.steps as Workflow[]),
    ].filter((step) =>
      JSON.stringify(step).includes("TAVERNKEEPER_ARTIFACT_KEY"),
    );

    expect(upload?.with?.path).toBe("outcome.enc");
    expect(JSON.stringify(upload)).not.toMatch(
      /candidate\.json|transition\.json/u,
    );
    expect(transportKeySteps.map((step) => step.name)).toEqual([
      "Initialize encrypted bootstrap failure",
      "Encrypt sanitized outcome",
      "Decrypt sanitized outcomes",
    ]);
    expect(JSON.stringify(transportKeySteps)).not.toMatch(/GITHUB_OUTPUT/iu);
  });

  test("creates an encrypted retry transition before fallible scan setup", async () => {
    const value = await workflow("scan-and-publish.yml");
    const steps = value.jobs.scan.steps as Workflow[];
    const bootstrap = steps[0];
    const checkoutIndex = steps.findIndex((step) =>
      String(step.uses).startsWith("actions/checkout@"),
    );
    const encrypt = steps.find(
      (step) => step.name === "Encrypt sanitized outcome",
    );
    const upload = steps.find((step) =>
      String(step.uses).startsWith("actions/upload-artifact@"),
    );

    expect(bootstrap).toMatchObject({
      name: "Initialize encrypted bootstrap failure",
      env: {
        TAVERNKEEPER_ARTIFACT_KEY: "${{ secrets.TAVERNKEEPER_ARTIFACT_KEY }}",
        TAVERNKEEPER_SCAN_REQUEST: "${{ toJSON(matrix.request) }}",
      },
    });
    expect(checkoutIndex).toBeGreaterThan(0);
    expect(String(bootstrap?.run)).toMatch(
      /SCAN_BOOTSTRAP_FAILED|outcome\.enc|aes-256-gcm/u,
    );
    expect(encrypt?.if).toBe("always()");
    expect(String(encrypt?.run)).toMatch(
      /outcome-actual\.enc[\s\S]*mv outcome-actual\.enc outcome\.enc/u,
    );
    expect(upload?.if).toBe("always()");
  });

  test("the Publisher App token has one reviewed consumer", async () => {
    const value = await workflow("scan-and-publish.yml");
    const source = await readFile(
      new URL("../.github/workflows/scan-and-publish.yml", import.meta.url),
      "utf8",
    );
    const steps = value.jobs.publish.steps as Workflow[];
    const tokenSteps = steps.filter((step) =>
      JSON.stringify(step).match(
        /TAVERNKEEPER_PUBLISHER_APP_(?:ID|PRIVATE_KEY)/u,
      ),
    );
    const consumers = steps.filter((step) =>
      JSON.stringify(step).includes("steps.publisher-token.outputs.token"),
    );

    expect(value.jobs.publish.permissions.contents).toBe("read");
    expect(tokenSteps).toHaveLength(1);
    expect(tokenSteps[0]).toMatchObject({
      name: "Create TavernKeeper Publisher token",
      id: "publisher-token",
      uses: publisherAction,
      with: {
        "app-id": "${{ secrets.TAVERNKEEPER_PUBLISHER_APP_ID }}",
        "private-key": "${{ secrets.TAVERNKEEPER_PUBLISHER_APP_PRIVATE_KEY }}",
        owner: "MentallyQuill",
        repositories: "TavernKeeper",
        "permission-contents": "write",
      },
    });
    expect(consumers).toHaveLength(1);
    expect(consumers[0]!.run).toContain("git push origin HEAD:main");
    expect(consumers[0]!.run).not.toMatch(/--force|gh workflow run/iu);
    expect(source).not.toMatch(/X-GitHub-Stateless-S2S-Token|\bghs_/iu);
  });

  test("workflow policy rejects model secrets outside the review step", async () => {
    await expectPolicyFailure(
      (text) =>
        text.replace(
          "  scan:\n",
          "  scan:\n    env:\n      TAVERNKEEPER_MODEL: ${{ secrets.TAVERNKEEPER_MODEL }}\n",
        ),
      /model secret appears outside a reviewed provider step/u,
    );
  });

  test("workflow policy rejects plaintext scan artifact uploads", async () => {
    await expectPolicyFailure(
      (text) => text.replace("path: outcome.enc", "path: candidate.json"),
      /scan artifact upload must contain only outcome\.enc/u,
    );
  });

  test("workflow policy rejects Publisher token reuse", async () => {
    await expectPolicyFailure(
      (text) =>
        text.replace(
          "      - name: Commit reports and state\n",
          "      - name: Extra token consumer\n        env:\n          GH_TOKEN: ${{ steps.publisher-token.outputs.token }}\n        run: gh api user\n      - name: Commit reports and state\n",
        ),
      /Publisher App token is consumed outside the reviewed commit step/u,
    );
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

  test("Pages verifies the exact public index before waking Tavernary", async () => {
    const text = await readFile(
      new URL("../.github/workflows/deploy-pages.yml", import.meta.url),
      "utf8",
    );

    expect(text).toMatch(/merge-base --is-ancestor/iu);
    expect(text).toMatch(/reports\/index\.json/iu);
    expect(text).toMatch(/actions\/workflows\/.+\/dispatches/iu);
    expect(text).not.toMatch(/token_budget|priority|mode:/iu);
  });

  test("the reviewed workflow policy passes", async () => {
    await expect(
      execFile(process.execPath, [workflowPolicyScript], {
        cwd: repositoryRoot,
      }),
    ).resolves.toMatchObject({
      stdout: expect.stringMatching(/Workflow policy passed/u),
    });
  });
});
