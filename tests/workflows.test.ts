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
  "actions/create-github-app-token@f8d387b68d61c58ab83c6c016672934102569859";
const uploadArtifactAction =
  "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a";
const downloadArtifactAction =
  "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c";
const workflowNames = [
  "ci.yml",
  "deploy-pages.yml",
  "policy-rescan.yml",
  "provider-check.yml",
  "reconcile.yml",
  "retry.yml",
  "scan-and-publish.yml",
  "staff-operations.yml",
  "targeted-scan.yml",
];

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
    await Promise.all(
      workflowNames.map(async (name) =>
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
      join(root, "config", "scanner-policy.v3.json"),
      await readFile(
        new URL("../config/scanner-policy.v3.json", import.meta.url),
        "utf8",
      ),
    );
    await expect(
      execFile(process.execPath, [workflowPolicyScript], { cwd: root }),
    ).rejects.toMatchObject({ stderr: expect.stringMatching(expected) });
  } finally {
    await rm(root, { recursive: true, force: true });
  }
}

describe("GitHub workflow security policy", () => {
  test("the active workflow set is explicit", async () => {
    const names = (
      await readdir(new URL("../.github/workflows/", import.meta.url))
    )
      .filter((name) => /\.ya?ml$/u.test(name))
      .sort();
    expect(names).toEqual(workflowNames);
  });

  test("manual mutation workflows retain protected staff environments", async () => {
    const [policy, staff, deploy] = await Promise.all([
      workflow("policy-rescan.yml"),
      workflow("staff-operations.yml"),
      workflow("deploy-pages.yml"),
    ]);
    expect(policy.jobs.schedule.environment).toBe("tavernkeeper-staff");
    expect(staff.jobs.operate.environment).toBe("tavernkeeper-staff");
    expect(deploy.jobs["authorize-manual"].environment).toBe(
      "tavernkeeper-staff",
    );
  });

  test("automatic reusable deployments bypass only the manual approval gate", async () => {
    const [deploy, reconcile, scanAndPublish] = await Promise.all([
      workflow("deploy-pages.yml"),
      workflow("reconcile.yml"),
      workflow("scan-and-publish.yml"),
    ]);

    expect(deploy.on.workflow_call.inputs.automatic).toEqual({
      type: "boolean",
      required: true,
    });
    expect(deploy.on.workflow_dispatch.inputs).not.toHaveProperty("automatic");
    expect(deploy.jobs["authorize-manual"].if).toBe("${{ !inputs.automatic }}");
    expect(reconcile.jobs["recover-pages"].with.automatic).toBe(true);
    expect(scanAndPublish.jobs.deploy.with.automatic).toBe(true);
  });

  test("reconciliation is bounded and all ordinary entry points converge", async () => {
    const [reconcile, targeted, retry, policy] = await Promise.all([
      workflow("reconcile.yml"),
      workflow("targeted-scan.yml"),
      workflow("retry.yml"),
      workflow("policy-rescan.yml"),
    ]);
    expect(reconcile.jobs.run.uses).toBe(
      "./.github/workflows/scan-and-publish.yml",
    );
    expect(targeted.jobs.scan.uses).toBe(
      "./.github/workflows/scan-and-publish.yml",
    );
    expect(retry.on.schedule).toEqual([{ cron: "17 * * * *" }]);
    expect(retry.jobs.reconcile.uses).toBe("./.github/workflows/reconcile.yml");
    expect(JSON.stringify(policy.jobs)).toContain("policy-rescan");
    expect(JSON.stringify(policy.jobs)).toContain("reconcile.yml");
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
    expect(value["run-name"]).toBe(
      "Tavernary targeted scan #${{ inputs.repository_id }}",
    );
    expect(value.jobs.resolve.if).toContain("github.actor_id");
    expect(value.jobs.resolve.if).toContain("vars.TAVERNARY_WAKE_APP_BOT_ID");
    expect(text).toMatch(/tavernkeeper-targets\.json/u);
    expect(text).not.toMatch(
      /clone_url|repository_url|branch|token_budget|priority|mode.*inputs/iu,
    );
  });

  test("the scan job isolates provider secrets to contextual review", async () => {
    const value = await workflow("scan-and-publish.yml");
    const steps = value.jobs.scan.steps as Workflow[];
    const prepareIndex = steps.findIndex(
      (step) => step.name === "Prepare exact target and scanner evidence",
    );
    const finalizeIndex = steps.findIndex(
      (step) => step.name === "Finalize contextual V5 report",
    );
    const reviewIndex = steps.findIndex(
      (step) => step.name === "Contextually assess scanner evidence",
    );
    const source = await readFile(
      new URL("../.github/workflows/scan-and-publish.yml", import.meta.url),
      "utf8",
    );
    const packageSource = await readFile(
      new URL("../package.json", import.meta.url),
      "utf8",
    );

    expect(value.jobs.scan.strategy["max-parallel"]).toBe(2);
    expect(value.jobs.scan.strategy["fail-fast"]).toBe(true);
    expect(reviewIndex).toBe(prepareIndex + 1);
    expect(finalizeIndex).toBe(reviewIndex + 1);
    expect(steps[prepareIndex]?.run).toBe("npm run --silent prepare-target");
    expect(steps[finalizeIndex]?.run).toBe(
      "npm run --silent finalize-target -- candidate.json",
    );
    expect(steps[reviewIndex]?.run).toBe("npm run --silent review-target");
    expect(steps[reviewIndex]?.env).toMatchObject({
      TAVERNKEEPER_API_ENDPOINT: "${{ secrets.TAVERNKEEPER_API_ENDPOINT }}",
      TAVERNKEEPER_API_KEY: "${{ secrets.TAVERNKEEPER_API_KEY }}",
      TAVERNKEEPER_MODEL: "${{ secrets.TAVERNKEEPER_MODEL }}",
    });
    expect(`${source}\n${packageSource}`).not.toMatch(
      /deep-scan|tavernkeeper-model-cache/iu,
    );
    const providerSecretSteps = steps.filter((step) =>
      /TAVERNKEEPER_API_(?:ENDPOINT|KEY)|TAVERNKEEPER_MODEL/u.test(
        JSON.stringify(step),
      ),
    );
    expect(providerSecretSteps.map((step) => step.name)).toEqual([
      "Contextually assess scanner evidence",
    ]);
  });

  test("the protected provider check makes one non-publishing contextual request", async () => {
    const value = await workflow("provider-check.yml");
    expect(value.jobs.authorize.environment).toBe("tavernkeeper-staff");
    expect(value.jobs.check.environment).toBe("tavernkeeper-scanner");
    const steps = value.jobs.check.steps as Workflow[];
    const check = steps.find(
      (step) => step.name === "Check one benign contextual review",
    );
    expect(check?.run).toBe("npm run --silent provider:check");
    expect(check?.env).toEqual({
      TAVERNKEEPER_API_ENDPOINT: "${{ secrets.TAVERNKEEPER_API_ENDPOINT }}",
      TAVERNKEEPER_API_KEY: "${{ secrets.TAVERNKEEPER_API_KEY }}",
      TAVERNKEEPER_MODEL: "${{ secrets.TAVERNKEEPER_MODEL }}",
    });
    expect(JSON.stringify(value)).not.toMatch(
      /publish|candidate\.json|git push/iu,
    );
  });

  test("uploads only authenticated ciphertext and exposes the key only to transport steps", async () => {
    const value = await workflow("scan-and-publish.yml");
    const scanSteps = value.jobs.scan.steps as Workflow[];
    const allSteps = [
      ...scanSteps,
      ...(value.jobs.publish.steps as Workflow[]),
    ];
    const bootstrap = scanSteps[0];
    const encrypt = scanSteps.find(
      (step) => step.name === "Encrypt sanitized outcome",
    );
    const upload = scanSteps.find((step) =>
      String(step.uses).startsWith("actions/upload-artifact@"),
    );
    const download = (value.jobs.publish.steps as Workflow[]).find((step) =>
      String(step.uses).startsWith("actions/download-artifact@"),
    );
    const transportKeySteps = allSteps.filter((step) =>
      JSON.stringify(step).includes("TAVERNKEEPER_ARTIFACT_KEY"),
    );

    expect(bootstrap?.name).toBe("Initialize encrypted bootstrap failure");
    expect(String(bootstrap?.run)).toMatch(
      /SCAN_BOOTSTRAP_FAILED|outcome\.enc|aes-256-gcm/u,
    );
    expect(encrypt?.if).toBe("always()");
    expect(upload).toMatchObject({
      uses: uploadArtifactAction,
      if: "always()",
      with: { path: "outcome.enc", "retention-days": 1 },
    });
    expect(download?.uses).toBe(downloadArtifactAction);
    expect(JSON.stringify(upload)).not.toMatch(
      /candidate\.json|transition\.json/u,
    );
    expect(transportKeySteps.map((step) => step.name)).toEqual([
      "Initialize encrypted bootstrap failure",
      "Encrypt sanitized outcome",
      "Decrypt sanitized outcomes",
    ]);
  });

  test("the Publisher App token has one reviewed bounded push consumer", async () => {
    const value = await workflow("scan-and-publish.yml");
    const steps = value.jobs.publish.steps as Workflow[];
    const tokenSteps = steps.filter((step) =>
      JSON.stringify(step).match(
        /TAVERNKEEPER_PUBLISHER_APP_(?:ID|PRIVATE_KEY)/u,
      ),
    );
    const consumers = steps.filter((step) =>
      JSON.stringify(step).includes("steps.publisher-token.outputs.token"),
    );

    expect(tokenSteps).toHaveLength(1);
    expect(tokenSteps[0]).toMatchObject({
      name: "Create TavernKeeper Publisher token",
      id: "publisher-token",
      uses: publisherAction,
      with: {
        owner: "MentallyQuill",
        repositories: "TavernKeeper",
        "permission-contents": "write",
      },
    });
    expect(consumers).toHaveLength(1);
    expect(consumers[0]!.run).toContain("git push origin HEAD:main");
    expect(consumers[0]!.run).toContain("for attempt in 1 2 3; do");
    expect(consumers[0]!.run).toContain('sleep "$((attempt * 15))"');
    expect(consumers[0]!.run).toContain('test "$push_succeeded" = "true"');
    expect(consumers[0]!.run).not.toMatch(/--force|gh workflow run/iu);
  });

  test("workflow policy rejects removal of the contextual review boundary", async () => {
    await expectPolicyFailure(
      (text) =>
        text.replace(
          /      - name: Contextually assess scanner evidence[\s\S]*?run: npm run --silent review-target\n/u,
          "",
        ),
      /contextual review must separate preparation from V5 finalization/u,
    );
  });

  test("workflow policy rejects dynamic and unapproved secrets", async () => {
    await expectPolicyFailure(
      (text) =>
        text.replace(
          "  scan:\n",
          "  scan:\n    env:\n      EXTRA: ${{ secrets[env.SECRET_NAME] }}\n",
        ),
      /dynamic secrets context access is not allowed/u,
    );
    await expectPolicyFailure(
      (text) =>
        text.replace(
          "  scan:\n",
          "  scan:\n    env:\n      EXTRA: ${{ secrets.UNREVIEWED_SECRET }}\n",
        ),
      /unapproved workflow secret UNREVIEWED_SECRET/u,
    );
  });

  test("workflow policy rejects plaintext scan artifact uploads", async () => {
    await expectPolicyFailure(
      (text) => text.replace("path: outcome.enc", "path: candidate.json"),
      /scan artifact upload must always retain only outcome\.enc for one day/u,
    );
  });

  test("workflow policy rejects artifact action pin drift", async () => {
    await expectPolicyFailure(
      (text) =>
        text.replace(
          uploadArtifactAction,
          `actions/upload-artifact@${"0".repeat(40)}`,
        ),
      /scan artifact upload must always retain only outcome\.enc for one day/u,
    );
    await expectPolicyFailure(
      (text) =>
        text.replace(
          downloadArtifactAction,
          `actions/download-artifact@${"0".repeat(40)}`,
        ),
      /artifact actions must retain the reviewed Node 24 pins/u,
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

  test("workflow policy rejects removal of bounded Publisher push retries", async () => {
    await expectPolicyFailure(
      (text) =>
        text.replace("for attempt in 1 2 3; do", "for attempt in 1; do"),
      /Publisher-authenticated push must retain one canonical bounded retry block/u,
    );
  });

  test("workflow policy rejects an extra Publisher-authenticated push", async () => {
    await expectPolicyFailure(
      (text) =>
        text.replace(
          '            test "$push_succeeded" = "true"\n',
          '            test "$push_succeeded" = "true"\n            git push origin HEAD:main\n',
        ),
      /Publisher-authenticated push must retain one canonical bounded retry block/u,
    );
  });

  test("all external Actions are pinned to full commit SHAs", async () => {
    const texts = await Promise.all(
      workflowNames.map((name) =>
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
      stdout: expect.stringMatching(/Workflow policy passed for 9 workflows/u),
    });
  });
});
