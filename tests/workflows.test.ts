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
const reviewProgressCountScript = fileURLToPath(
  new URL("../scripts/contextual-review-progress-count.mjs", import.meta.url),
);
const publisherAction =
  "actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1";
const checkoutAction =
  "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1";
const publisherClientId = "${{ vars.TAVERNKEEPER_PUBLISHER_CLIENT_ID }}";
const publisherPrivateKey =
  "${{ secrets.TAVERNKEEPER_PUBLISHER_APP_PRIVATE_KEY }}";
const publisherMutationJobs = [
  ["coverage-campaign.yml", "create", "tavernkeeper-staff"],
  ["policy-rescan.yml", "schedule", "tavernkeeper-staff"],
  ["publisher-verification.yml", "verify-scanner", "tavernkeeper-scanner"],
  ["publisher-verification.yml", "verify-staff", "tavernkeeper-staff"],
  ["reconcile.yml", "claim", "tavernkeeper-scanner"],
  ["reconcile.yml", "probe-provider", "tavernkeeper-scanner"],
  ["release-holds.yml", "release", "tavernkeeper-staff"],
  ["scan-and-publish.yml", "publish", "tavernkeeper-scanner"],
  ["staff-operations.yml", "operate", "tavernkeeper-staff"],
  ["targeted-scan.yml", "enqueue", "tavernkeeper-scanner"],
] as const;
const uploadArtifactAction =
  "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a";
const downloadArtifactAction =
  "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c";
const workflowNames = [
  "ci.yml",
  "coverage-campaign.yml",
  "delayed-wake.yml",
  "deploy-pages.yml",
  "pages-reconcile.yml",
  "policy-rescan.yml",
  "prepare-diagnostic.yml",
  "provider-check.yml",
  "publisher-verification.yml",
  "reconcile.yml",
  "release-holds.yml",
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
  mutatedWorkflow = "scan-and-publish.yml",
) {
  const root = await mkdtemp(join(tmpdir(), "tavernkeeper-workflow-policy-"));
  try {
    await mkdir(join(root, ".github", "workflows"), { recursive: true });
    await mkdir(join(root, "config"), { recursive: true });
    await Promise.all(
      workflowNames.map(async (name) =>
        writeFile(
          join(root, ".github", "workflows", name),
          name === mutatedWorkflow
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
      join(root, "config", "scanner-policy.v5.json"),
      await readFile(
        new URL("../config/scanner-policy.v5.json", import.meta.url),
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
  test("prepares without secrets and reviews only the bounded handoff", async () => {
    const value = await workflow("scan-and-publish.yml");
    const prepare = value.jobs.prepare;
    const review = value.jobs.scan;

    expect(prepare.strategy).toBeUndefined();
    expect(prepare["timeout-minutes"]).toBe(30);
    expect(review.needs).toBe("prepare");
    expect(review.strategy).toBeUndefined();
    expect(review["timeout-minutes"]).toBe(90);
    expect(JSON.stringify(prepare)).not.toMatch(
      /TAVERNKEEPER_API_(?:ENDPOINT|KEY)|TAVERNKEEPER_MODEL|JSONREPAIR_|TAVERNKEEPER_ARTIFACT_KEY|TAVERNKEEPER_PUBLISHER/iu,
    );
    expect(JSON.stringify(review)).toContain("TAVERNKEEPER_API_KEY");
    expect(JSON.stringify(review)).toContain("JSONREPAIR_API_KEY");
    expect(JSON.stringify(review)).not.toContain("TAVERNKEEPER_CHECKOUT_ROOT");

    const prepareUpload = (prepare.steps as Workflow[]).find(
      (step) => step.name === "Upload bounded prepared evidence",
    );
    const reviewDownload = (review.steps as Workflow[]).find(
      (step) => step.name === "Download bounded prepared evidence",
    );
    expect(prepareUpload).toMatchObject({
      uses: uploadArtifactAction,
      if: "always()",
      with: {
        name: "prepared-${{ fromJSON(inputs.request_json).repository_id }}",
        "retention-days": 1,
      },
    });
    expect(reviewDownload).toMatchObject({
      uses: downloadArtifactAction,
      with: {
        name: "prepared-${{ fromJSON(inputs.request_json).repository_id }}",
      },
    });
  });

  test("runs an owner-only model-free preparation diagnostic", async () => {
    const value = await workflow("prepare-diagnostic.yml");
    const job = value.jobs.prepare;
    const steps = job.steps as Workflow[];
    const prepare = steps.find(
      (step) => step.name === "Prepare exact target and scanner evidence",
    );
    const cleanup = steps.find(
      (step) => step.name === "Remove repository preparation data",
    );
    const upload = steps.find(
      (step) => step.name === "Upload sanitized preparation diagnostic",
    );

    expect(value.on.workflow_dispatch.inputs.request_json).toMatchObject({
      type: "string",
      required: true,
    });
    expect(value.permissions).toEqual({ contents: "read" });
    expect(job.environment).toBeUndefined();
    expect(job.if).toContain("github.actor_id == '2625904'");
    expect(job.if).toContain("github.ref == 'refs/heads/main'");
    expect(job["timeout-minutes"]).toBe(30);
    expect(prepare).toMatchObject({
      "continue-on-error": true,
      run: "npm run --silent prepare-target",
      env: {
        TAVERNKEEPER_SCAN_REQUEST: "${{ inputs.request_json }}",
        TAVERNKEEPER_CHECKOUT_ROOT:
          "${{ runner.temp }}/tavernkeeper-checkout-${{ fromJSON(inputs.request_json).repository_id }}",
        TAVERNKEEPER_SESSION_ROOT:
          "${{ runner.temp }}/tavernkeeper-session-${{ fromJSON(inputs.request_json).repository_id }}",
        TAVERNKEEPER_ERROR_OUTPUT: "phase-error.json",
      },
    });
    expect(cleanup?.if).toBe("always()");
    expect(cleanup?.id).toBe("cleanup");
    expect(cleanup?.run).toContain("tavernkeeper-checkout-");
    expect(cleanup?.run).toContain("tavernkeeper-session-");
    expect(cleanup?.run).toContain("phase-error.json");
    expect(upload).toMatchObject({
      if: "${{ always() && steps.cleanup.outcome == 'success' }}",
      uses: uploadArtifactAction,
      with: {
        name: "preparation-diagnostic-${{ fromJSON(inputs.request_json).repository_id }}",
        path: "${{ runner.temp }}/tavernkeeper-preparation-diagnostic/result.json",
        "if-no-files-found": "error",
        "retention-days": 1,
      },
    });
    expect(JSON.stringify(value)).not.toMatch(
      /TAVERNKEEPER_API_|TAVERNKEEPER_MODEL|JSONREPAIR_|TAVERNKEEPER_ARTIFACT_KEY|TAVERNKEEPER_PUBLISHER|review-target|finalize-target|candidate\.json|git push|reconcile\.yml/iu,
    );
  });

  test("the review progress counter never prints malformed checkpoint content", async () => {
    const root = await mkdtemp(join(tmpdir(), "tavernkeeper-review-progress-"));
    const checkpoint = join(root, "review-progress.json");
    const canary = "PRIVATE_CHECKPOINT_NARRATIVE_CANARY";
    try {
      await writeFile(checkpoint, `{\"progress\":${canary}}\n`);
      const result = await execFile(process.execPath, [
        reviewProgressCountScript,
        checkpoint,
      ]).catch((error: unknown) => error as { stdout: string; stderr: string });
      expect(result).toMatchObject({ stdout: "", stderr: "" });
      expect(`${result.stdout}${result.stderr}`).not.toContain(canary);
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

  test("the review progress counter emits only a validated group count", async () => {
    const root = await mkdtemp(join(tmpdir(), "tavernkeeper-review-progress-"));
    const checkpoint = join(root, "review-progress.json");
    try {
      await expect(
        execFile(process.execPath, [reviewProgressCountScript, checkpoint]),
      ).resolves.toMatchObject({ stdout: "0", stderr: "" });
      await writeFile(
        checkpoint,
        JSON.stringify({
          progress: {
            completed_group_ids: ["a".repeat(64), "b".repeat(64)],
          },
        }),
      );
      await expect(
        execFile(process.execPath, [reviewProgressCountScript, checkpoint]),
      ).resolves.toMatchObject({ stdout: "2", stderr: "" });
    } finally {
      await rm(root, { recursive: true, force: true });
    }
  });

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
    expect(staff.concurrency).toEqual({
      group: "tavernkeeper-staff-operations",
      queue: "max",
      "cancel-in-progress": false,
    });
    const commit = (staff.jobs.operate.steps as Workflow[]).find(
      (step) => step.name === "Apply and commit validated staff operation",
    );
    expect(commit?.run).toContain("git fetch origin main");
    expect(commit?.run).toContain("git reset --hard origin/main");
    expect(commit?.run).toContain("run_operation");
    expect(commit?.run).toContain(
      "env -u GH_TOKEN -u GITHUB_TOKEN TAVERNKEEPER_OPERATION",
    );
    expect(commit?.run).not.toContain("if git diff --cached --quiet; then");
    expect(deploy.jobs["authorize-manual"].environment).toBe(
      "tavernkeeper-staff",
    );
  });

  test("protected policy rescans expose only the validated campaign scope", async () => {
    const value = await workflow("policy-rescan.yml");
    const inputs = value.on.workflow_dispatch.inputs;
    const campaign = (value.jobs.schedule.steps as Workflow[]).find(
      (step) => step.name === "Create reviewed policy campaign",
    );
    const otherSteps = (value.jobs.schedule.steps as Workflow[]).filter(
      (step) => step !== campaign,
    );

    expect(value.jobs.schedule.environment).toBe("tavernkeeper-staff");
    expect(Object.keys(inputs)).toEqual(["scope"]);
    expect(inputs.scope).toMatchObject({
      type: "choice",
      required: true,
      default: "all",
      options: ["all", "yellow"],
    });
    expect(campaign?.env).toEqual({
      TAVERNKEEPER_POLICY_RESCAN_SCOPE: "${{ inputs.scope }}",
    });
    expect(JSON.stringify(otherSteps)).not.toContain(
      "TAVERNKEEPER_POLICY_RESCAN_SCOPE",
    );
  });

  test("automatic reusable deployments bypass only the manual approval gate", async () => {
    const [deploy, pagesReconcile, scanAndPublish] = await Promise.all([
      workflow("deploy-pages.yml"),
      workflow("pages-reconcile.yml"),
      workflow("scan-and-publish.yml"),
    ]);

    expect(deploy.on.workflow_call.inputs.automatic).toEqual({
      type: "boolean",
      required: true,
    });
    expect(deploy.on.workflow_dispatch.inputs).not.toHaveProperty("automatic");
    expect(deploy.jobs["authorize-manual"].if).toBe("${{ !inputs.automatic }}");
    expect(pagesReconcile.on.schedule).toEqual([{ cron: "*/15 * * * *" }]);
    expect(pagesReconcile.jobs.deploy.with.automatic).toBe(true);
    expect(scanAndPublish.jobs.deploy.with.automatic).toBe(true);
  });

  test("reconciliation is bounded and all ordinary entry points converge", async () => {
    const [reconcile, delayedWake, targeted, retry, policy] = await Promise.all(
      [
        workflow("reconcile.yml"),
        workflow("delayed-wake.yml"),
        workflow("targeted-scan.yml"),
        workflow("retry.yml"),
        workflow("policy-rescan.yml"),
      ],
    );
    expect(reconcile.jobs.run.uses).toBe(
      "./.github/workflows/scan-and-publish.yml",
    );
    expect(reconcile.jobs.claim.permissions).toEqual({
      contents: "read",
      actions: "write",
    });
    expect(reconcile.jobs.run.strategy["max-parallel"]).toBe(2);
    const scheduleWake = reconcile.jobs.claim.steps.find(
      (step: Workflow) => step.name === "Schedule deterministic delayed wake",
    );
    expect(scheduleWake?.if).toContain(
      "fromJSON(steps.claim.outputs.requests_json)[0] == null",
    );
    expect(scheduleWake?.if).toContain(
      "steps.claim.outputs.total_remaining != '0'",
    );
    expect(scheduleWake?.if).toContain(
      "steps.claim.outputs.next_wake_at != ''",
    );
    expect(scheduleWake?.run).toBe(
      'gh workflow run delayed-wake.yml --repo "$GITHUB_REPOSITORY" --ref main -f wake_at="$TAVERNKEEPER_WAKE_AT"',
    );
    expect(delayedWake.on.workflow_dispatch.inputs.wake_at).toMatchObject({
      type: "string",
      required: true,
    });
    expect(delayedWake.concurrency).toEqual({
      group: "tavernkeeper-delayed-wake",
      "cancel-in-progress": true,
    });
    expect(delayedWake.jobs.wake["timeout-minutes"]).toBe(345);
    const wait = delayedWake.jobs.wake.steps.find(
      (step: Workflow) => step.name === "Wait for bounded wake time",
    );
    expect(wait?.run).toContain("new Date(wakeMs).toISOString() !== wakeAt");
    expect(wait?.run).toContain("Math.min(20_400");
    expect(JSON.stringify(delayedWake.jobs.wake)).toContain(
      'gh workflow run reconcile.yml --repo \\"$GITHUB_REPOSITORY\\" --ref main',
    );
    expect(targeted.jobs.enqueue.environment).toBe("tavernkeeper-scanner");
    expect(JSON.stringify(targeted.jobs.enqueue)).toContain("targeted-scan");
    expect(JSON.stringify(targeted.jobs.enqueue)).toContain(
      "gh workflow run reconcile.yml",
    );
    expect(JSON.stringify(targeted.jobs.enqueue)).toContain(
      "git add operations/state.json",
    );
    expect(retry.on.schedule).toEqual([{ cron: "*/5 * * * *" }]);
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
    expect(value.jobs.enqueue.if).toContain("github.actor_id");
    expect(value.jobs.enqueue.if).toContain("vars.TAVERNARY_WAKE_APP_BOT_ID");
    expect(text).toMatch(/tavernkeeper-targets\.json/u);
    expect(text).not.toContain("scan-and-publish.yml");
    expect(text).not.toMatch(
      /clone_url|repository_url|branch|token_budget|priority|mode.*inputs/iu,
    );
  });

  test("the scan job isolates provider secrets to contextual review", async () => {
    const value = await workflow("scan-and-publish.yml");
    const steps = value.jobs.scan.steps as Workflow[];
    const prepareSteps = value.jobs.prepare.steps as Workflow[];
    const prepareIndex = prepareSteps.findIndex(
      (step) => step.name === "Prepare exact target and scanner evidence",
    );
    const pack = prepareSteps.find(
      (step) => step.name === "Package bounded prepared evidence",
    );
    const packageFailure = prepareSteps.find(
      (step) => step.name === "Package sanitized preparation failure",
    );
    const markPreparationFailure = prepareSteps.find(
      (step) =>
        step.name === "Mark failed preparation after preserving the handoff",
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
    const reviewConfig = JSON.parse(
      await readFile(
        new URL("../config/contextual-review.v5.json", import.meta.url),
        "utf8",
      ),
    ) as { timeoutMs: number };

    expect(value.jobs.scan.strategy).toBeUndefined();
    expect(value.jobs.scan["timeout-minutes"]).toBe(90);
    expect(prepareIndex).toBeGreaterThan(-1);
    expect(finalizeIndex).toBe(reviewIndex + 1);
    expect(prepareSteps[prepareIndex]?.run).toBe(
      "npm run --silent prepare-target",
    );
    expect(steps[finalizeIndex]?.run).toBe(
      "npm run --silent finalize-target -- candidate.json",
    );
    expect(steps[reviewIndex]?.run).toContain("npm run --silent review-target");
    expect(steps[reviewIndex]?.run).toContain('code == "MODEL_PROVIDER"');
    expect(steps[reviewIndex]?.run).toContain('code == "MODEL_QUOTA"');
    expect(steps[reviewIndex]?.run).toContain(
      'code == "MODEL_REVIEW_BUDGET_EXCEEDED"',
    );
    expect(steps[reviewIndex]?.run).toContain('code:"MODEL_REVIEW_TIMEOUT"');
    expect(steps[reviewIndex]?.run).toContain(
      "timeout --signal=TERM --kill-after=5s 20m",
    );
    expect(steps[reviewIndex]?.run).toContain("for pass in $(seq 1 64); do");
    expect(steps[reviewIndex]?.run).toContain(
      "npm run --silent review-target > review-result.json",
    );
    expect(steps[reviewIndex]?.run).toContain(
      "review_status=\"$(jq -er '.status' review-result.json)\"",
    );
    expect(steps[reviewIndex]?.run).toContain(
      'if [[ "$review_status" == "review_pending" ]]; then',
    );
    expect(steps[reviewIndex]?.run).toContain(
      'if [[ "$review_status" == "reviewed" ]]; then',
    );
    expect(steps[reviewIndex]?.run).toContain("progress_count() {");
    expect(steps[reviewIndex]?.run).toContain(
      'progress_before="$(progress_count)"',
    );
    expect(steps[reviewIndex]?.run).toContain(
      'progress_after="$(progress_count)"',
    );
    expect(steps[reviewIndex]?.run).toContain(
      'if [[ "$progress_after" -gt "$progress_before" ]]; then',
    );
    expect(steps[reviewIndex]?.run).toContain(
      'provider_no_progress_retries="0"',
    );
    expect(steps[reviewIndex]?.run).toContain(
      'provider_review_failure && [[ "$provider_no_progress_retries" -lt 1 ]]',
    );
    expect(steps[reviewIndex]?.run).toContain(
      'if ! retryable_review_failure || [[ "$pass" -eq 64 ]]; then',
    );
    expect(steps[reviewIndex]?.run).toContain('sleep "$((pass * 5))"');
    expect(steps[reviewIndex]?.run).toContain('sleep "$((pass * 60))"');
    expect(steps[reviewIndex]?.run).toContain("rm -f phase-error.json");
    expect(steps[reviewIndex]?.["timeout-minutes"]).toBe(65);
    expect(reviewConfig.timeoutMs).toBe(300_000);
    expect(steps[reviewIndex]?.env).toMatchObject({
      TAVERNKEEPER_API_ENDPOINT: "${{ secrets.TAVERNKEEPER_API_ENDPOINT }}",
      TAVERNKEEPER_API_KEY: "${{ secrets.TAVERNKEEPER_API_KEY }}",
      TAVERNKEEPER_MODEL: "${{ secrets.TAVERNKEEPER_MODEL }}",
      JSONREPAIR_API_ENDPOINT: "${{ secrets.JSONREPAIR_API_ENDPOINT }}",
      JSONREPAIR_API_KEY: "${{ secrets.JSONREPAIR_API_KEY }}",
      JSONREPAIR_MODEL: "${{ secrets.JSONREPAIR_MODEL }}",
    });
    expect(`${source}\n${packageSource}`).not.toMatch(
      /deep-scan|tavernkeeper-model-cache/iu,
    );
    const providerSecretSteps = steps.filter((step) =>
      /TAVERNKEEPER_API_(?:ENDPOINT|KEY)|TAVERNKEEPER_MODEL|JSONREPAIR_/u.test(
        JSON.stringify(step),
      ),
    );
    expect(providerSecretSteps.map((step) => step.name)).toEqual([
      "Contextually assess scanner evidence",
    ]);
    const dependencies = prepareSteps.find(
      (step) => step.name === "Install dependencies",
    );
    const toolchain = prepareSteps.find(
      (step) => step.name === "Install and verify pinned scanners",
    );
    const toolchainFailure = prepareSteps.find(
      (step) => step.name === "Record shared scanner toolchain failure",
    );
    expect(
      dependencies?.continueOnError ?? dependencies?.["continue-on-error"],
    ).toBe(true);
    expect(toolchain?.continueOnError ?? toolchain?.["continue-on-error"]).toBe(
      true,
    );
    expect(toolchainFailure?.run).toContain("SCANNER_UNAVAILABLE");
    expect(prepareSteps[prepareIndex]?.if).toContain(
      "steps.toolchain.outcome == 'success'",
    );
    expect(pack?.id).toBe("pack");
    expect(pack?.continueOnError ?? pack?.["continue-on-error"]).toBe(true);
    expect(pack?.env).toMatchObject({
      TAVERNKEEPER_ERROR_OUTPUT: "phase-error.json",
    });
    expect(pack?.run).toContain("prepared_bytes");
    expect(pack?.run).toContain("evidence_bytes");
    expect(packageFailure?.if).toContain("steps.pack.outcome != 'success'");
    expect(markPreparationFailure?.if).toContain(
      "steps.pack.outcome != 'success'",
    );
  });

  test("publisher-authoritative targets deploy and continue safely", async () => {
    const value = await workflow("scan-and-publish.yml");
    const publish = (value.jobs.publish.steps as Workflow[]).find(
      (step) => step.name === "Publish serialized target",
    );

    expect(value.jobs.publish.outputs).toMatchObject({
      reports: "${{ steps.publish.outputs.reports }}",
      failures: "${{ steps.publish.outputs.failures }}",
      queue_remaining: "${{ steps.publish.outputs.queue_remaining }}",
      queue_delayed: "${{ steps.publish.outputs.queue_delayed }}",
      next_wake_at: "${{ steps.publish.outputs.next_wake_at }}",
      chronic_failures: "${{ steps.publish.outputs.chronic_failures }}",
      automatic_holds: "${{ steps.publish.outputs.automatic_holds }}",
    });
    expect(value.jobs.publish.if).toBe("${{ always() }}");
    expect(publish).toMatchObject({ id: "publish", shell: "bash" });
    expect(publish?.run).toContain(
      `reports="$(jq -er '.reports | select(type == "number")' <<< "$result")"`,
    );
    expect(publish?.run).toContain("queue_remaining");
    expect(publish?.run).toContain("queue_delayed");
    expect(publish?.run).toContain("chronic_failures");
    expect(publish?.run).toContain("automatic_holds");
    expect(publish?.run).not.toMatch(
      /continuation_blocked|target_failures|shared_holds|security_holds|terminal_failures/u,
    );
    expect(publish?.run).toContain(
      `printf 'reports=%s\\n' "$reports" >> "$GITHUB_OUTPUT"`,
    );
    expect(publish?.run).not.toMatch(/echo .*jq/iu);
    expect(value.jobs.deploy.if).toBe(
      "${{ always() && needs.publish.result == 'success' && needs.publish.outputs.reports != '0' }}",
    );
    expect(value.jobs.continue.needs).toBe("publish");
    expect(value.jobs.continue.if).toContain(
      "needs.publish.outputs.queue_remaining != '0'",
    );
    expect(value.jobs.continue.if).not.toContain("needs.deploy");
    expect(value.jobs.continue.if).not.toMatch(
      /needs\.scan\.result|system_failure/u,
    );
    expect(Object.keys(value.on.workflow_call.inputs)).toEqual([
      "request_json",
    ]);
  });

  test("reports a secret-free incident when publication cannot persist state", async () => {
    const value = await workflow("scan-and-publish.yml");
    const incident = value.jobs.incident;
    const report = (incident.steps as Workflow[]).find(
      (step) => step.name === "Report bounded pipeline failure",
    );

    expect(incident.needs).toEqual(["scan", "publish"]);
    expect(incident.if).toContain("needs.publish.result == 'failure'");
    expect(incident.permissions).toEqual({ contents: "read", issues: "write" });
    expect(report?.env).toEqual({ GH_TOKEN: "${{ github.token }}" });
    expect(report?.run).toContain("PUBLISH_PIPELINE_FAILED");
    expect(report?.run).toContain('component="publication"');
    expect(JSON.stringify(incident)).not.toMatch(/secrets\./u);
  });

  test("reconciles chronic incidents by exact immutable target", async () => {
    const value = await workflow("scan-and-publish.yml");
    const reconcile = (value.jobs.publish.steps as Workflow[]).find(
      (step) => step.name === "Reconcile secret-free operational incidents",
    );

    expect(reconcile?.run).toContain(".target_incident_key");
    expect(reconcile?.run).toContain("Target incident key:");
    expect(reconcile?.run).toContain(".failure_history");
    expect(reconcile?.run).toContain("gh issue list --state all");
    expect(reconcile?.run).toContain("gh issue reopen");
    expect(reconcile?.run).toContain("gh issue close");
    expect(reconcile?.run).not.toContain(
      'gh issue list --state open --label scanner-operations --search "$repository_id $target in:body"',
    );
  });

  test("retry recovery remains manually dispatchable for operations", async () => {
    const value = await workflow("retry.yml");
    expect(value.on).toHaveProperty("workflow_dispatch");
  });

  test("reconcile exposes rich queue state to the reusable scanner", async () => {
    const value = await workflow("reconcile.yml");
    expect(value.jobs.claim.environment).toBe("tavernkeeper-scanner");
    expect(JSON.stringify(value.jobs.claim)).toContain("queue:claim");
    expect(value.jobs.claim.outputs).toMatchObject({
      total_remaining: "${{ steps.claim.outputs.total_remaining }}",
      runnable_remaining: "${{ steps.claim.outputs.runnable_remaining }}",
      delayed_entries: "${{ steps.claim.outputs.delayed_entries }}",
      next_wake_at: "${{ steps.claim.outputs.next_wake_at }}",
      emergency_stopped: "${{ steps.claim.outputs.emergency_stopped }}",
      automatic_holds: "${{ steps.claim.outputs.automatic_holds }}",
      recovery_probes: "${{ steps.claim.outputs.recovery_probes }}",
    });
    expect(value.jobs.run.with).toEqual({
      request_json: "${{ toJSON(matrix.request) }}",
    });
    expect(JSON.stringify(value)).not.toMatch(
      /deploy_required|recover-pages|shared_holds|security_holds|continuation_blocked/u,
    );
  });

  test("state migration exists only behind the protected staff workflow", async () => {
    const values = await Promise.all(
      workflowNames.map(async (name) => [name, await workflow(name)] as const),
    );
    const containingMigration = values
      .filter(([, value]) => JSON.stringify(value).includes("state:migrate"))
      .map(([name]) => name);
    const staff = values.find(([name]) => name === "staff-operations.yml")![1];

    expect(containingMigration).toEqual(["staff-operations.yml"]);
    expect(staff.jobs.operate.environment).toBe("tavernkeeper-staff");
    expect(staff.on.workflow_dispatch.inputs.operation.options).toContain(
      "migrate",
    );
  });

  test("staff can revoke a queued scan without reopening reconciliation", async () => {
    const value = await workflow("staff-operations.yml");
    const inputs = value.on.workflow_dispatch.inputs;
    const operate = (value.jobs.operate.steps as Workflow[]).find(
      (step) => step.name === "Apply and commit validated staff operation",
    );
    const reconcile = (value.jobs.operate.steps as Workflow[]).find(
      (step) => step.name === "Dispatch reconcile",
    );

    expect(inputs.operation.options).toContain("revoke");
    expect(inputs.repository_id.description).toMatch(/retry or revoke/iu);
    expect(operate?.run).toContain(
      '[[ "$OPERATION" = "retry" || "$OPERATION" = "revoke" ]]',
    );
    expect(reconcile?.if).toContain("inputs.operation != 'revoke'");
  });

  test("release holds is staff-gated and restarts reconciliation", async () => {
    const value = await workflow("release-holds.yml");
    const job = value.jobs.release;
    const steps = job.steps as Workflow[];
    const apply = steps.find(
      (step) => step.name === "Release automatic recovery holds",
    );
    const commit = steps.find(
      (step) => step.name === "Commit released operational state",
    );
    const reconcile = steps.find(
      (step) => step.name === "Dispatch backlog reconciliation",
    );

    expect(value.on).toEqual({ workflow_dispatch: null });
    expect(value.concurrency).toEqual({
      group: "tavernkeeper-global-scan",
      "cancel-in-progress": false,
    });
    expect(job.environment).toBe("tavernkeeper-staff");
    expect(apply?.env).toEqual({
      TAVERNKEEPER_OPERATION: '{"operation":"release-holds"}',
    });
    expect(apply?.run).toBe("npm run --silent retry");
    expect(commit?.run).toContain("git diff --quiet -- operations/state.json");
    expect(reconcile?.run).toBe(
      'gh workflow run reconcile.yml --repo "$GITHUB_REPOSITORY" --ref main',
    );
  });

  test("publisher authenticates its decrypted outcome against the requested target", async () => {
    const value = await workflow("scan-and-publish.yml");
    const decrypt = (value.jobs.publish.steps as Workflow[]).find(
      (step) => step.name === "Decrypt sanitized outcome",
    );
    const publish = (value.jobs.publish.steps as Workflow[]).find(
      (step) => step.name === "Publish serialized target",
    );

    expect(decrypt?.env).toEqual({
      TAVERNKEEPER_ARTIFACT_KEY: "${{ secrets.TAVERNKEEPER_ARTIFACT_KEY }}",
    });
    expect(decrypt?.run).toContain(
      "encrypted-artifact/tavernkeeper-outcome-${{ fromJSON(inputs.request_json).repository_id }}.enc",
    );
    expect(publish?.env).toEqual({
      TAVERNKEEPER_SCAN_REQUEST: "${{ inputs.request_json }}",
    });
  });

  test("the protected provider check makes isolated non-publishing provider requests", async () => {
    const value = await workflow("provider-check.yml");
    expect(value.jobs.authorize.environment).toBe("tavernkeeper-staff");
    expect(value.jobs.check.environment).toBe("tavernkeeper-scanner");
    const steps = value.jobs.check.steps as Workflow[];
    const check = steps.find(
      (step) => step.name === "Check one benign contextual review",
    );
    const repair = steps.find(
      (step) => step.name === "Check one synthetic JSON repair",
    );
    expect(check?.run).toBe("npm run --silent provider:check");
    expect(check?.env).toEqual({
      TAVERNKEEPER_API_ENDPOINT: "${{ secrets.TAVERNKEEPER_API_ENDPOINT }}",
      TAVERNKEEPER_API_KEY: "${{ secrets.TAVERNKEEPER_API_KEY }}",
      TAVERNKEEPER_MODEL: "${{ secrets.TAVERNKEEPER_MODEL }}",
    });
    expect(repair?.run).toBe("npm run --silent jsonrepair:check");
    expect(repair?.env).toEqual({
      JSONREPAIR_API_ENDPOINT: "${{ secrets.JSONREPAIR_API_ENDPOINT }}",
      JSONREPAIR_API_KEY: "${{ secrets.JSONREPAIR_API_KEY }}",
      JSONREPAIR_MODEL: "${{ secrets.JSONREPAIR_MODEL }}",
    });
    expect(JSON.stringify(check)).not.toContain("JSONREPAIR_");
    expect(JSON.stringify(repair)).not.toContain("TAVERNKEEPER_API_");
    expect(JSON.stringify(value)).not.toMatch(
      /publish|candidate\.json|git push/iu,
    );
  });

  test("reconcile probes a due provider hold without selecting a repository", async () => {
    const value = await workflow("reconcile.yml");
    const claimSteps = value.jobs.claim.steps as Workflow[];
    const claim = claimSteps.find(
      (step) => step.name === "Claim and commit available scan slots",
    );
    const probe = value.jobs["probe-provider"];
    const steps = probe.steps as Workflow[];
    const check = steps.find(
      (step) => step.name === "Check benign provider compatibility",
    );
    const transition = steps.find(
      (step) => step.name === "Apply provider probe outcome",
    );
    const commit = steps.find(
      (step) => step.name === "Commit provider recovery state",
    );
    const reconcile = steps.find(
      (step) => step.name === "Dispatch backlog reconciliation",
    );

    expect(value.jobs.claim.outputs.provider_probe_fingerprint).toBe(
      "${{ steps.claim.outputs.provider_probe_fingerprint }}",
    );
    expect(
      value.on.workflow_dispatch.inputs.force_provider_probe,
    ).toMatchObject({ type: "boolean", required: false, default: false });
    expect(claim?.env).toMatchObject({
      TAVERNKEEPER_FORCE_PROVIDER_PROBE:
        "${{ github.event.inputs.force_provider_probe || 'false' }}",
    });
    expect(claim?.run).toContain("provider_probe_fingerprint");
    expect(probe.needs).toBe("claim");
    expect(probe.if).toContain("provider_probe_fingerprint != ''");
    expect(probe.environment).toBe("tavernkeeper-scanner");
    expect(check).toMatchObject({
      id: "provider_check",
      "continue-on-error": true,
      "timeout-minutes": 5,
      run: "npm run --silent provider:check",
      env: {
        TAVERNKEEPER_API_ENDPOINT: "${{ secrets.TAVERNKEEPER_API_ENDPOINT }}",
        TAVERNKEEPER_API_KEY: "${{ secrets.TAVERNKEEPER_API_KEY }}",
        TAVERNKEEPER_MODEL: "${{ secrets.TAVERNKEEPER_MODEL }}",
        TAVERNKEEPER_ERROR_OUTPUT: "phase-error.json",
      },
    });
    expect(transition?.run).toContain("provider-probe-success");
    expect(transition?.run).toContain("provider-probe-failure");
    expect(transition?.run).toContain(
      "npm run --silent probe-outcome -- phase-error.json",
    );
    expect(transition?.run).toContain("probed_at");
    expect(transition?.run).toContain("npm run --silent retry");
    expect(commit?.run).toContain("git add operations/state.json");
    expect(commit?.run).toContain("git fetch origin main");
    expect(commit?.run).toContain("git reset --hard origin/main");
    expect(commit?.run).toContain("npm run --silent retry");
    expect(reconcile?.run).toBe(
      'gh workflow run reconcile.yml --repo "$GITHUB_REPOSITORY" --ref main',
    );
    expect(JSON.stringify(probe)).not.toMatch(
      /prepare-target|review-target|finalize-target|candidate\.json/u,
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
      with: {
        path: "${{ runner.temp }}/tavernkeeper-outcome-${{ fromJSON(inputs.request_json).repository_id }}.enc",
        "retention-days": 1,
      },
    });
    expect(download?.uses).toBe(downloadArtifactAction);
    expect(JSON.stringify(upload)).not.toMatch(
      /candidate\.json|transition\.json/u,
    );
    expect(transportKeySteps.map((step) => step.name)).toEqual([
      "Initialize encrypted bootstrap failure",
      "Encrypt sanitized outcome",
      "Decrypt sanitized outcome",
    ]);
  });

  test("every Publisher token uses the protected Client ID variable", async () => {
    for (const [workflowName, jobName, environment] of publisherMutationJobs) {
      const value = await workflow(workflowName);
      const job = value.jobs[jobName];
      const steps = job.steps as Workflow[];
      const tokenSteps = steps.filter((step) => step.uses === publisherAction);
      const tokenStep = tokenSteps[0];

      expect(job.environment).toBe(environment);
      expect(tokenSteps).toHaveLength(1);
      expect(tokenStep).toMatchObject({
        name: "Create TavernKeeper Publisher token",
        id: "publisher-token",
        uses: publisherAction,
        with: {
          "client-id": publisherClientId,
          "private-key": publisherPrivateKey,
          owner: "MentallyQuill",
          repositories: "TavernKeeper",
          "permission-contents": "write",
        },
      });
      expect(tokenStep?.with).not.toHaveProperty("app-id");
      expect(JSON.stringify(job)).not.toMatch(
        /TAVERNKEEPER_PUBLISHER_APP_ID|\bapp-id\b/u,
      );
    }
  });

  test("the Publisher verification canary is owner-only and sequential", async () => {
    const value = await workflow("publisher-verification.yml");
    const ownerMainGuard =
      "${{ github.actor_id == 2625904 && github.ref == 'refs/heads/main' }}";

    expect(value.on).toEqual({ workflow_dispatch: null });
    expect(value.permissions).toEqual({ contents: "read" });
    expect(value.concurrency).toEqual({
      group: "tavernkeeper-publisher-verification",
      "cancel-in-progress": false,
    });
    expect(Object.keys(value.jobs)).toEqual(["verify-scanner", "verify-staff"]);
    expect(value.jobs["verify-scanner"].needs).toBeUndefined();
    expect(value.jobs["verify-staff"].needs).toBe("verify-scanner");

    for (const [jobName, environment] of [
      ["verify-scanner", "tavernkeeper-scanner"],
      ["verify-staff", "tavernkeeper-staff"],
    ] as const) {
      const job = value.jobs[jobName];
      const steps = job.steps as Workflow[];
      const checkout = steps.find((step) => step.uses === checkoutAction);
      const token = steps.find((step) => step.uses === publisherAction);
      const push = steps.find((step) =>
        String(step.run).includes("git push origin HEAD:main"),
      );

      expect(job.if).toBe(ownerMainGuard);
      expect(job.environment).toBe(environment);
      expect(job.permissions).toEqual({ contents: "read" });
      expect(checkout).toMatchObject({
        uses: checkoutAction,
        with: { ref: "main", "persist-credentials": false },
      });
      expect(token?.with).not.toHaveProperty("skip-token-revoke");
      expect(push?.env).toEqual({
        GH_TOKEN: "${{ steps.publisher-token.outputs.token }}",
      });
      expect(push?.run).toContain("gh auth setup-git");
      expect(push?.run).toContain("git commit --allow-empty");
      expect(push?.run).not.toMatch(/--force/iu);
    }
  });

  test("each Publisher App token has one reviewed bounded push consumer", async () => {
    for (const [workflowName, jobName] of publisherMutationJobs) {
      const value = await workflow(workflowName);
      const steps = value.jobs[jobName].steps as Workflow[];
      const tokenSteps = steps.filter((step) => step.uses === publisherAction);
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
    }
  });

  test("workflow policy rejects removal of the contextual review boundary", async () => {
    await expectPolicyFailure(
      (text) =>
        text.replace(
          /      - name: Contextually assess scanner evidence[\s\S]*?(?=      - name: Finalize contextual V5 report)/u,
          "",
        ),
      /contextual review must remain bounded between preparation and V5 finalization/u,
    );
  });

  test("workflow policy rejects JSON repair credentials in preparation", async () => {
    await expectPolicyFailure(
      (text) =>
        text.replace(
          "          TAVERNKEEPER_SCAN_REQUEST: ${{ inputs.request_json }}",
          "          JSONREPAIR_API_KEY: ${{ secrets.JSONREPAIR_API_KEY }}\n          TAVERNKEEPER_SCAN_REQUEST: ${{ inputs.request_json }}",
        ),
      /JSON repair secret appears outside a repair-only step/u,
    );
  });

  test("workflow policy rejects an unguarded preparation diagnostic", async () => {
    await expectPolicyFailure(
      (source) => source.replace("github.actor_id == '2625904' && ", ""),
      /preparation diagnostic must remain owner-only/iu,
      "prepare-diagnostic.yml",
    );
  });

  test("workflow policy requires the synthetic JSON repair check", async () => {
    await expectPolicyFailure(
      (text) =>
        text.replace(
          /      - name: Check one synthetic JSON repair[\s\S]*$/u,
          "",
        ),
      /provider check must make one contextual and one JSON-repair-only request/u,
      "provider-check.yml",
    );
  });

  test("workflow policy pins target-domain provider recovery", async () => {
    await expectPolicyFailure(
      (text) =>
        text.replace(
          "npm run --silent probe-outcome -- phase-error.json",
          "jq -e '.domain == \"target\"' phase-error.json",
        ),
      /provider probe outcome classifier changed/iu,
      "reconcile.yml",
    );
  });

  test("workflow policy rejects an unbounded contextual review step", async () => {
    await expectPolicyFailure(
      (text) => text.replace("        timeout-minutes: 65\n", ""),
      /contextual review must remain bounded between preparation and V5 finalization/u,
    );
  });

  test("workflow policy pins the exact contextual resume loop", async () => {
    await expectPolicyFailure(
      (text) =>
        text.replace(
          '(.code == "MODEL_PROVIDER" and .domain == "shared"',
          '(.code == "MODEL_PROVIDER" and .domain != "security"',
        ),
      /contextual review must remain bounded between preparation and V5 finalization/u,
    );
  });

  test("workflow policy rejects removal of the no-progress cutoff", async () => {
    await expectPolicyFailure(
      (text) =>
        text.replace(
          'if [[ "$progress_after" -gt "$progress_before" ]]; then',
          'if [[ "$progress_after" -ge "$progress_before" ]]; then',
        ),
      /contextual review must remain bounded between preparation and V5 finalization/u,
    );
  });

  test("workflow policy rejects unbounded single-target jobs", async () => {
    await expectPolicyFailure(
      (text) => text.replace("    timeout-minutes: 30\n", ""),
      /single-target child jobs must retain bounded timeouts/u,
    );
  });

  test("workflow policy rejects removal of requested-target authentication", async () => {
    await expectPolicyFailure(
      (text) =>
        text.replace(
          /(      - name: Publish serialized target[\s\S]*?        env:\n)          TAVERNKEEPER_SCAN_REQUEST: \$\{\{ inputs\.request_json \}\}\n/u,
          "$1",
        ),
      /publisher must authenticate its decrypted target and expose typed routing outputs/u,
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
      (text) =>
        text.replace(
          "path: ${{ runner.temp }}/tavernkeeper-outcome-${{ fromJSON(inputs.request_json).repository_id }}.enc",
          "path: candidate.json",
        ),
      /scan artifact upload must always retain only outcome\.enc for one day/u,
    );
  });

  test("workflow policy preserves sanitized pack-failure handoffs", async () => {
    await expectPolicyFailure(
      (text) => text.replace("        id: pack\n", ""),
      /prepare must preserve a sanitized pack-failure artifact/u,
    );
  });

  test("workflow policy rejects artifact action pin drift", async () => {
    await expectPolicyFailure(
      (text) =>
        text.replace(
          uploadArtifactAction,
          `actions/upload-artifact@${"0".repeat(40)}`,
        ),
      /prepare must upload one bounded per-repository artifact for one day/u,
    );
    await expectPolicyFailure(
      (text) =>
        text.replace(
          downloadArtifactAction,
          `actions/download-artifact@${"0".repeat(40)}`,
        ),
      /review must download only its bounded prepared artifact/u,
    );
  });

  test("workflow policy rejects Publisher token reuse", async () => {
    await expectPolicyFailure(
      (text) =>
        text.replace(
          "      - name: Commit report and state\n",
          "      - name: Extra token consumer\n        env:\n          GH_TOKEN: ${{ steps.publisher-token.outputs.token }}\n        run: gh api user\n      - name: Commit report and state\n",
        ),
      /Publisher App token is consumed outside the reviewed commit step/u,
    );
  });

  test("workflow policy rejects legacy Publisher App ID credentials", async () => {
    await expectPolicyFailure(
      (text) =>
        text.replace(
          "client-id: ${{ vars.TAVERNKEEPER_PUBLISHER_CLIENT_ID }}",
          "app-id: ${{ vars.TAVERNKEEPER_PUBLISHER_CLIENT_ID }}",
        ),
      /Publisher App token step changed from the reviewed contract/u,
      "coverage-campaign.yml",
    );
    await expectPolicyFailure(
      (text) =>
        text.replace(
          "client-id: ${{ vars.TAVERNKEEPER_PUBLISHER_CLIENT_ID }}",
          "client-id: ${{ secrets.TAVERNKEEPER_PUBLISHER_APP_ID }}",
        ),
      /legacy Publisher App ID credential is not allowed/u,
      "coverage-campaign.yml",
    );
  });

  test("workflow policy rejects removal of bounded Publisher push retries", async () => {
    await expectPolicyFailure(
      (text) =>
        text.replace("for attempt in 1 2 3; do", "for attempt in 1; do"),
      /Publisher-authenticated push must retain one canonical bounded retry block/u,
    );
  });

  test("workflow policy pins staff queuing and Publisher token isolation", async () => {
    await expectPolicyFailure(
      (text) => text.replace("  queue: max\n", ""),
      /staff operations must retain their lossless serialized queue/u,
      "staff-operations.yml",
    );
    await expectPolicyFailure(
      (text) =>
        text.replace(
          "env -u GH_TOKEN -u GITHUB_TOKEN npm run --silent state:migrate",
          "npm run --silent state:migrate",
        ),
      /staff operation and Publisher token boundary changed/u,
      "staff-operations.yml",
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

  test("workflow policy rejects an alternate-syntax Publisher push", async () => {
    await expectPolicyFailure(
      (text) =>
        text.replace(
          '            test "$push_succeeded" = "true"\n',
          '            test "$push_succeeded" = "true"\n            git push origin \'HEAD:main\'\n',
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
    const reconcile = await readFile(
      new URL("../.github/workflows/pages-reconcile.yml", import.meta.url),
      "utf8",
    );
    expect(text).toMatch(/merge-base --is-ancestor/iu);
    expect(text).toMatch(/sha256sum \.site\/reports\/index\.json/iu);
    expect(text).not.toMatch(/sha256sum reports\/index\.json/iu);
    expect(text).toMatch(/\.site\/deployment-source\.txt/iu);
    expect(text).toMatch(/TavernKeeper\/deployment-source\.txt/iu);
    expect(reconcile).toMatch(/TavernKeeper\/deployment-source\.txt/iu);
    expect(reconcile).not.toMatch(/sha256sum reports\/index\.json/iu);
    expect(text).toMatch(/actions\/workflows\/.+\/dispatches/iu);
    expect(text).not.toMatch(/token_budget|priority|mode:/iu);
  });

  test("Pages artifacts are unique to each reusable deployment", async () => {
    const text = await readFile(
      new URL("../.github/workflows/deploy-pages.yml", import.meta.url),
      "utf8",
    );
    const sourceScopedArtifactName =
      /github-pages-\$\{\{\s*inputs\.source_sha\s*\}\}/gu;

    expect(text.match(sourceScopedArtifactName)).toHaveLength(2);
    expect(text).toMatch(
      /actions\/upload-pages-artifact@[0-9a-f]{40}[\s\S]*?with:\s*[\s\S]*?name:\s*github-pages-\$\{\{\s*inputs\.source_sha\s*\}\}/iu,
    );
    expect(text).toMatch(
      /actions\/deploy-pages@[0-9a-f]{40}[\s\S]*?with:\s*[\s\S]*?artifact_name:\s*github-pages-\$\{\{\s*inputs\.source_sha\s*\}\}/iu,
    );
  });

  test("documents the GitHub-only policy-5 JavaScript boundary", async () => {
    const scanning = await readFile(
      new URL("../docs/SCANNING.md", import.meta.url),
      "utf8",
    );
    const combined = [
      scanning,
      await readFile(new URL("../README.md", import.meta.url), "utf8"),
      await readFile(new URL("../docs/operations.md", import.meta.url), "utf8"),
      await readFile(
        new URL("../docs/architecture.md", import.meta.url),
        "utf8",
      ),
    ].join("\n");

    expect(scanning).toMatch(/policy 5/iu);
    expect(scanning).toMatch(/minified.*encoded.*bundle/isu);
    expect(scanning).toMatch(/never.*(?:execute|run).*target/isu);
    expect(scanning).toMatch(/first filter/iu);
    expect(scanning).toMatch(
      /The public color describes demonstrated risk, not scan completeness:[\s\S]*?\*\*Teal \/ low\*\* means the review found no demonstrated caution-level risk\./u,
    );
    expect(scanning).toMatch(
      /Coverage gaps\s+never change the advisory color or concern counts\./u,
    );
    expect(combined).not.toMatch(
      /\bincomplete coverage\b[^.]*\bcannot appear low\b/iu,
    );
    expect(combined).toMatch(/prepared-\$\{repository_id\}/u);
    expect(combined).toMatch(/GitHub-hosted Actions/iu);
    expect(combined).not.toMatch(/external scan server/iu);
  });

  test("the reviewed workflow policy passes", async () => {
    await expect(
      execFile(process.execPath, [workflowPolicyScript], {
        cwd: repositoryRoot,
      }),
    ).resolves.toMatchObject({
      stdout: expect.stringMatching(/Workflow policy passed for 15 workflows/u),
    });
  });
});
