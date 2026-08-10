import { readFile } from "node:fs/promises";

import { parse } from "yaml";
import { describe, expect, test } from "vitest";

type Workflow = Record<string, any>;

async function workflow(name: string): Promise<Workflow> {
  return parse(
    await readFile(
      new URL(`../.github/workflows/${name}`, import.meta.url),
      "utf8",
    ),
  ) as Workflow;
}

describe("two-lane scan workflows", () => {
  test("commits claims before fanning out at most two single-target children", async () => {
    const value = await workflow("reconcile.yml");
    const claim = value.jobs.claim;
    const run = value.jobs.run;

    expect(value.concurrency).toBeUndefined();
    expect(claim.environment).toBe("tavernkeeper-scanner");
    expect(JSON.stringify(claim)).toContain("queue:claim");
    expect(JSON.stringify(claim)).toContain("operations/state.json");
    expect(JSON.stringify(claim)).toContain("git fetch origin main");
    expect(claim.outputs.requests_json).toBe(
      "${{ steps.claim.outputs.requests_json }}",
    );
    expect(run.needs).toBe("claim");
    expect(run.strategy).toMatchObject({
      "fail-fast": false,
      "max-parallel": 2,
      matrix: {
        request: "${{ fromJSON(needs.claim.outputs.requests_json) }}",
      },
    });
    expect(run.uses).toBe("./.github/workflows/scan-and-publish.yml");
    expect(run.with).toEqual({
      request_json: "${{ toJSON(matrix.request) }}",
    });
  });

  test("each child scans and publishes only its own target", async () => {
    const value = await workflow("scan-and-publish.yml");
    const prepare = value.jobs.prepare;
    const scan = value.jobs.scan;
    const publishSteps = value.jobs.publish.steps as Workflow[];
    const download = publishSteps.find(
      (step) => step.name === "Download encrypted outcome",
    );
    const commit = publishSteps.find(
      (step) => step.name === "Commit report and state",
    );

    expect(Object.keys(value.on.workflow_call.inputs)).toEqual([
      "request_json",
    ]);
    expect(prepare.strategy).toBeUndefined();
    expect(scan.strategy).toBeUndefined();
    expect(prepare["timeout-minutes"]).toBe(30);
    expect(scan["timeout-minutes"]).toBe(90);
    expect(JSON.stringify(value)).toContain("fromJSON(inputs.request_json)");
    expect(download?.with.name).toContain("scan-");
    expect(download?.with).not.toHaveProperty("pattern");
    expect(JSON.stringify(publishSteps)).not.toContain(
      "find encrypted-artifacts",
    );
    expect(commit?.run).toContain("git fetch origin main");
    expect(commit?.run).toContain("git reset --hard origin/main");
    expect(commit?.run).toContain("run_publication");
    expect(value.jobs.deploy.needs).toBe("publish");
    expect(value.jobs.continue.needs).toBe("publish");
  });
});
