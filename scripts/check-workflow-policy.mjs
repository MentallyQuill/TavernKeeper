import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";

import { parse } from "yaml";

const root = process.cwd();
const workflowRoot = join(root, ".github", "workflows");
const allowedTriggers = {
  "adjudicate.yml": ["workflow_dispatch"],
  "ci.yml": ["pull_request", "push"],
  "deep-scan.yml": ["workflow_dispatch"],
  "deploy-pages.yml": ["workflow_call", "workflow_dispatch"],
  "policy-rescan.yml": ["workflow_dispatch"],
  "reconcile.yml": [
    "repository_dispatch",
    "schedule",
    "workflow_call",
    "workflow_dispatch",
  ],
  "retry.yml": ["schedule"],
  "staff-operations.yml": ["workflow_dispatch"],
  "token-compat-receiver.yml": ["workflow_dispatch"],
  "token-compat.yml": ["workflow_dispatch"],
};
const protectedManualWorkflows = new Set([
  "adjudicate.yml",
  "deep-scan.yml",
  "policy-rescan.yml",
  "staff-operations.yml",
]);
const modelSecretPattern =
  /TAVERNKEEPER_API_(?:ENDPOINT|KEY)\b|TAVERNKEEPER_MODEL\b/u;
const modelSecretNames = new Set([
  "TAVERNKEEPER_API_ENDPOINT",
  "TAVERNKEEPER_API_KEY",
  "TAVERNKEEPER_MODEL",
]);
const publisherAction =
  "actions/create-github-app-token@fee1f7d63c2ff003460e3d139729b119787bc349";
const publisherToken = "${{ steps.publisher-token.outputs.token }}";
const publisherSecretPattern =
  /TAVERNKEEPER_PUBLISHER_APP_(?:ID|PRIVATE_KEY)\b/u;
const mutationJobs = {
  "adjudicate.yml": {
    job: "adjudicate",
    environment: "tavernkeeper-staff",
  },
  "deep-scan.yml": { job: "scan", environment: "tavernkeeper-staff" },
  "policy-rescan.yml": {
    job: "schedule",
    environment: "tavernkeeper-staff",
  },
  "reconcile.yml": { job: "publish", environment: "tavernkeeper-scanner" },
  "staff-operations.yml": {
    job: "operate",
    environment: "tavernkeeper-staff",
  },
};
const reviewedPublisherRuns = {
  "adjudicate.yml": `gh auth setup-git
git config user.name "TavernKeeper"
git config user.email "tavernkeeper@users.noreply.github.com"
git add reports operations/state.json rules/dismissals.json
git commit -m "chore(reports): publish staff adjudication"
git push origin HEAD:main
echo "source_sha=$(git rev-parse HEAD)" >> "$GITHUB_OUTPUT"`,
  "deep-scan.yml": `gh auth setup-git
git config user.name "TavernKeeper"
git config user.email "tavernkeeper@users.noreply.github.com"
git add reports operations/state.json
if ! git diff --cached --quiet; then
  git commit -m "chore(reports): publish staff deep scan"
  git push origin HEAD:main
fi
echo "source_sha=$(git rev-parse HEAD)" >> "$GITHUB_OUTPUT"`,
  "policy-rescan.yml": `gh auth setup-git
git config user.name "TavernKeeper"
git config user.email "tavernkeeper@users.noreply.github.com"
git add operations/state.json
git commit -m "chore(scans): schedule policy campaign"
git push origin HEAD:main`,
  "reconcile.yml": `gh auth setup-git
git config user.name "TavernKeeper"
git config user.email "tavernkeeper@users.noreply.github.com"
git add reports operations/state.json
if ! git diff --cached --quiet; then
  git commit -m "chore(reports): publish completed scans"
  git push origin HEAD:main
fi
echo "source_sha=$(git rev-parse HEAD)" >> "$GITHUB_OUTPUT"`,
  "staff-operations.yml": `gh auth setup-git
git config user.name "TavernKeeper"
git config user.email "tavernkeeper@users.noreply.github.com"
git add operations/state.json
git commit -m "chore(ops): apply staff queue operation"
git push origin HEAD:main`,
};
const reviewedContinuationDispatches = {
  "policy-rescan.yml": {
    job: "schedule",
    step: {
      name: "Dispatch reconcile",
      env: { GH_TOKEN: "${{ github.token }}" },
      run: "gh workflow run reconcile.yml --ref main",
    },
  },
  "reconcile.yml": {
    job: "continue",
    needs: ["plan", "deploy"],
    if: "${{ needs.deploy.result == 'success' && needs.plan.outputs.remaining != '0' }}",
    step: {
      name: "Continue remaining backlog without inputs",
      env: { GH_TOKEN: "${{ github.token }}" },
      run: "gh workflow run reconcile.yml --ref main",
    },
  },
  "staff-operations.yml": {
    job: "operate",
    step: {
      name: "Dispatch reconcile",
      if: "${{ inputs.operation != 'pause' }}",
      env: { GH_TOKEN: "${{ github.token }}" },
      run: "gh workflow run reconcile.yml --ref main",
    },
  },
};
const reviewedPermissionProfiles = {
  "adjudicate.yml": {
    workflow: { contents: "read", pages: "write", "id-token": "write" },
    jobs: { adjudicate: { contents: "read" }, deploy: undefined },
  },
  "ci.yml": {
    workflow: { contents: "read" },
    jobs: { check: undefined },
  },
  "deep-scan.yml": {
    workflow: {
      contents: "read",
      issues: "write",
      pages: "write",
      "id-token": "write",
    },
    jobs: {
      scan: { contents: "read", issues: "write" },
      deploy: undefined,
    },
  },
  "deploy-pages.yml": {
    workflow: { contents: "read", pages: "write", "id-token": "write" },
    jobs: { "authorize-manual": {}, deploy: undefined },
  },
  "policy-rescan.yml": {
    workflow: { contents: "read", actions: "write" },
    jobs: { schedule: { contents: "read", actions: "write" } },
  },
  "reconcile.yml": {
    workflow: {
      contents: "read",
      pages: "write",
      "id-token": "write",
      actions: "write",
    },
    jobs: {
      plan: { contents: "read" },
      scan: { contents: "read" },
      publish: { contents: "read", issues: "write" },
      deploy: undefined,
      continue: { actions: "write" },
    },
  },
  "retry.yml": {
    workflow: {
      contents: "read",
      pages: "write",
      "id-token": "write",
      actions: "write",
    },
    jobs: { reconcile: undefined },
  },
  "staff-operations.yml": {
    workflow: { contents: "read", actions: "write" },
    jobs: { operate: { contents: "read", actions: "write" } },
  },
};
const sensitiveInputPattern = /clone_url|endpoint|model|token|budget|command/iu;
const failures = [];

function fail(file, message) {
  failures.push(`${file}: ${message}`);
}

function walk(value, visit, path = []) {
  visit(value, path);
  if (Array.isArray(value)) {
    value.forEach((child, index) => walk(child, visit, [...path, index]));
    return;
  }
  if (value === null || typeof value !== "object") return;
  for (const [key, child] of Object.entries(value))
    walk(child, visit, [...path, key]);
}

function checkTriggers(file, workflow) {
  const expected = allowedTriggers[file];
  if (expected === undefined) {
    fail(file, "workflow is not present in the reviewed trigger allowlist");
    return;
  }
  const actual = Object.keys(workflow.on ?? {}).sort();
  if (JSON.stringify(actual) !== JSON.stringify([...expected].sort()))
    fail(
      file,
      `trigger set changed (expected ${expected.join(", ")}; received ${actual.join(", ")})`,
    );
  const dispatchInputs = workflow.on?.workflow_dispatch?.inputs ?? {};
  for (const name of Object.keys(dispatchInputs))
    if (sensitiveInputPattern.test(name))
      fail(
        file,
        `manual input ${name} may bypass the trusted target/model contract`,
      );
  if (
    protectedManualWorkflows.has(file) &&
    !JSON.stringify(workflow.jobs).includes("tavernkeeper-staff")
  )
    fail(
      file,
      "staff-only manual workflow lacks tavernkeeper-staff protection",
    );
}

function normalizedPermissions(value) {
  if (value === undefined) return undefined;
  if (value === null || typeof value !== "object" || Array.isArray(value))
    return value;
  return Object.fromEntries(
    Object.entries(value).sort(([left], [right]) => left.localeCompare(right)),
  );
}

function samePermissions(left, right) {
  return (
    JSON.stringify(normalizedPermissions(left)) ===
    JSON.stringify(normalizedPermissions(right))
  );
}

function checkPermissions(file, workflow) {
  const expected = reviewedPermissionProfiles[file];
  if (expected === undefined) return;
  if (!samePermissions(workflow.permissions, expected.workflow))
    fail(file, "root permissions changed from the reviewed profile");

  const jobs = workflow.jobs ?? {};
  const expectedNames = Object.keys(expected.jobs).sort();
  const actualNames = Object.keys(jobs).sort();
  if (JSON.stringify(actualNames) !== JSON.stringify(expectedNames)) {
    fail(file, "job set changed from the reviewed permission profile");
    return;
  }
  for (const jobName of expectedNames)
    if (!samePermissions(jobs[jobName]?.permissions, expected.jobs[jobName]))
      fail(file, `${jobName} permissions changed from the reviewed profile`);
}

function checkActionPins(file, workflow) {
  walk(workflow, (value, path) => {
    if (path.at(-1) !== "uses" || typeof value !== "string") return;
    if (value.startsWith("./")) return;
    if (!/@[0-9a-f]{40}$/u.test(value))
      fail(
        file,
        `external action is not pinned to a full commit SHA: ${value}`,
      );
  });
}

function checkParallelism(file, workflow) {
  walk(workflow, (value, path) => {
    if (path.at(-1) !== "max-parallel") return;
    if (!Number.isInteger(value) || value < 1 || value > 2)
      fail(
        file,
        `max-parallel must be an integer from 1 through 2, not ${String(value)}`,
      );
  });
  if (
    file === "reconcile.yml" &&
    workflow.jobs?.scan?.strategy?.["max-parallel"] !== 2
  )
    fail(file, "scan matrix must retain max-parallel: 2");
}

function modelSecretLocations(value, path = [], locations = []) {
  if (typeof value === "string") {
    if (modelSecretPattern.test(value)) locations.push({ path, value });
    return locations;
  }
  if (Array.isArray(value)) {
    value.forEach((child, index) =>
      modelSecretLocations(child, [...path, index], locations),
    );
    return locations;
  }
  if (value === null || typeof value !== "object") return locations;
  for (const [key, child] of Object.entries(value)) {
    const childPath = [...path, key];
    if (modelSecretPattern.test(key)) {
      locations.push({ path: childPath, value: child });
      continue;
    }
    modelSecretLocations(child, childPath, locations);
  }
  return locations;
}

function isAllowedModelSecretLocation(workflow, location) {
  const path = location.path;
  if (
    path.length !== 6 ||
    path[0] !== "jobs" ||
    path[2] !== "steps" ||
    !Number.isInteger(path[3]) ||
    path[4] !== "env" ||
    typeof path[5] !== "string" ||
    !modelSecretNames.has(path[5])
  )
    return false;
  const step = workflow.jobs?.[path[1]]?.steps?.[path[3]];
  if (step?.name !== "Review with configured model") return false;
  return (
    typeof location.value === "string" &&
    new RegExp(`^\\$\\{\\{\\s*secrets\\.${path[5]}\\s*\\}\\}$`, "u").test(
      location.value,
    )
  );
}

function checkModelSecretPlacement(file, workflow) {
  for (const location of modelSecretLocations(workflow))
    if (!isAllowedModelSecretLocation(workflow, location))
      fail(file, "model secret appears outside the review-step env");
}

function publisherSecretLocations(value, path = [], locations = []) {
  if (typeof value === "string") {
    if (publisherSecretPattern.test(value)) locations.push({ path, value });
    return locations;
  }
  if (Array.isArray(value)) {
    value.forEach((child, index) =>
      publisherSecretLocations(child, [...path, index], locations),
    );
    return locations;
  }
  if (value === null || typeof value !== "object") return locations;
  for (const [key, child] of Object.entries(value))
    publisherSecretLocations(child, [...path, key], locations);
  return locations;
}

function publisherTokenLocations(value, path = [], locations = []) {
  if (typeof value === "string") {
    if (value.includes(publisherToken)) locations.push(path);
    return locations;
  }
  if (Array.isArray(value)) {
    value.forEach((child, index) =>
      publisherTokenLocations(child, [...path, index], locations),
    );
    return locations;
  }
  if (value === null || typeof value !== "object") return locations;
  for (const [key, child] of Object.entries(value))
    publisherTokenLocations(child, [...path, key], locations);
  return locations;
}

function checkContinuationDispatch(file, workflow) {
  const contract = reviewedContinuationDispatches[file];
  if (contract === undefined) return;
  const job = workflow.jobs?.[contract.job];
  const dispatches = Object.entries(workflow.jobs ?? {}).flatMap(
    ([jobName, candidate]) =>
      (Array.isArray(candidate?.steps) ? candidate.steps : [])
        .filter(
          (step) =>
            typeof step?.run === "string" &&
            step.run.includes("gh workflow run"),
        )
        .map((step) => ({ jobName, step })),
  );
  if (
    job === undefined ||
    (contract.needs !== undefined &&
      JSON.stringify(job.needs) !== JSON.stringify(contract.needs)) ||
    (contract.if !== undefined && job.if !== contract.if) ||
    dispatches.length !== 1 ||
    dispatches[0]?.jobName !== contract.job ||
    JSON.stringify(dispatches[0]?.step) !== JSON.stringify(contract.step)
  )
    fail(file, "continuation dispatch changed from the reviewed contract");
}

function checkPublisherBoundary(file, workflow) {
  if (file === "token-compat.yml") return;
  const mutation = mutationJobs[file];
  const secretLocations = publisherSecretLocations(workflow);
  if (mutation === undefined) {
    if (secretLocations.length > 0)
      fail(file, "Publisher App secret appears outside a mutation workflow");
    return;
  }

  const job = workflow.jobs?.[mutation.job];
  if (job === undefined) {
    fail(file, `missing reviewed mutation job ${mutation.job}`);
    return;
  }
  if (job.environment !== mutation.environment)
    fail(
      file,
      `${mutation.job} must use protected environment ${mutation.environment}`,
    );

  const steps = Array.isArray(job.steps) ? job.steps : [];
  const secretSteps = steps.filter((step) =>
    JSON.stringify(step).match(publisherSecretPattern),
  );
  if (secretSteps.length !== 1)
    fail(file, "Publisher App secrets must appear in exactly one token step");

  const tokenStep = steps.find((step) => step?.id === "publisher-token");
  const tokenStepIndex = steps.indexOf(tokenStep);
  const expectedWith = {
    "app-id": "${{ secrets.TAVERNKEEPER_PUBLISHER_APP_ID }}",
    "private-key": "${{ secrets.TAVERNKEEPER_PUBLISHER_APP_PRIVATE_KEY }}",
    owner: "MentallyQuill",
    repositories: "TavernKeeper",
    "permission-contents": "write",
  };
  if (
    tokenStep?.name !== "Create TavernKeeper Publisher token" ||
    tokenStep?.uses !== publisherAction ||
    JSON.stringify(tokenStep?.with) !== JSON.stringify(expectedWith)
  )
    fail(file, "Publisher App token step changed from the reviewed contract");

  const expectedSecretLocations = new Map([
    [
      JSON.stringify([
        "jobs",
        mutation.job,
        "steps",
        tokenStepIndex,
        "with",
        "app-id",
      ]),
      expectedWith["app-id"],
    ],
    [
      JSON.stringify([
        "jobs",
        mutation.job,
        "steps",
        tokenStepIndex,
        "with",
        "private-key",
      ]),
      expectedWith["private-key"],
    ],
  ]);
  if (
    secretLocations.length !== expectedSecretLocations.size ||
    secretLocations.some(
      (location) =>
        expectedSecretLocations.get(JSON.stringify(location.path)) !==
        location.value,
    )
  )
    fail(file, "Publisher App secret appears outside the reviewed token step");

  const checkouts = steps.filter(
    (step) =>
      typeof step?.uses === "string" &&
      step.uses.startsWith("actions/checkout@"),
  );
  if (
    checkouts.length === 0 ||
    checkouts.some((step) => step?.with?.["persist-credentials"] !== false)
  )
    fail(file, "mutation checkout must disable persisted credentials");

  const pushSteps = steps.filter(
    (step) =>
      typeof step?.run === "string" &&
      step.run.includes("git push origin HEAD:main"),
  );
  if (pushSteps.length !== 1)
    fail(
      file,
      "mutation job must contain exactly one reviewed direct push step",
    );
  const pushStep = pushSteps[0];
  const pushStepIndex = steps.indexOf(pushStep);
  const expectedTokenLocation = JSON.stringify([
    "jobs",
    mutation.job,
    "steps",
    pushStepIndex,
    "env",
    "GH_TOKEN",
  ]);
  const tokenLocations = publisherTokenLocations(workflow);
  if (
    tokenLocations.length !== 1 ||
    JSON.stringify(tokenLocations[0]) !== expectedTokenLocation
  )
    fail(
      file,
      "Publisher App token is consumed outside the reviewed commit step",
    );
  if (pushStep?.run?.trim() !== reviewedPublisherRuns[file])
    fail(
      file,
      "Publisher-authenticated commit script changed from the reviewed contract",
    );
  for (const step of pushSteps) {
    if (step?.env?.GH_TOKEN !== publisherToken)
      fail(file, "direct push does not use the Publisher App token");
    if (!step.run.includes("gh auth setup-git"))
      fail(file, "direct push does not configure Git authentication");
    if (step.run.includes("gh workflow run"))
      fail(file, "direct push step also dispatches Actions");
  }
}

const names = (await readdir(workflowRoot))
  .filter((name) => /\.ya?ml$/u.test(name))
  .sort();
for (const file of names) {
  let workflow;
  try {
    workflow = parse(await readFile(join(workflowRoot, file), "utf8"));
  } catch (error) {
    fail(
      file,
      `could not parse workflow: ${error instanceof Error ? error.message : String(error)}`,
    );
    continue;
  }
  checkTriggers(file, workflow);
  checkPermissions(file, workflow);
  checkActionPins(file, workflow);
  checkParallelism(file, workflow);
  checkModelSecretPlacement(file, workflow);
  checkPublisherBoundary(file, workflow);
  checkContinuationDispatch(file, workflow);
}

const policy = JSON.parse(
  await readFile(join(root, "config", "scanner-policy.v1.json"), "utf8"),
);
if (policy.queue?.batchSize !== 5)
  fail(
    "config/scanner-policy.v1.json",
    "queue batchSize must remain exactly 5",
  );
if (policy.queue?.maxParallel !== 2)
  fail(
    "config/scanner-policy.v1.json",
    "queue maxParallel must remain exactly 2",
  );

if (failures.length > 0) {
  for (const failure of failures) process.stderr.write(`${failure}\n`);
  process.exitCode = 1;
} else {
  process.stdout.write(
    `Workflow policy passed for ${names.length} workflows.\n`,
  );
}
