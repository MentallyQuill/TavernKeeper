import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";

import { parse } from "yaml";

const root = process.cwd();
const workflowRoot = join(root, ".github", "workflows");
const failures = [];
const publisherAction =
  "actions/create-github-app-token@fee1f7d63c2ff003460e3d139729b119787bc349";
const publisherToken = "${{ steps.publisher-token.outputs.token }}";
const artifactSecret = "${{ secrets.TAVERNKEEPER_ARTIFACT_KEY }}";
const allowedTriggers = {
  "ci.yml": ["pull_request", "push"],
  "deep-scan.yml": ["workflow_dispatch"],
  "deploy-pages.yml": ["workflow_call", "workflow_dispatch"],
  "policy-rescan.yml": ["workflow_dispatch"],
  "provider-check.yml": ["workflow_dispatch"],
  "reconcile.yml": [
    "repository_dispatch",
    "schedule",
    "workflow_call",
    "workflow_dispatch",
  ],
  "retry.yml": ["schedule"],
  "scan-and-publish.yml": ["workflow_call"],
  "staff-operations.yml": ["workflow_dispatch"],
  "targeted-scan.yml": ["workflow_dispatch"],
};
const permissionProfiles = {
  "ci.yml": {
    workflow: { contents: "read" },
    jobs: { check: undefined, "scanner-toolchain": undefined },
  },
  "deep-scan.yml": {
    workflow: {
      contents: "read",
      issues: "write",
      pages: "write",
      "id-token": "write",
      actions: "write",
    },
    jobs: { resolve: { contents: "read" }, scan: undefined },
  },
  "deploy-pages.yml": {
    workflow: { contents: "read", pages: "write", "id-token": "write" },
    jobs: { "authorize-manual": {}, deploy: undefined },
  },
  "policy-rescan.yml": {
    workflow: { contents: "read", actions: "write" },
    jobs: { schedule: { contents: "read", actions: "write" } },
  },
  "provider-check.yml": {
    workflow: { contents: "read" },
    jobs: { authorize: {}, check: { contents: "read" } },
  },
  "reconcile.yml": {
    workflow: {
      contents: "read",
      issues: "write",
      pages: "write",
      "id-token": "write",
      actions: "write",
    },
    jobs: {
      plan: { contents: "read" },
      "recover-pages": undefined,
      run: undefined,
      "resume-after-recovery": { actions: "write" },
    },
  },
  "retry.yml": {
    workflow: {
      contents: "read",
      issues: "write",
      pages: "write",
      "id-token": "write",
      actions: "write",
    },
    jobs: { reconcile: undefined },
  },
  "scan-and-publish.yml": {
    workflow: {
      contents: "read",
      issues: "write",
      pages: "write",
      "id-token": "write",
      actions: "write",
    },
    jobs: {
      scan: { contents: "read" },
      publish: { contents: "read", issues: "write" },
      deploy: undefined,
      continue: { actions: "write" },
    },
  },
  "staff-operations.yml": {
    workflow: { contents: "read", actions: "write" },
    jobs: { operate: { contents: "read", actions: "write" } },
  },
  "targeted-scan.yml": {
    workflow: {
      contents: "read",
      issues: "write",
      pages: "write",
      "id-token": "write",
      actions: "write",
    },
    jobs: {
      resolve: { contents: "read", actions: "read" },
      scan: undefined,
    },
  },
};
const protectedManual = new Set([
  "deep-scan.yml",
  "policy-rescan.yml",
  "provider-check.yml",
  "staff-operations.yml",
]);
const mutationJobs = {
  "policy-rescan.yml": { job: "schedule", environment: "tavernkeeper-staff" },
  "scan-and-publish.yml": {
    job: "publish",
    environment: "tavernkeeper-scanner",
  },
  "staff-operations.yml": {
    job: "operate",
    environment: "tavernkeeper-staff",
  },
};
const modelProviderSecretNames = new Set([
  "TAVERNKEEPER_API_ENDPOINT",
  "TAVERNKEEPER_API_KEY",
  "TAVERNKEEPER_MODEL",
]);
const approvedWorkflowSecretNames = new Set([
  ...modelProviderSecretNames,
  "TAVERNKEEPER_ARTIFACT_KEY",
  "TAVERNKEEPER_PUBLISHER_APP_ID",
  "TAVERNKEEPER_PUBLISHER_APP_PRIVATE_KEY",
  "TAVERNARY_WAKE_APP_ID",
  "TAVERNARY_WAKE_APP_PRIVATE_KEY",
]);
const publisherSecretPattern =
  /TAVERNKEEPER_PUBLISHER_APP_(?:ID|PRIVATE_KEY)\b/u;
const artifactSecretPattern = /TAVERNKEEPER_ARTIFACT_KEY\b/u;
const sensitiveInputPattern =
  /clone_url|repository_url|endpoint|branch|sha|model|mode|priority|token|budget|command/iu;
const modelProviderSecretSteps = {
  "provider-check.yml": {
    job: "check",
    step: "Check configured model provider",
  },
  "scan-and-publish.yml": {
    job: "scan",
    step: "Review with configured model",
  },
};

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

function locationsMatching(value, pattern) {
  const locations = [];
  walk(value, (candidate, path) => {
    if (
      (typeof candidate === "string" && pattern.test(candidate)) ||
      (typeof path.at(-1) === "string" && pattern.test(path.at(-1)))
    )
      locations.push({ path, value: candidate });
  });
  return locations;
}

function workflowSecretReferences(workflow) {
  const references = [];
  const dynamicAccesses = [];
  walk(workflow, (candidate, path) => {
    if (typeof candidate !== "string") return;
    for (const match of candidate.matchAll(/secrets\s*\.\s*([A-Z0-9_]+)/giu))
      references.push({ name: match[1].toUpperCase(), path });
    for (const match of candidate.matchAll(
      /secrets\s*\[\s*['"]([A-Z0-9_]+)['"]\s*\]/giu,
    ))
      references.push({ name: match[1].toUpperCase(), path });
    for (const expression of candidate.matchAll(/\$\{\{([\s\S]*?)\}\}/gu)) {
      const withoutLiterals = expression[1].replace(
        /secrets\s*(?:\.\s*[A-Z0-9_]+|\[\s*(['"])[A-Z0-9_]+\1\s*\])/giu,
        "",
      );
      if (/\bsecrets\b/iu.test(withoutLiterals)) dynamicAccesses.push({ path });
    }
  });
  return { references, dynamicAccesses };
}

function workflowCallSecretDeclarations(workflow) {
  const events = workflow.on ?? workflow.true ?? {};
  return Object.keys(events.workflow_call?.secrets ?? {}).map((name) =>
    name.toUpperCase(),
  );
}

function normalized(value) {
  if (value === undefined) return undefined;
  if (value === null || typeof value !== "object" || Array.isArray(value))
    return value;
  return Object.fromEntries(
    Object.entries(value)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, child]) => [key, normalized(child)]),
  );
}

function same(left, right) {
  return JSON.stringify(normalized(left)) === JSON.stringify(normalized(right));
}

function checkTriggers(file, workflow) {
  const expected = allowedTriggers[file];
  if (expected === undefined) {
    fail(file, "workflow is not present in the reviewed trigger allowlist");
    return;
  }
  const actual = Object.keys(workflow.on ?? {}).sort();
  if (JSON.stringify(actual) !== JSON.stringify([...expected].sort()))
    fail(file, "trigger set changed from the reviewed contract");
  for (const name of Object.keys(workflow.on?.workflow_dispatch?.inputs ?? {}))
    if (
      sensitiveInputPattern.test(name) &&
      !(file === "deploy-pages.yml" && name === "source_sha")
    )
      fail(file, `manual input ${name} bypasses the trusted target contract`);
  if (
    protectedManual.has(file) &&
    !JSON.stringify(workflow.jobs).includes("tavernkeeper-staff")
  )
    fail(file, "staff-only manual workflow lacks staff environment protection");
}

function checkPermissions(file, workflow) {
  const expected = permissionProfiles[file];
  if (expected === undefined) return;
  if (!same(workflow.permissions, expected.workflow))
    fail(file, "root permissions changed from the reviewed profile");
  const jobs = workflow.jobs ?? {};
  if (
    JSON.stringify(Object.keys(jobs).sort()) !==
    JSON.stringify(Object.keys(expected.jobs).sort())
  ) {
    fail(file, "job set changed from the reviewed permission profile");
    return;
  }
  for (const [job, permissions] of Object.entries(expected.jobs))
    if (!same(jobs[job]?.permissions, permissions))
      fail(file, `${job} permissions changed from the reviewed profile`);
}

function checkPins(file, workflow) {
  walk(workflow, (value, path) => {
    if (path.at(-1) !== "uses" || typeof value !== "string") return;
    if (!value.startsWith("./") && !/@[0-9a-f]{40}$/u.test(value))
      fail(file, `external action is not pinned: ${value}`);
  });
}

function checkSecretPlacement(file, workflow) {
  for (const name of workflowCallSecretDeclarations(workflow))
    if (!approvedWorkflowSecretNames.has(name))
      fail(file, `unapproved workflow secret ${name}`);

  const { references, dynamicAccesses } = workflowSecretReferences(workflow);
  for (const _access of dynamicAccesses)
    fail(file, "dynamic secrets context access is not allowed");
  for (const { name, path } of references) {
    if (!approvedWorkflowSecretNames.has(name)) {
      fail(file, `unapproved workflow secret ${name}`);
      continue;
    }
    if (!modelProviderSecretNames.has(name)) continue;
    const approved = modelProviderSecretSteps[file];
    const stepIndex = path[3];
    const step = Number.isInteger(stepIndex)
      ? workflow.jobs?.[path[1]]?.steps?.[stepIndex]
      : undefined;
    const reviewedProviderStep =
      path[0] === "jobs" &&
      path[1] === approved?.job &&
      path[2] === "steps" &&
      path[4] === "env" &&
      path[5] === name &&
      step?.name === approved?.step;
    if (!reviewedProviderStep)
      fail(file, "model secret appears outside a reviewed provider step");
  }

  for (const location of locationsMatching(workflow, artifactSecretPattern)) {
    const joined = location.path.join(".");
    const declaration = joined.startsWith("on.workflow_call.secrets.");
    const stepIndex = location.path[3];
    const step = Number.isInteger(stepIndex)
      ? workflow.jobs?.[location.path[1]]?.steps?.[stepIndex]
      : undefined;
    if (
      !declaration &&
      ![
        "Initialize encrypted bootstrap failure",
        "Encrypt sanitized outcome",
        "Decrypt sanitized outcomes",
      ].includes(step?.name)
    )
      fail(file, "artifact key appears outside authenticated transport steps");
  }
}

function checkModelReviewPhase(file, workflow) {
  if (file !== "scan-and-publish.yml") return;
  const phases = [];
  for (const [jobName, job] of Object.entries(workflow.jobs ?? {}))
    for (const step of job?.steps ?? [])
      if (
        step?.name === "Review with configured model" ||
        String(step?.run ?? "").includes("review-target") ||
        workflowSecretReferences(step).references.some(({ name }) =>
          modelProviderSecretNames.has(name),
        )
      )
        phases.push({ jobName, step });

  if (phases.some(({ jobName }) => jobName !== "scan"))
    fail(file, "model-review phase appears outside the approved scan job step");
  const approved = phases.filter(
    ({ jobName, step }) =>
      jobName === "scan" &&
      step?.name === "Review with configured model" &&
      step?.run === "npm run --silent review-target -- review.json",
  );
  if (phases.length !== 1 || approved.length !== 1)
    fail(file, "must contain exactly one approved model-review phase");
}

function checkEncryptedHandoff(file, workflow) {
  if (file !== "scan-and-publish.yml") return;
  const steps = workflow.jobs?.scan?.steps ?? [];
  const bootstrap = steps[0];
  if (
    bootstrap?.name !== "Initialize encrypted bootstrap failure" ||
    bootstrap?.env?.TAVERNKEEPER_ARTIFACT_KEY !== artifactSecret ||
    !bootstrap?.run?.includes("SCAN_BOOTSTRAP_FAILED") ||
    !bootstrap?.run?.includes("aes-256-gcm") ||
    !bootstrap?.run?.includes('"outcome.enc"')
  )
    fail(file, "scan must initialize an encrypted failure before setup");
  const uploads = steps.filter(
    (step) =>
      typeof step?.uses === "string" &&
      step.uses.startsWith("actions/upload-artifact@"),
  );
  if (uploads.length !== 1 || uploads[0]?.with?.path !== "outcome.enc")
    fail(file, "scan artifact upload must contain only outcome.enc");
  const encrypt = steps.find(
    (step) => step?.name === "Encrypt sanitized outcome",
  );
  if (
    encrypt?.if !== "always()" ||
    !encrypt?.run?.includes("outcome-actual.enc") ||
    !encrypt?.run?.includes("mv outcome-actual.enc outcome.enc")
  )
    fail(file, "scan must atomically replace the bootstrap failure outcome");
  if (workflow.jobs?.scan?.strategy?.["max-parallel"] !== 2)
    fail(file, "scan matrix must retain max-parallel: 2");
  if (workflow.jobs?.scan?.strategy?.["fail-fast"] !== true)
    fail(file, "scan matrix must stop pending work after a system failure");
}

function checkPublisherBoundary(file, workflow) {
  const mutation = mutationJobs[file];
  const publisherLocations = locationsMatching(
    workflow,
    publisherSecretPattern,
  );
  if (mutation === undefined) {
    if (publisherLocations.length > 0)
      fail(file, "Publisher App secret appears outside a mutation workflow");
    return;
  }
  const job = workflow.jobs?.[mutation.job];
  if (job?.environment !== mutation.environment)
    fail(file, `${mutation.job} must use ${mutation.environment}`);
  const steps = job?.steps ?? [];
  const tokenSteps = steps.filter((step) =>
    JSON.stringify(step).match(publisherSecretPattern),
  );
  const tokenStep = tokenSteps[0];
  if (
    tokenSteps.length !== 1 ||
    tokenStep?.name !== "Create TavernKeeper Publisher token" ||
    tokenStep?.id !== "publisher-token" ||
    tokenStep?.uses !== publisherAction ||
    tokenStep?.with?.owner !== "MentallyQuill" ||
    tokenStep?.with?.repositories !== "TavernKeeper" ||
    tokenStep?.with?.["permission-contents"] !== "write"
  )
    fail(file, "Publisher App token step changed from the reviewed contract");
  const consumers = [];
  walk(workflow, (value, path) => {
    if (typeof value === "string" && value.includes(publisherToken))
      consumers.push(path);
  });
  const pushStep = steps.find(
    (step) =>
      typeof step?.run === "string" &&
      step.run.includes("git push origin HEAD:main"),
  );
  const expectedConsumer = [
    "jobs",
    mutation.job,
    "steps",
    steps.indexOf(pushStep),
    "env",
    "GH_TOKEN",
  ];
  if (
    consumers.length !== 1 ||
    JSON.stringify(consumers[0]) !== JSON.stringify(expectedConsumer)
  )
    fail(
      file,
      "Publisher App token is consumed outside the reviewed commit step",
    );
  if (
    pushStep?.env?.GH_TOKEN !== publisherToken ||
    !pushStep?.run?.includes("gh auth setup-git") ||
    /--force|gh workflow run/iu.test(pushStep?.run ?? "")
  )
    fail(
      file,
      "Publisher-authenticated push changed from the reviewed contract",
    );
  const checkouts = steps.filter(
    (step) =>
      typeof step?.uses === "string" &&
      step.uses.startsWith("actions/checkout@"),
  );
  if (
    checkouts.length === 0 ||
    checkouts.some((step) => step.with?.["persist-credentials"] !== false)
  )
    fail(file, "mutation checkout must disable persisted credentials");
}

function checkTargetedAuthority(file, workflow) {
  if (file !== "targeted-scan.yml") return;
  const inputs = Object.keys(workflow.on?.workflow_dispatch?.inputs ?? {});
  if (JSON.stringify(inputs) !== JSON.stringify(["repository_id"]))
    fail(file, "targeted workflow accepts more than repository_id");
  const condition = workflow.jobs?.resolve?.if ?? "";
  if (
    !condition.includes("github.actor_id") ||
    !condition.includes("vars.TAVERNARY_WAKE_APP_BOT_ID")
  )
    fail(
      file,
      "targeted workflow lacks immutable wake-App actor authorization",
    );
}

function checkScannerToolchain(file, workflow) {
  if (file !== "ci.yml") return;
  const steps = workflow.jobs?.["scanner-toolchain"]?.steps ?? [];
  const smoke = steps.find(
    (step) => step?.name === "Smoke-test the production scanner adapters",
  );
  if (smoke?.run !== "npm run scanners:smoke")
    fail(
      file,
      "scanner-toolchain must run the real adapter compatibility smoke test",
    );
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
  checkPins(file, workflow);
  checkSecretPlacement(file, workflow);
  checkModelReviewPhase(file, workflow);
  checkEncryptedHandoff(file, workflow);
  checkPublisherBoundary(file, workflow);
  checkTargetedAuthority(file, workflow);
  checkScannerToolchain(file, workflow);
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
