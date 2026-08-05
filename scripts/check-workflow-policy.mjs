import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";

import { parse } from "yaml";

const root = process.cwd();
const workflowRoot = join(root, ".github", "workflows");
const failures = [];
const publisherAction =
  "actions/create-github-app-token@f8d387b68d61c58ab83c6c016672934102569859";
const uploadArtifactAction =
  "actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a";
const downloadArtifactAction =
  "actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c";
const publisherToken = "${{ steps.publisher-token.outputs.token }}";
const canonicalPublisherPushLines = [
  'push_succeeded="false"',
  "for attempt in 1 2 3; do",
  "  if git push origin HEAD:main; then",
  '    push_succeeded="true"',
  "    break",
  "  fi",
  '  if [[ "$attempt" -lt 3 ]]; then',
  '    sleep "$((attempt * 15))"',
  "  fi",
  "done",
  'test "$push_succeeded" = "true"',
];
const canonicalStaffPublisherPushLines = [
  'push_succeeded="false"',
  "for attempt in 1 2 3; do",
  "  git fetch origin main",
  "  git reset --hard origin/main",
  "  run_operation",
  "  git add operations/state.json",
  "  if ! git diff --cached --quiet; then",
  '    git commit -m "chore(ops): apply staff queue operation"',
  "  fi",
  "  if git push origin HEAD:main; then",
  '    push_succeeded="true"',
  "    break",
  "  fi",
  '  if [[ "$attempt" -lt 3 ]]; then',
  '    sleep "$((attempt * 15))"',
  "  fi",
  "done",
  'test "$push_succeeded" = "true"',
];
const canonicalStaffPublisherRun =
  [
    "run_operation() {",
    '  if [[ "$OPERATION" = "migrate" ]]; then',
    "    env -u GH_TOKEN -u GITHUB_TOKEN npm run --silent state:migrate",
    '  elif [[ "$OPERATION" = "pause" ]]; then',
    '    request="$(jq -nc --arg operation "$OPERATION" --arg reason_code "$REASON_CODE" \'{operation:$operation,reason_code:$reason_code}\')"',
    '    env -u GH_TOKEN -u GITHUB_TOKEN TAVERNKEEPER_OPERATION="$request" npm run --silent retry',
    '  elif [[ "$OPERATION" = "retry" ]]; then',
    '    request="$(jq -nc --arg operation "$OPERATION" --argjson repository_id "$REPOSITORY_ID" \'{operation:$operation,repository_id:$repository_id}\')"',
    '    env -u GH_TOKEN -u GITHUB_TOKEN TAVERNKEEPER_OPERATION="$request" npm run --silent retry',
    "  else",
    '    env -u GH_TOKEN -u GITHUB_TOKEN TAVERNKEEPER_OPERATION=\'{"operation":"resume"}\' npm run --silent retry',
    "  fi",
    "}",
    "",
    "gh auth setup-git",
    'git config user.name "TavernKeeper"',
    'git config user.email "tavernkeeper@users.noreply.github.com"',
    ...canonicalStaffPublisherPushLines,
  ].join("\n") + "\n";
const canonicalContextualReviewRun = String.raw`run_review() {
  node -e 'require("node:fs").writeFileSync("phase-error.json", JSON.stringify({code:"MODEL_REVIEW_TIMEOUT",domain:"target",component:"contextual-model"}) + "\n", {flag:"wx"})'
  if timeout --signal=TERM --kill-after=5s 10m npm run --silent review-target; then
    rm -f phase-error.json
    return 0
  fi
  return 1
}
retryable_review_failure() {
  jq -e '(.code == "MODEL_PROVIDER" and .domain == "shared" and .component == "contextual-model") or (.code == "MODEL_REVIEW_TIMEOUT" and .domain == "target" and .component == "contextual-model")' phase-error.json >/dev/null
}
for pass in 1 2 3 4; do
  if run_review; then
    exit 0
  fi
  if ! retryable_review_failure || [[ "$pass" -eq 4 ]]; then
    exit 1
  fi
  rm -f phase-error.json
  sleep "$((pass * 5))"
done
exit 1
`;
const artifactSecret = "${{ secrets.TAVERNKEEPER_ARTIFACT_KEY }}";

const allowedTriggers = {
  "ci.yml": ["pull_request", "push"],
  "delayed-wake.yml": ["workflow_dispatch"],
  "deploy-pages.yml": ["workflow_call", "workflow_dispatch"],
  "pages-reconcile.yml": ["schedule", "workflow_dispatch"],
  "policy-rescan.yml": ["workflow_dispatch"],
  "provider-check.yml": ["workflow_dispatch"],
  "reconcile.yml": [
    "repository_dispatch",
    "schedule",
    "workflow_call",
    "workflow_dispatch",
  ],
  "release-holds.yml": ["workflow_dispatch"],
  "retry.yml": ["schedule", "workflow_dispatch"],
  "scan-and-publish.yml": ["workflow_call"],
  "staff-operations.yml": ["workflow_dispatch"],
  "targeted-scan.yml": ["workflow_dispatch"],
};

const permissionProfiles = {
  "ci.yml": {
    workflow: { contents: "read" },
    jobs: { check: undefined, "scanner-toolchain": undefined },
  },
  "delayed-wake.yml": {
    workflow: { contents: "read", actions: "write" },
    jobs: { wake: { contents: "read", actions: "write" } },
  },
  "deploy-pages.yml": {
    workflow: { contents: "read", pages: "write", "id-token": "write" },
    jobs: { "authorize-manual": {}, deploy: undefined },
  },
  "pages-reconcile.yml": {
    workflow: { contents: "read", pages: "write", "id-token": "write" },
    jobs: { check: { contents: "read" }, deploy: undefined },
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
      sync: { contents: "read" },
      plan: { contents: "read", actions: "write" },
      run: undefined,
    },
  },
  "release-holds.yml": {
    workflow: { contents: "read", actions: "write" },
    jobs: { release: { contents: "read", actions: "write" } },
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
      incident: { contents: "read", issues: "write" },
      continue: { actions: "write" },
    },
  },
  "staff-operations.yml": {
    workflow: { contents: "read", actions: "write" },
    jobs: { operate: { contents: "read", actions: "write" } },
  },
  "targeted-scan.yml": {
    workflow: { contents: "read", actions: "write" },
    jobs: {
      enqueue: { contents: "read", actions: "write" },
    },
  },
};

const protectedManual = new Set([
  "policy-rescan.yml",
  "provider-check.yml",
  "release-holds.yml",
  "staff-operations.yml",
]);
const mutationJobs = {
  "policy-rescan.yml": { job: "schedule", environment: "tavernkeeper-staff" },
  "reconcile.yml": { job: "sync", environment: "tavernkeeper-scanner" },
  "scan-and-publish.yml": {
    job: "publish",
    environment: "tavernkeeper-scanner",
  },
  "release-holds.yml": {
    job: "release",
    environment: "tavernkeeper-staff",
  },
  "staff-operations.yml": {
    job: "operate",
    environment: "tavernkeeper-staff",
  },
  "targeted-scan.yml": {
    job: "enqueue",
    environment: "tavernkeeper-scanner",
  },
};
const approvedWorkflowSecretNames = new Set([
  "TAVERNKEEPER_ARTIFACT_KEY",
  "TAVERNKEEPER_API_ENDPOINT",
  "TAVERNKEEPER_API_KEY",
  "TAVERNKEEPER_MODEL",
  "TAVERNKEEPER_PUBLISHER_APP_ID",
  "TAVERNKEEPER_PUBLISHER_APP_PRIVATE_KEY",
  "TAVERNARY_WAKE_APP_ID",
  "TAVERNARY_WAKE_APP_PRIVATE_KEY",
]);
const publisherSecretPattern =
  /TAVERNKEEPER_PUBLISHER_APP_(?:ID|PRIVATE_KEY)\b/u;
const artifactSecretPattern = /TAVERNKEEPER_ARTIFACT_KEY\b/u;
const providerSecretPattern =
  /TAVERNKEEPER_API_(?:ENDPOINT|KEY)\b|TAVERNKEEPER_MODEL\b/u;
const sensitiveInputPattern =
  /clone_url|repository_url|endpoint|branch|sha|model|mode|priority|token|budget|command/iu;
const forbiddenRuntimePattern =
  /deep-scan|tavernkeeper-model-cache|scanner-policy\.v1\.json/iu;

function fail(file, message) {
  failures.push(`${file}: ${message}`);
}

function containsOnlyCanonicalPublisherPush(
  run,
  expectedLines = canonicalPublisherPushLines,
) {
  const lines = run.split("\n");
  const start = lines.findIndex((line) => line.trim() === expectedLines[0]);
  if (start < 0) return false;
  const indentation = /^\s*/u.exec(lines[start])?.[0] ?? "";
  const hasCanonicalBlock = expectedLines.every(
    (line, index) => lines[start + index] === `${indentation}${line}`,
  );
  if (!hasCanonicalBlock) return false;

  lines.splice(start, expectedLines.length);
  const residualCommandShape = lines
    .join("\n")
    .replace(/[^a-z]/giu, "")
    .toLowerCase();
  return !residualCommandShape.includes("push");
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
  if (!same(Object.keys(jobs).sort(), Object.keys(expected.jobs).sort())) {
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
  for (const { name } of references)
    if (!approvedWorkflowSecretNames.has(name))
      fail(file, `unapproved workflow secret ${name}`);

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
  for (const location of locationsMatching(workflow, providerSecretPattern)) {
    const stepIndex = location.path[3];
    const step = Number.isInteger(stepIndex)
      ? workflow.jobs?.[location.path[1]]?.steps?.[stepIndex]
      : undefined;
    const approved =
      (file === "scan-and-publish.yml" &&
        step?.name === "Contextually assess scanner evidence") ||
      (file === "provider-check.yml" &&
        step?.name === "Check one benign contextual review");
    if (!approved)
      fail(file, "model provider secret appears outside a review-only step");
  }
}

function checkContextualRuntime(file, workflow) {
  if (forbiddenRuntimePattern.test(JSON.stringify(workflow)))
    fail(file, "removed legacy scan runtime resurfaced");
  if (file === "scan-and-publish.yml") {
    const steps = workflow.jobs?.scan?.steps ?? [];
    const prepareIndex = steps.findIndex(
      (step) =>
        step?.name === "Prepare exact target and scanner evidence" &&
        step?.run === "npm run --silent prepare-target",
    );
    const reviewIndex = steps.findIndex(
      (step) =>
        step?.name === "Contextually assess scanner evidence" &&
        step?.run === canonicalContextualReviewRun,
    );
    const finalizeIndex = steps.findIndex(
      (step) =>
        step?.name === "Finalize contextual V5 report" &&
        step?.run === "npm run --silent finalize-target -- candidate.json",
    );
    if (
      prepareIndex < 0 ||
      reviewIndex !== prepareIndex + 1 ||
      finalizeIndex !== reviewIndex + 1 ||
      steps[reviewIndex]?.["timeout-minutes"] !== 42
    )
      fail(
        file,
        "contextual review must remain bounded between preparation and V5 finalization",
      );
  }
  if (file === "provider-check.yml") {
    const steps = workflow.jobs?.check?.steps ?? [];
    const check = steps.filter(
      (step) =>
        step?.name === "Check one benign contextual review" &&
        step?.run === "npm run --silent provider:check",
    );
    if (
      check.length !== 1 ||
      /publish|candidate\.json|git push/iu.test(JSON.stringify(workflow))
    )
      fail(
        file,
        "provider check must make one non-publishing contextual request",
      );
  }
}

function checkEncryptedHandoff(file, workflow) {
  if (file !== "scan-and-publish.yml") return;
  const steps = workflow.jobs?.scan?.steps ?? [];
  const bootstrap = steps[0];
  if (
    bootstrap?.name !== "Initialize encrypted bootstrap failure" ||
    bootstrap?.env?.TAVERNKEEPER_ARTIFACT_KEY !== artifactSecret ||
    bootstrap?.env?.TAVERNKEEPER_BOOTSTRAP_OUTCOME !==
      "${{ runner.temp }}/tavernkeeper-outcome-${{ matrix.request.repository_id }}.enc" ||
    !bootstrap?.run?.includes("SCAN_BOOTSTRAP_FAILED") ||
    !bootstrap?.run?.includes("aes-256-gcm") ||
    !bootstrap?.run?.includes("TAVERNKEEPER_BOOTSTRAP_OUTCOME")
  )
    fail(file, "scan must initialize an encrypted failure before setup");
  const uploads = steps.filter(
    (step) =>
      typeof step?.uses === "string" &&
      step.uses.startsWith("actions/upload-artifact@"),
  );
  if (
    uploads.length !== 1 ||
    uploads[0]?.uses !== uploadArtifactAction ||
    uploads[0]?.if !== "always()" ||
    uploads[0]?.with?.path !==
      "${{ runner.temp }}/tavernkeeper-outcome-${{ matrix.request.repository_id }}.enc" ||
    uploads[0]?.with?.["retention-days"] !== 1
  )
    fail(
      file,
      "scan artifact upload must always retain only outcome.enc for one day",
    );
  const downloads = (workflow.jobs?.publish?.steps ?? []).filter(
    (step) =>
      typeof step?.uses === "string" &&
      step.uses.startsWith("actions/download-artifact@"),
  );
  if (downloads.length !== 1 || downloads[0]?.uses !== downloadArtifactAction)
    fail(file, "artifact actions must retain the reviewed Node 24 pins");
  const decrypt = (workflow.jobs?.publish?.steps ?? []).find(
    (step) => step?.name === "Decrypt sanitized outcomes",
  );
  if (
    decrypt?.env?.TAVERNKEEPER_SCAN_REQUESTS !==
      "${{ inputs.requests_json }}" ||
    !decrypt?.run?.includes(
      "find encrypted-artifacts -type f -name 'tavernkeeper-outcome-*.enc' -print0",
    ) ||
    !decrypt?.run?.includes('test "$position" -eq "$expected"')
  )
    fail(
      file,
      "publisher must decrypt the exact per-repository artifact batch",
    );
  const encrypt = steps.find(
    (step) => step?.name === "Encrypt sanitized outcome",
  );
  if (
    encrypt?.if !== "always()" ||
    !encrypt?.run?.includes("outcome-actual.enc") ||
    !encrypt?.run?.includes(
      'mv outcome-actual.enc "${{ runner.temp }}/tavernkeeper-outcome-${{ matrix.request.repository_id }}.enc"',
    )
  )
    fail(file, "scan must atomically replace the bootstrap failure outcome");
  if (workflow.jobs?.scan?.strategy?.["max-parallel"] !== 2)
    fail(file, "scan matrix must retain max-parallel: 2");
  if (workflow.jobs?.scan?.strategy?.["fail-fast"] !== false)
    fail(file, "scan matrix must finish every selected repository");
  const dependencies = steps.find(
    (step) => step?.name === "Install dependencies",
  );
  const toolchain = steps.find(
    (step) => step?.name === "Install and verify pinned scanners",
  );
  const toolchainFailure = steps.find(
    (step) => step?.name === "Record shared scanner toolchain failure",
  );
  const prepare = steps.find(
    (step) => step?.name === "Prepare exact target and scanner evidence",
  );
  if (
    dependencies?.["continue-on-error"] !== true ||
    toolchain?.["continue-on-error"] !== true ||
    !toolchainFailure?.run?.includes("SCANNER_UNAVAILABLE") ||
    !prepare?.if?.includes("steps.toolchain.outcome == 'success'")
  )
    fail(
      file,
      "scanner setup failures must retain an authenticated shared outcome",
    );

  const publishJob = workflow.jobs?.publish;
  const publish = (publishJob?.steps ?? []).find(
    (step) => step?.name === "Publish serialized batch",
  );
  const publishRun = publish?.run ?? "";
  if (
    publish?.id !== "publish" ||
    publish?.shell !== "bash" ||
    publish?.env?.TAVERNKEEPER_SCAN_REQUESTS !==
      "${{ inputs.requests_json }}" ||
    !publishRun.includes(
      `reports="$(jq -er '.reports | select(type == "number")' <<< "$result")"`,
    ) ||
    !publishRun.includes("failures") ||
    !publishRun.includes("queue_remaining") ||
    !publishRun.includes("queue_due") ||
    !publishRun.includes("queue_delayed") ||
    !publishRun.includes("next_wake_at") ||
    !publishRun.includes("chronic_failures") ||
    /target_failures|shared_holds|security_holds|continuation_blocked|terminal_failures/u.test(
      publishRun,
    ) ||
    !publishRun.includes(
      `printf 'reports=%s\\n' "$reports" >> "$GITHUB_OUTPUT"`,
    ) ||
    /echo .*jq/iu.test(publishRun) ||
    publishJob?.if !== "${{ always() }}" ||
    publishJob?.outputs?.reports !== "${{ steps.publish.outputs.reports }}" ||
    publishJob?.outputs?.queue_remaining !==
      "${{ steps.publish.outputs.queue_remaining }}" ||
    publishJob?.outputs?.chronic_failures !==
      "${{ steps.publish.outputs.chronic_failures }}"
  )
    fail(
      file,
      "publisher must authenticate every decrypted outcome against the requested batch and expose typed routing outputs",
    );

  if (
    workflow.jobs?.deploy?.if !==
    "${{ always() && needs.publish.result == 'success' && needs.publish.outputs.reports != '0' }}"
  )
    fail(file, "deployment must accept a successful mixed-batch publisher");

  const continuation = workflow.jobs?.continue;
  if (
    continuation?.needs !== "publish" ||
    !continuation?.if?.includes(
      "needs.publish.outputs.queue_remaining != '0'",
    ) ||
    /needs\.scan\.result|system_failure/u.test(continuation?.if ?? "")
  )
    fail(
      file,
      "persisted queue work must continue independently of deployment",
    );
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
  const pushRun = pushStep?.run ?? "";
  if (
    file === "staff-operations.yml" &&
    (!same(workflow.concurrency, {
      group: "tavernkeeper-staff-operations",
      queue: "max",
      "cancel-in-progress": false,
    }) ||
      !same(pushStep?.env, {
        GH_TOKEN: publisherToken,
        OPERATION: "${{ inputs.operation }}",
        REPOSITORY_ID: "${{ inputs.repository_id }}",
        REASON_CODE: "${{ inputs.reason_code }}",
      }))
  )
    fail(file, "staff operations must retain their lossless serialized queue");
  if (file === "staff-operations.yml" && pushRun !== canonicalStaffPublisherRun)
    fail(file, "staff operation and Publisher token boundary changed");
  const expectedPushLines =
    file === "staff-operations.yml"
      ? canonicalStaffPublisherPushLines
      : canonicalPublisherPushLines;
  if (!containsOnlyCanonicalPublisherPush(pushRun, expectedPushLines))
    fail(
      file,
      "Publisher-authenticated push must retain one canonical bounded retry block",
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
  if (!same(inputs, ["repository_id"]))
    fail(file, "targeted workflow accepts more than repository_id");
  const condition = workflow.jobs?.enqueue?.if ?? "";
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

function checkDelayedWake(file, workflow) {
  if (file === "reconcile.yml") {
    const schedule = (workflow.jobs?.plan?.steps ?? []).find(
      (step) => step?.name === "Schedule deterministic delayed wake",
    );
    if (
      !schedule?.if?.includes(
        "fromJSON(steps.plan.outputs.requests_json)[0] == null",
      ) ||
      !schedule.if.includes("steps.plan.outputs.total_remaining != '0'") ||
      !schedule.if.includes("steps.plan.outputs.next_wake_at != ''") ||
      schedule?.env?.TAVERNKEEPER_WAKE_AT !==
        "${{ steps.plan.outputs.next_wake_at }}" ||
      schedule?.run !==
        'gh workflow run delayed-wake.yml --repo "$GITHUB_REPOSITORY" --ref main -f wake_at="$TAVERNKEEPER_WAKE_AT"'
    )
      fail(file, "idle durable work must schedule its exact next wake");
  }
  if (file === "delayed-wake.yml") {
    const wait = (workflow.jobs?.wake?.steps ?? []).find(
      (step) => step?.name === "Wait for bounded wake time",
    );
    const dispatch = (workflow.jobs?.wake?.steps ?? []).find(
      (step) => step?.name === "Dispatch reconciliation",
    );
    if (
      !same(Object.keys(workflow.on?.workflow_dispatch?.inputs ?? {}), [
        "wake_at",
      ]) ||
      workflow.on?.workflow_dispatch?.inputs?.wake_at?.required !== true ||
      !same(workflow.concurrency, {
        group: "tavernkeeper-delayed-wake",
        "cancel-in-progress": true,
      }) ||
      workflow.jobs?.wake?.["timeout-minutes"] !== 345 ||
      !wait?.run?.includes("new Date(wakeMs).toISOString() !== wakeAt") ||
      !wait?.run?.includes("Math.min(20_400") ||
      dispatch?.run !==
        'gh workflow run reconcile.yml --repo "$GITHUB_REPOSITORY" --ref main'
    )
      fail(file, "delayed wake must be validated, bounded, and resumable");
  }
}

const names = (await readdir(workflowRoot))
  .filter((name) => /\.ya?ml$/u.test(name))
  .sort();
if (!same(names, Object.keys(allowedTriggers).sort()))
  fail(
    ".github/workflows",
    "workflow file set changed from the reviewed allowlist",
  );

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
  checkContextualRuntime(file, workflow);
  checkEncryptedHandoff(file, workflow);
  checkPublisherBoundary(file, workflow);
  checkTargetedAuthority(file, workflow);
  checkScannerToolchain(file, workflow);
  checkDelayedWake(file, workflow);
}

const policyFile = "config/scanner-policy.v3.json";
const policy = JSON.parse(await readFile(join(root, policyFile), "utf8"));
if (policy.version !== "3") fail(policyFile, "policy version must remain 3");
if (policy.queue?.batchSize !== 5)
  fail(policyFile, "queue batchSize must remain exactly 5");
if (policy.queue?.maxParallel !== 2)
  fail(policyFile, "queue maxParallel must remain exactly 2");

if (failures.length > 0) {
  for (const failure of failures) process.stderr.write(`${failure}\n`);
  process.exitCode = 1;
} else {
  process.stdout.write(
    `Workflow policy passed for ${names.length} workflows.\n`,
  );
}
