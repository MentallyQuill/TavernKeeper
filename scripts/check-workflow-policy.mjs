import { readFile, readdir } from "node:fs/promises";
import { join } from "node:path";

import { parse } from "yaml";

const root = process.cwd();
const workflowRoot = join(root, ".github", "workflows");
const failures = [];
const publisherAction =
  "actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1";
const publisherClientId = "${{ vars.TAVERNKEEPER_PUBLISHER_CLIENT_ID }}";
const publisherPrivateKey =
  "${{ secrets.TAVERNKEEPER_PUBLISHER_APP_PRIVATE_KEY }}";
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
const canonicalCoverageCampaignPushLines = [
  'push_succeeded="false"',
  "if ! commit_campaign; then",
  '  push_succeeded="true"',
  "else",
  "  for attempt in 1 2 3; do",
  "    if git push origin HEAD:main; then",
  '      push_succeeded="true"',
  "      break",
  "    fi",
  '    if [[ "$attempt" -lt 3 ]]; then',
  '      sleep "$((attempt * 15))"',
  '      env -u GH_TOKEN GITHUB_TOKEN="$SELECTION_TOKEN" git fetch origin main',
  "      git reset --hard origin/main",
  "      run_operation",
  "      if ! commit_campaign; then",
  '        push_succeeded="true"',
  "        break",
  "      fi",
  "    fi",
  "  done",
  "fi",
  'test "$push_succeeded" = "true"',
];
const canonicalClaimPushLines = [
  'push_succeeded="false"',
  "for attempt in 1 2 3; do",
  "  git fetch origin main",
  "  git reset --hard origin/main",
  "  run_claim",
  "  if ! commit_claim; then",
  '    push_succeeded="true"',
  "    break",
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
const canonicalPublicationReplayPushLines = [
  'push_succeeded="false"',
  "for attempt in 1 2 3; do",
  "  if git push origin HEAD:main; then",
  '    push_succeeded="true"',
  "    break",
  "  fi",
  '  if [[ "$attempt" -lt 3 ]]; then',
  '    sleep "$((attempt * 15))"',
  "    git fetch origin main",
  "    git reset --hard origin/main",
  "    run_publication",
  "    if ! commit_publication; then",
  '      push_succeeded="true"',
  "      break",
  "    fi",
  "  fi",
  "done",
  'test "$push_succeeded" = "true"',
];
const canonicalProviderProbePushLines = [
  'push_succeeded="false"',
  "for attempt in 1 2 3; do",
  "  if git push origin HEAD:main; then",
  '    push_succeeded="true"',
  "    break",
  "  fi",
  '  if [[ "$attempt" -lt 3 ]]; then',
  '    sleep "$((attempt * 15))"',
  "    git fetch origin main",
  "    git reset --hard origin/main",
  "    run_operation",
  "    git add operations/state.json",
  "    if git diff --cached --quiet; then",
  '      push_succeeded="true"',
  "      break",
  "    fi",
  '    git commit -m "chore(ops): record provider recovery probe"',
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
    '  elif [[ "$OPERATION" = "retry" || "$OPERATION" = "revoke" || "$OPERATION" = "add-back" ]]; then',
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
const canonicalCoverageCampaignPublisherRun =
  [
    "run_operation() {",
    '  env -u GH_TOKEN GITHUB_TOKEN="$SELECTION_TOKEN" npm run --silent coverage-campaign',
    "}",
    "commit_campaign() {",
    "  if git diff --quiet -- operations/state.json; then",
    "    return 1",
    "  fi",
    "  git add operations/state.json",
    '  git commit -m "chore(scans): schedule one-time coverage"',
    "}",
    "",
    "gh auth setup-git",
    'git config user.name "TavernKeeper"',
    'git config user.email "tavernkeeper@users.noreply.github.com"',
    ...canonicalCoverageCampaignPushLines,
  ].join("\n") + "\n";
const canonicalContextualReviewRun = String.raw`progress_count() {
  node scripts/contextual-review-progress-count.mjs "$TAVERNKEEPER_SESSION_ROOT/review-progress.json"
}
run_review() {
  rm -f review-result.json
  node -e 'require("node:fs").writeFileSync("phase-error.json", JSON.stringify({code:"MODEL_REVIEW_TIMEOUT",domain:"target",component:"contextual-model"}) + "\n", {flag:"wx"})'
  if timeout --signal=TERM --kill-after=5s 20m npm run --silent review-target > review-result.json; then
    rm -f phase-error.json
    return 0
  fi
  return 1
}
retryable_review_failure() {
  jq -e '(.code == "MODEL_PROVIDER" and .domain == "shared" and .component == "contextual-model") or (.code == "MODEL_QUOTA" and .domain == "shared" and .component == "contextual-model") or (.code == "MODEL_REVIEW_TIMEOUT" and .domain == "target" and .component == "contextual-model")' phase-error.json >/dev/null
}
provider_review_failure() {
  jq -e '.code == "MODEL_PROVIDER" and .domain == "shared" and .component == "contextual-model"' phase-error.json >/dev/null
}
quota_review_failure() {
  jq -e '.code == "MODEL_QUOTA" and .domain == "shared" and .component == "contextual-model"' phase-error.json >/dev/null
}
budget_review_failure() {
  jq -e '.code == "MODEL_REVIEW_BUDGET_EXCEEDED" and .domain == "target" and .component == "contextual-model"' phase-error.json >/dev/null
}
provider_no_progress_retries="0"
for pass in $(seq 1 64); do
  progress_before="$(progress_count)"
  if run_review; then
    review_status="$(jq -er '.status' review-result.json)"
    if [[ "$review_status" == "review_pending" ]]; then
      continue
    fi
    if [[ "$review_status" == "reviewed" ]]; then
      exit 0
    fi
    exit 1
  fi
  progress_after="$(progress_count)"
  if budget_review_failure; then
    exit 1
  fi
  if ! retryable_review_failure || [[ "$pass" -eq 64 ]]; then
    exit 1
  fi
  if [[ "$progress_after" -gt "$progress_before" ]]; then
    if quota_review_failure; then
      rm -f phase-error.json
      sleep "$((pass * 60))"
    else
      rm -f phase-error.json
      sleep "$((pass * 5))"
    fi
    continue
  fi
  if provider_review_failure && [[ "$provider_no_progress_retries" -lt 1 ]]; then
    provider_no_progress_retries="$((provider_no_progress_retries + 1))"
    rm -f phase-error.json
    sleep "$((pass * 5))"
    continue
  fi
  exit 1
done
exit 1
`;
const canonicalProviderProbeOutcomeRun = String.raw`operation="provider-probe-failure"
if [[ "$TAVERNKEEPER_PROBE_OUTCOME" = "success" ]] || npm run --silent probe-outcome -- phase-error.json >/dev/null 2>&1; then
  operation="provider-probe-success"
fi
probed_at="$(date -u +%Y-%m-%dT%H:%M:%S.%3NZ)"
request="$(jq -nc --arg operation "$operation" --arg error_fingerprint "$TAVERNKEEPER_PROBE_FINGERPRINT" --arg probed_at "$probed_at" '{operation:$operation,error_fingerprint:$error_fingerprint,probed_at:$probed_at}')"
echo "request=$request" >> "$GITHUB_OUTPUT"
env -u GH_TOKEN -u GITHUB_TOKEN TAVERNKEEPER_OPERATION="$request" npm run --silent retry
`;
const artifactSecret = "${{ secrets.TAVERNKEEPER_ARTIFACT_KEY }}";

const allowedTriggers = {
  "ci.yml": ["pull_request", "push"],
  "coverage-campaign.yml": ["workflow_dispatch"],
  "delayed-wake.yml": ["workflow_dispatch"],
  "deploy-pages.yml": ["workflow_call", "workflow_dispatch"],
  "pages-reconcile.yml": ["schedule", "workflow_dispatch"],
  "policy-rescan.yml": ["workflow_dispatch"],
  "prepare-diagnostic.yml": ["workflow_dispatch"],
  "provider-check.yml": ["workflow_dispatch"],
  "publisher-verification.yml": ["workflow_dispatch"],
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
  "coverage-campaign.yml": {
    workflow: { contents: "read", actions: "write" },
    jobs: { create: { contents: "read", actions: "write" } },
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
  "prepare-diagnostic.yml": {
    workflow: { contents: "read" },
    jobs: { prepare: { contents: "read" } },
  },
  "provider-check.yml": {
    workflow: { contents: "read" },
    jobs: { authorize: {}, check: { contents: "read" } },
  },
  "publisher-verification.yml": {
    workflow: { contents: "read" },
    jobs: {
      "verify-scanner": { contents: "read" },
      "verify-staff": { contents: "read" },
    },
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
      claim: { contents: "read", actions: "write", issues: "write" },
      "probe-provider": { contents: "read", actions: "write" },
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
      prepare: { contents: "read" },
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
  "coverage-campaign.yml",
  "policy-rescan.yml",
  "provider-check.yml",
  "release-holds.yml",
  "staff-operations.yml",
]);
const mutationJobs = {
  "coverage-campaign.yml": [
    { job: "create", environment: "tavernkeeper-staff" },
  ],
  "policy-rescan.yml": [{ job: "schedule", environment: "tavernkeeper-staff" }],
  "publisher-verification.yml": [
    { job: "verify-scanner", environment: "tavernkeeper-scanner" },
    { job: "verify-staff", environment: "tavernkeeper-staff" },
  ],
  "reconcile.yml": [
    { job: "claim", environment: "tavernkeeper-scanner" },
    { job: "probe-provider", environment: "tavernkeeper-scanner" },
  ],
  "scan-and-publish.yml": [
    {
      job: "publish",
      environment: "tavernkeeper-scanner",
    },
  ],
  "release-holds.yml": [
    {
      job: "release",
      environment: "tavernkeeper-staff",
    },
  ],
  "staff-operations.yml": [
    {
      job: "operate",
      environment: "tavernkeeper-staff",
    },
  ],
  "targeted-scan.yml": [
    {
      job: "enqueue",
      environment: "tavernkeeper-scanner",
    },
  ],
};
const approvedWorkflowSecretNames = new Set([
  "JSONREPAIR_API_ENDPOINT",
  "JSONREPAIR_API_KEY",
  "JSONREPAIR_MODEL",
  "TAVERNKEEPER_ARTIFACT_KEY",
  "TAVERNKEEPER_API_ENDPOINT",
  "TAVERNKEEPER_API_KEY",
  "TAVERNKEEPER_MODEL",
  "TAVERNKEEPER_PUBLISHER_APP_PRIVATE_KEY",
  "TAVERNARY_WAKE_APP_ID",
  "TAVERNARY_WAKE_APP_PRIVATE_KEY",
]);
const publisherCredentialPattern =
  /TAVERNKEEPER_PUBLISHER_(?:CLIENT_ID|APP_PRIVATE_KEY|APP_ID)\b/u;
const legacyPublisherAppIdPattern = /TAVERNKEEPER_PUBLISHER_APP_ID\b/u;
const artifactSecretPattern = /TAVERNKEEPER_ARTIFACT_KEY\b/u;
const providerSecretPattern =
  /TAVERNKEEPER_API_(?:ENDPOINT|KEY)\b|TAVERNKEEPER_MODEL\b/u;
const jsonRepairSecretPattern = /JSONREPAIR_(?:API_ENDPOINT|API_KEY|MODEL)\b/u;
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
  if (legacyPublisherAppIdPattern.test(JSON.stringify(workflow)))
    fail(file, "legacy Publisher App ID credential is not allowed");
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
        "Decrypt sanitized outcome",
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
        step?.name === "Check one benign contextual review") ||
      (file === "reconcile.yml" &&
        step?.name === "Check benign provider compatibility");
    if (!approved)
      fail(file, "model provider secret appears outside a review-only step");
  }
  for (const location of locationsMatching(workflow, jsonRepairSecretPattern)) {
    const stepIndex = location.path[3];
    const step = Number.isInteger(stepIndex)
      ? workflow.jobs?.[location.path[1]]?.steps?.[stepIndex]
      : undefined;
    const approved =
      (file === "scan-and-publish.yml" &&
        step?.name === "Contextually assess scanner evidence") ||
      (file === "provider-check.yml" &&
        step?.name === "Check one synthetic JSON repair");
    if (!approved)
      fail(file, "JSON repair secret appears outside a repair-only step");
  }
}

function checkContextualRuntime(file, workflow) {
  if (forbiddenRuntimePattern.test(JSON.stringify(workflow)))
    fail(file, "removed legacy scan runtime resurfaced");
  if (file === "scan-and-publish.yml") {
    const prepareSteps = workflow.jobs?.prepare?.steps ?? [];
    const reviewSteps = workflow.jobs?.scan?.steps ?? [];
    const prepareIndex = prepareSteps.findIndex(
      (step) =>
        step?.name === "Prepare exact target and scanner evidence" &&
        step?.run === "npm run --silent prepare-target",
    );
    const reviewIndex = reviewSteps.findIndex(
      (step) =>
        step?.name === "Contextually assess scanner evidence" &&
        step?.run === canonicalContextualReviewRun,
    );
    const finalizeIndex = reviewSteps.findIndex(
      (step) =>
        step?.name === "Finalize contextual V5 report" &&
        step?.run === "npm run --silent finalize-target -- candidate.json",
    );
    if (
      prepareIndex < 0 ||
      finalizeIndex !== reviewIndex + 1 ||
      reviewSteps[reviewIndex]?.["timeout-minutes"] !== 65
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
    const repair = steps.filter(
      (step) =>
        step?.name === "Check one synthetic JSON repair" &&
        step?.run === "npm run --silent jsonrepair:check",
    );
    if (
      check.length !== 1 ||
      repair.length !== 1 ||
      /publish|candidate\.json|git push/iu.test(JSON.stringify(workflow))
    )
      fail(
        file,
        "provider check must make one contextual and one JSON-repair-only request",
      );
  }
  if (file === "reconcile.yml") {
    const job = workflow.jobs?.["probe-provider"];
    const checks = (job?.steps ?? []).filter(
      (step) =>
        step?.name === "Check benign provider compatibility" &&
        step?.run === "npm run --silent provider:check",
    );
    if (
      checks.length !== 1 ||
      checks[0]?.["continue-on-error"] !== true ||
      checks[0]?.["timeout-minutes"] !== 5 ||
      /prepare-target|review-target|finalize-target|candidate\.json/iu.test(
        JSON.stringify(job),
      )
    )
      fail(
        file,
        "automatic provider probe must remain bounded and target-free",
      );
    const outcome = (job?.steps ?? []).find(
      (step) => step?.name === "Apply provider probe outcome",
    );
    if (outcome?.run !== canonicalProviderProbeOutcomeRun)
      fail(file, "provider probe outcome classifier changed");
  }
}

function checkEncryptedHandoff(file, workflow) {
  if (file !== "scan-and-publish.yml") return;
  const steps = workflow.jobs?.scan?.steps ?? [];
  const prepareSteps = workflow.jobs?.prepare?.steps ?? [];
  const repositoryExpression =
    "${{ fromJSON(inputs.request_json).repository_id }}";
  const bootstrap = steps[0];
  if (
    bootstrap?.name !== "Initialize encrypted bootstrap failure" ||
    bootstrap?.env?.TAVERNKEEPER_ARTIFACT_KEY !== artifactSecret ||
    bootstrap?.env?.TAVERNKEEPER_BOOTSTRAP_OUTCOME !==
      `${"${{ runner.temp }}"}/tavernkeeper-outcome-${repositoryExpression}.enc` ||
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
      `${"${{ runner.temp }}"}/tavernkeeper-outcome-${repositoryExpression}.enc` ||
    uploads[0]?.with?.["retention-days"] !== 1
  )
    fail(
      file,
      "scan artifact upload must always retain only outcome.enc for one day",
    );
  const preparedUploads = prepareSteps.filter(
    (step) =>
      typeof step?.uses === "string" &&
      step.uses.startsWith("actions/upload-artifact@"),
  );
  if (
    preparedUploads.length !== 1 ||
    preparedUploads[0]?.uses !== uploadArtifactAction ||
    preparedUploads[0]?.if !== "always()" ||
    preparedUploads[0]?.with?.name !== `prepared-${repositoryExpression}` ||
    preparedUploads[0]?.with?.path !==
      `${"${{ runner.temp }}"}/tavernkeeper-prepared-${repositoryExpression}` ||
    preparedUploads[0]?.with?.["retention-days"] !== 1
  )
    fail(
      file,
      "prepare must upload one bounded per-repository artifact for one day",
    );
  const pack = prepareSteps.find(
    (step) => step?.name === "Package bounded prepared evidence",
  );
  const packageFailure = prepareSteps.find(
    (step) => step?.name === "Package sanitized preparation failure",
  );
  const markPreparationFailure = prepareSteps.find(
    (step) =>
      step?.name === "Mark failed preparation after preserving the handoff",
  );
  if (
    pack?.id !== "pack" ||
    pack?.["continue-on-error"] !== true ||
    pack?.env?.TAVERNKEEPER_ERROR_OUTPUT !== "phase-error.json" ||
    !pack?.run?.includes("prepared_bytes") ||
    !pack?.run?.includes("evidence_bytes") ||
    !pack?.run?.includes("prepared-evidence -- pack") ||
    !packageFailure?.if?.includes("steps.pack.outcome != 'success'") ||
    !markPreparationFailure?.if?.includes("steps.pack.outcome != 'success'")
  )
    fail(file, "prepare must preserve a sanitized pack-failure artifact");
  const preparedDownloads = steps.filter(
    (step) =>
      typeof step?.uses === "string" &&
      step.uses.startsWith("actions/download-artifact@"),
  );
  if (
    preparedDownloads.length !== 1 ||
    preparedDownloads[0]?.uses !== downloadArtifactAction ||
    preparedDownloads[0]?.with?.name !== `prepared-${repositoryExpression}`
  )
    fail(file, "review must download only its bounded prepared artifact");
  const downloads = (workflow.jobs?.publish?.steps ?? []).filter(
    (step) =>
      typeof step?.uses === "string" &&
      step.uses.startsWith("actions/download-artifact@"),
  );
  if (
    downloads.length !== 1 ||
    downloads[0]?.uses !== downloadArtifactAction ||
    downloads[0]?.with?.name !== `scan-${repositoryExpression}` ||
    downloads[0]?.with?.pattern !== undefined
  )
    fail(file, "artifact actions must retain the reviewed Node 24 pins");
  const decrypt = (workflow.jobs?.publish?.steps ?? []).find(
    (step) => step?.name === "Decrypt sanitized outcome",
  );
  if (
    decrypt?.env?.TAVERNKEEPER_ARTIFACT_KEY !== artifactSecret ||
    !decrypt?.run?.includes(
      `encrypted-artifact/tavernkeeper-outcome-${repositoryExpression}.enc`,
    ) ||
    decrypt?.run?.includes("find encrypted-artifacts")
  )
    fail(
      file,
      "publisher must decrypt exactly its requested repository artifact",
    );
  const encrypt = steps.find(
    (step) => step?.name === "Encrypt sanitized outcome",
  );
  if (
    encrypt?.if !== "always()" ||
    !encrypt?.run?.includes("outcome-actual.enc") ||
    !encrypt?.run?.includes(
      `mv outcome-actual.enc "${"${{ runner.temp }}"}/tavernkeeper-outcome-${repositoryExpression}.enc"`,
    )
  )
    fail(file, "scan must atomically replace the bootstrap failure outcome");
  if (
    workflow.jobs?.scan?.strategy !== undefined ||
    workflow.jobs?.prepare?.strategy !== undefined ||
    workflow.jobs?.prepare?.["timeout-minutes"] !== 30 ||
    workflow.jobs?.scan?.["timeout-minutes"] !== 90
  )
    fail(file, "single-target child jobs must retain bounded timeouts");
  if (workflow.jobs?.scan?.needs !== "prepare")
    fail(file, "review must wait for preparation");
  if (
    JSON.stringify(workflow.jobs?.prepare).match(
      /secrets\.|TAVERNKEEPER_API_|TAVERNKEEPER_MODEL|JSONREPAIR_|TAVERNKEEPER_ARTIFACT_KEY|TAVERNKEEPER_PUBLISHER/iu,
    )
  )
    fail(file, "preparation must remain credential-free");
  if (
    JSON.stringify(workflow.jobs?.scan).includes("TAVERNKEEPER_CHECKOUT_ROOT")
  )
    fail(file, "review must not receive a target checkout path");
  const dependencies = prepareSteps.find(
    (step) => step?.name === "Install dependencies",
  );
  const toolchain = prepareSteps.find(
    (step) => step?.name === "Install and verify pinned scanners",
  );
  const toolchainFailure = prepareSteps.find(
    (step) => step?.name === "Record shared scanner toolchain failure",
  );
  const prepare = prepareSteps.find(
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
    (step) => step?.name === "Publish serialized target",
  );
  const publishRun = publish?.run ?? "";
  if (
    publish?.id !== "publish" ||
    publish?.shell !== "bash" ||
    publish?.env?.TAVERNKEEPER_SCAN_REQUEST !== "${{ inputs.request_json }}" ||
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
      "publisher must authenticate its decrypted target and expose typed routing outputs",
    );

  if (
    workflow.jobs?.deploy?.if !==
    "${{ always() && needs.publish.result == 'success' && needs.publish.outputs.reports != '0' }}"
  )
    fail(file, "deployment must accept each successful target publisher");

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
  const mutations = mutationJobs[file];
  const jobsWithPublisherCredentials = Object.entries(workflow.jobs ?? {})
    .filter(([, job]) => publisherCredentialPattern.test(JSON.stringify(job)))
    .map(([jobName]) => jobName);
  if (mutations === undefined) {
    if (jobsWithPublisherCredentials.length > 0)
      fail(
        file,
        "Publisher App credential appears outside a mutation workflow",
      );
    return;
  }
  const mutationJobNames = new Set(mutations.map(({ job }) => job));
  if (jobsWithPublisherCredentials.some((job) => !mutationJobNames.has(job)))
    fail(file, "Publisher App credential appears outside a mutation job");
  for (const mutation of mutations) {
    const job = workflow.jobs?.[mutation.job];
    if (job?.environment !== mutation.environment)
      fail(file, `${mutation.job} must use ${mutation.environment}`);
    const steps = job?.steps ?? [];
    const tokenSteps = steps.filter((step) =>
      JSON.stringify(step).match(publisherCredentialPattern),
    );
    const tokenStep = tokenSteps[0];
    if (
      tokenSteps.length !== 1 ||
      tokenStep?.name !== "Create TavernKeeper Publisher token" ||
      tokenStep?.id !== "publisher-token" ||
      tokenStep?.uses !== publisherAction ||
      tokenStep?.with?.["client-id"] !== publisherClientId ||
      tokenStep?.with?.["private-key"] !== publisherPrivateKey ||
      tokenStep?.with?.["app-id"] !== undefined ||
      tokenStep?.with?.["skip-token-revoke"] !== undefined ||
      tokenStep?.with?.owner !== "MentallyQuill" ||
      tokenStep?.with?.repositories !== "TavernKeeper" ||
      tokenStep?.with?.["permission-contents"] !== "write"
    )
      fail(file, "Publisher App token step changed from the reviewed contract");
    const consumers = [];
    walk(job, (value, path) => {
      if (typeof value === "string" && value.includes(publisherToken))
        consumers.push(path);
    });
    const pushStep = steps.find(
      (step) =>
        typeof step?.run === "string" &&
        step.run.includes("git push origin HEAD:main"),
    );
    const expectedConsumer = [
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
      fail(
        file,
        "staff operations must retain their lossless serialized queue",
      );
    if (
      file === "staff-operations.yml" &&
      pushRun !== canonicalStaffPublisherRun
    )
      fail(file, "staff operation and Publisher token boundary changed");
    if (
      file === "coverage-campaign.yml" &&
      pushRun !== canonicalCoverageCampaignPublisherRun
    )
      fail(file, "coverage selection and Publisher token boundary changed");
    const expectedPushLines =
      file === "coverage-campaign.yml"
        ? canonicalCoverageCampaignPushLines
        : file === "reconcile.yml" && mutation.job === "claim"
          ? canonicalClaimPushLines
          : file === "reconcile.yml" && mutation.job === "probe-provider"
            ? canonicalProviderProbePushLines
            : file === "scan-and-publish.yml"
              ? canonicalPublicationReplayPushLines
              : file === "staff-operations.yml"
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
}

function checkPublisherVerification(file, workflow) {
  if (file !== "publisher-verification.yml") return;
  const ownerMainGuard =
    "${{ github.actor_id == 2625904 && github.ref == 'refs/heads/main' }}";
  const scanner = workflow.jobs?.["verify-scanner"];
  const staff = workflow.jobs?.["verify-staff"];
  if (
    Object.keys(workflow.on?.workflow_dispatch?.inputs ?? {}).length !== 0 ||
    !same(workflow.concurrency, {
      group: "tavernkeeper-publisher-verification",
      "cancel-in-progress": false,
    }) ||
    scanner?.if !== ownerMainGuard ||
    staff?.if !== ownerMainGuard ||
    scanner?.needs !== undefined ||
    staff?.needs !== "verify-scanner"
  )
    fail(
      file,
      "Publisher verification must remain owner-only, serialized, and sequential",
    );
  for (const job of [scanner, staff]) {
    const steps = job?.steps ?? [];
    const checkout = steps.find(
      (step) =>
        typeof step?.uses === "string" &&
        step.uses.startsWith("actions/checkout@"),
    );
    const push = steps.find(
      (step) =>
        typeof step?.run === "string" &&
        step.run.includes("git push origin HEAD:main"),
    );
    if (
      checkout?.with?.ref !== "main" ||
      checkout?.with?.["persist-credentials"] !== false ||
      !push?.run?.includes("git commit --allow-empty")
    )
      fail(file, "Publisher verification must make an empty commit from main");
  }
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

function checkPreparationDiagnostic(file, workflow) {
  if (file !== "prepare-diagnostic.yml") return;
  const inputs = workflow.on?.workflow_dispatch?.inputs ?? {};
  const job = workflow.jobs?.prepare;
  const steps = job?.steps ?? [];
  const prepare = steps.find(
    (step) => step?.name === "Prepare exact target and scanner evidence",
  );
  const finalize = steps.find(
    (step) => step?.name === "Finalize sanitized preparation diagnostic",
  );
  const cleanup = steps.find(
    (step) => step?.name === "Remove repository preparation data",
  );
  const uploads = steps.filter(
    (step) =>
      typeof step?.uses === "string" &&
      step.uses.startsWith("actions/upload-artifact@"),
  );
  const upload = uploads[0];
  const repositoryExpression =
    "${{ fromJSON(inputs.request_json).repository_id }}";
  const serialized = JSON.stringify(workflow);
  if (
    !same(Object.keys(inputs), ["request_json"]) ||
    inputs.request_json?.type !== "string" ||
    inputs.request_json?.required !== true ||
    job?.if !==
      "${{ github.actor_id == '2625904' && github.ref == 'refs/heads/main' && fromJSON(inputs.request_json) != null }}" ||
    job?.environment !== undefined ||
    job?.["timeout-minutes"] !== 30 ||
    prepare?.run !== "npm run --silent prepare-target" ||
    prepare?.["continue-on-error"] !== true ||
    prepare?.env?.TAVERNKEEPER_ERROR_OUTPUT !== "phase-error.json" ||
    !finalize?.run?.includes("prepared-evidence -- fail") ||
    !finalize?.run?.includes("{status,failure}") ||
    cleanup?.if !== "always()" ||
    cleanup?.id !== "cleanup" ||
    !cleanup?.run?.includes("tavernkeeper-checkout-") ||
    !cleanup?.run?.includes("tavernkeeper-session-") ||
    steps.indexOf(cleanup) >= steps.indexOf(upload) ||
    uploads.length !== 1 ||
    upload?.uses !== uploadArtifactAction ||
    upload?.if !== "${{ always() && steps.cleanup.outcome == 'success' }}" ||
    upload?.with?.name !== `preparation-diagnostic-${repositoryExpression}` ||
    upload?.with?.path !==
      "${{ runner.temp }}/tavernkeeper-preparation-diagnostic/result.json" ||
    upload?.with?.["retention-days"] !== 1 ||
    /TAVERNKEEPER_API_|TAVERNKEEPER_MODEL|JSONREPAIR_|TAVERNKEEPER_ARTIFACT_KEY|TAVERNKEEPER_PUBLISHER|review-target|finalize-target|candidate\.json|git push|reconcile\.yml/iu.test(
      serialized,
    )
  )
    fail(
      file,
      "preparation diagnostic must remain owner-only, model-free, sanitized, and non-mutating",
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
    const schedule = (workflow.jobs?.claim?.steps ?? []).find(
      (step) => step?.name === "Schedule deterministic delayed wake",
    );
    if (
      !schedule?.if?.includes(
        "fromJSON(steps.claim.outputs.requests_json)[0] == null",
      ) ||
      !schedule.if.includes("steps.claim.outputs.total_remaining != '0'") ||
      !schedule.if.includes("steps.claim.outputs.next_wake_at != ''") ||
      schedule?.env?.TAVERNKEEPER_WAKE_AT !==
        "${{ steps.claim.outputs.next_wake_at }}" ||
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
  checkPublisherVerification(file, workflow);
  checkTargetedAuthority(file, workflow);
  checkPreparationDiagnostic(file, workflow);
  checkScannerToolchain(file, workflow);
  checkDelayedWake(file, workflow);
}

const policyFile = "config/scanner-policy.v5.json";
const policy = JSON.parse(await readFile(join(root, policyFile), "utf8"));
if (policy.version !== "5") fail(policyFile, "policy version must remain 5");
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
