# Partial Batch Publication Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Publish every valid repository report from a mixed five-target batch while retrying only unsuccessful targets and preserving the existing system circuit breaker.

**Architecture:** Add a focused artifact-batch publisher that pairs each decrypted transition with its own candidate, records failures, and submits only completed reports to the existing transactional V5 publisher. Update GitHub Actions to finish every matrix target, deploy the serialized publisher commit even after a matrix failure, and suppress ordinary continuation when a system failure engaged the circuit.

**Tech Stack:** Node.js 24, TypeScript 6, Zod 4, Vitest 4, GitHub Actions YAML, Prettier, GitHub CLI.

## Global Constraints

- Keep the batch size at exactly five and `max-parallel` at exactly two.
- Do not change scanner selection, scanner policy, prompts, report construction, report schema, risk synthesis, retry delays, or catalog priority.
- Never publish an incomplete or degraded repository report.
- Keep authenticated encrypted outcome transport, immutable report paths, full-subset prevalidation, rollback, and Publisher App authentication.
- Preserve the existing system circuit breaker and terminal escalation.
- Do not reset Wandlight, Recursion, or any other report history.
- Use red-green-refactor: no production behavior change before its failing test is observed.

---

### Task 1: Publish successful outcomes from mixed batches

**Files:**

- Create: `src/publish/artifact-batch.ts`
- Modify: `src/cli/publish.ts`
- Create: `tests/artifact-batch.test.ts`

**Interfaces:**

- Consumes: `publishCandidates()`, `recordFailure()`, `parseOperationsState()`, `ScanTransitionSchema`, and `ScanReportV5Schema`.
- Produces:

```ts
export type ArtifactBatchStatus = "published" | "partial" | "deferred";

export interface PublishArtifactBatchInput {
  root: string;
  artifactsRoot: string;
  generatedAt: string;
}

export interface PublishArtifactBatchResult {
  status: ArtifactBatchStatus;
  reports: number;
  has_failures: boolean;
  system_failure: boolean;
  terminal_failures: number;
}

export function publishArtifactBatch(
  input: PublishArtifactBatchInput,
): Promise<PublishArtifactBatchResult>;
```

- [ ] **Step 1: Write failing mixed-batch tests**

Create `tests/artifact-batch.test.ts` with temporary-root helpers that write
`operations/state.json`, one outcome directory per transition, and candidate
envelopes shaped as `{ report }`. Cover these assertions with real V5 fixture
reports:

```ts
test("publishes completed reports while recording a system failure", async () => {
  const result = await publishArtifactBatch({
    root,
    artifactsRoot,
    generatedAt: "2026-08-04T04:00:00.000Z",
  });

  expect(result).toEqual({
    status: "partial",
    reports: 2,
    has_failures: true,
    system_failure: true,
    terminal_failures: 0,
  });
  expect(readPublishedRepositoryIds(root)).resolves.toEqual([42, 43]);
  expect(readState(root)).resolves.toMatchObject({
    circuit_breaker: { terminal: false },
    retries: [expect.objectContaining({ repository_id: 44 })],
  });
});

test("defers a failed-only batch without publishing a report", async () => {
  const result = await publishArtifactBatch({
    root,
    artifactsRoot,
    generatedAt,
  });
  expect(result).toMatchObject({
    status: "deferred",
    reports: 0,
    has_failures: true,
    system_failure: true,
  });
});

test("publishes successes beside repository-scoped failures without a breaker", async () => {
  const result = await publishArtifactBatch({
    root,
    artifactsRoot,
    generatedAt,
  });
  expect(result).toMatchObject({
    status: "partial",
    reports: 1,
    has_failures: true,
    system_failure: false,
  });
  expect((await readState(root)).circuit_breaker).toBeNull();
});

test.each([
  [
    "completed transition without candidate",
    "Completed outcome is missing its candidate",
  ],
  [
    "failure transition with candidate",
    "Failed outcome must not contain a candidate",
  ],
])("rejects %s", async (_case, message) => {
  await expect(
    publishArtifactBatch({ root, artifactsRoot, generatedAt }),
  ).rejects.toThrow(message);
});
```

- [ ] **Step 2: Run the focused tests and verify RED**

Run:

```powershell
npm test -- tests/artifact-batch.test.ts
```

Expected: FAIL because `src/publish/artifact-batch.ts` does not exist.

- [ ] **Step 3: Implement the artifact-batch publisher minimally**

Create `src/publish/artifact-batch.ts` with these responsibilities:

```ts
import { access, readdir } from "node:fs/promises";
import { dirname, join } from "node:path";

import { z } from "zod";

import {
  ScanReportV5Schema,
  type ScanReportV5,
} from "../contracts/reports-v5.js";
import type { Target } from "../contracts/targets.js";
import { parseOperationsState } from "../operations/state.js";
import { recordFailure } from "../operations/retry.js";
import { readJsonFile } from "../cli/io.js";
import {
  ScanTransitionSchema,
  type ScanTransition,
} from "../cli/transition.js";
import { publishCandidates } from "./publisher.js";

const CandidateEnvelopeSchema = z.strictObject({ report: ScanReportV5Schema });
type FailedScanTransition = Extract<ScanTransition, { status: "failure" }>;

async function exists(path: string) {
  try {
    await access(path);
    return true;
  } catch {
    return false;
  }
}

async function findTransitionFiles(root: string): Promise<string[]> {
  const paths: string[] = [];
  for (const entry of await readdir(root, { withFileTypes: true })) {
    const path = join(root, entry.name);
    if (entry.isDirectory()) paths.push(...(await findTransitionFiles(path)));
    else if (entry.isFile() && entry.name === "transition.json")
      paths.push(path);
  }
  return paths;
}

async function outcomeDirectories(artifactsRoot: string): Promise<string[]> {
  return [
    ...new Set((await findTransitionFiles(artifactsRoot)).map(dirname)),
  ].sort((left, right) => left.localeCompare(right));
}

async function loadPairedOutcome(directory: string) {
  const candidatePath = join(directory, "candidate.json");
  return {
    transition: ScanTransitionSchema.parse(
      await readJsonFile(join(directory, "transition.json")),
    ),
    candidate: (await exists(candidatePath))
      ? await readJsonFile(candidatePath)
      : null,
  };
}

function reportMatchesTarget(report: ScanReportV5, target: Target): boolean {
  return (
    report.source_id === target.source_id &&
    report.provider === target.provider &&
    report.repository_id === target.repository_id &&
    report.repository === target.repository &&
    report.canonical_url === target.canonical_url &&
    report.target_sha === target.target_sha
  );
}

export async function publishArtifactBatch(
  input: PublishArtifactBatchInput,
): Promise<PublishArtifactBatchResult> {
  const outcomes = await Promise.all(
    (await outcomeDirectories(input.artifactsRoot)).map(loadPairedOutcome),
  );
  if (outcomes.length === 0) throw new Error("No scan outcomes were supplied.");

  let state = parseOperationsState(
    await readJsonFile(join(input.root, "operations", "state.json")),
  );
  const reports: ScanReportV5[] = [];
  const failures: FailedScanTransition[] = [];
  const targetKeys = new Set<string>();

  for (const outcome of outcomes) {
    const targetKey = [
      outcome.transition.target.provider,
      outcome.transition.target.repository_id,
      outcome.transition.target.target_sha,
    ].join(":");
    if (targetKeys.has(targetKey))
      throw new Error("Duplicate scan outcome target in publication batch.");
    targetKeys.add(targetKey);
    if (outcome.transition.status === "failure") {
      if (outcome.candidate !== null)
        throw new Error("Failed outcome must not contain a candidate.");
      failures.push(outcome.transition);
      state = recordFailure(state, {
        target: outcome.transition.target,
        code: outcome.transition.code,
        scope: outcome.transition.scope,
        at: outcome.transition.at,
      }).state;
      continue;
    }
    if (outcome.candidate === null)
      throw new Error("Completed outcome is missing its candidate.");
    const report = CandidateEnvelopeSchema.parse(outcome.candidate).report;
    if (!reportMatchesTarget(report, outcome.transition.target))
      throw new Error(
        "Completed candidate does not match its transition target.",
      );
    reports.push(report);
  }

  const published = await publishCandidates({
    root: input.root,
    candidates: reports,
    state,
    generatedAt: input.generatedAt,
  });
  const hasFailures = failures.length > 0;
  return {
    status: hasFailures
      ? published.published.length > 0
        ? "partial"
        : "deferred"
      : "published",
    reports: published.published.length,
    has_failures: hasFailures,
    system_failure: failures.some(({ scope }) => scope === "system"),
    terminal_failures: failures.filter(({ target }) =>
      published.state.retries.some(
        (retry) =>
          retry.repository_id === target.repository_id &&
          retry.target_sha === target.target_sha &&
          retry.exhausted,
      ),
    ).length,
  };
}
```

Replace `src/cli/publish.ts` with a thin call to `publishArtifactBatch()` using
`process.cwd()`, the CLI artifacts argument, and one generated timestamp.

- [ ] **Step 4: Run the focused tests and verify GREEN**

Run:

```powershell
npm test -- tests/artifact-batch.test.ts
```

Expected: all artifact-batch tests PASS.

- [ ] **Step 5: Run publisher regression tests**

Run:

```powershell
npm test -- tests/publisher.test.ts tests/retry.test.ts tests/artifact-batch.test.ts
```

Expected: all selected tests PASS; mixed-batch publication does not weaken
publisher rollback or retry behavior.

- [ ] **Step 6: Commit the batch publisher**

```powershell
git add src/publish/artifact-batch.ts src/cli/publish.ts tests/artifact-batch.test.ts
git commit -m "fix(publish): retain mixed batch successes"
```

### Task 2: Finish every matrix target and route partial publication

**Files:**

- Modify: `.github/workflows/scan-and-publish.yml`
- Modify: `scripts/check-workflow-policy.mjs`
- Modify: `tests/workflows.test.ts`

**Interfaces:**

- Consumes: publish command JSON fields `reports` and `system_failure` from Task 1.
- Produces: publish job outputs `source_sha`, `reports`, and `system_failure`; deploy and continuation conditions that consume those outputs.

- [ ] **Step 1: Change workflow tests first**

Update the existing scan-boundary test and add one routing test:

```ts
expect(value.jobs.scan.strategy["max-parallel"]).toBe(2);
expect(value.jobs.scan.strategy["fail-fast"]).toBe(false);

test("mixed batches deploy successes but stop ordinary continuation on a system failure", async () => {
  const value = await workflow("scan-and-publish.yml");
  expect(value.jobs.publish.outputs).toMatchObject({
    reports: "${{ steps.publish.outputs.reports }}",
    system_failure: "${{ steps.publish.outputs.system_failure }}",
  });
  expect(value.jobs.deploy.if).toBe(
    "${{ always() && needs.publish.result == 'success' }}",
  );
  expect(value.jobs.continue.needs).toEqual(["publish", "deploy"]);
  expect(value.jobs.continue.if).toContain(
    "needs.publish.outputs.system_failure != 'true'",
  );
});
```

Add a workflow-policy mutation test that changes `fail-fast: false` back to
`true` and expects a failure containing `scan matrix must finish every selected
repository`.

- [ ] **Step 2: Run workflow tests and verify RED**

Run:

```powershell
npm test -- tests/workflows.test.ts
```

Expected: FAIL because the workflow still has fail-fast enabled and does not
export mixed-batch routing outputs.

- [ ] **Step 3: Update the workflow**

In `.github/workflows/scan-and-publish.yml`:

```yaml
strategy:
  fail-fast: false
  max-parallel: 2
```

Give the publisher step `id: publish`, capture its JSON, print it, and export
validated scalar outputs:

```yaml
- name: Publish serialized batch
  id: publish
  shell: bash
  run: |
    result="$(npm run --silent publish -- artifacts)"
    printf '%s\n' "$result"
    echo "reports=$(jq -er '.reports | select(type == \"number\")' <<< "$result")" >> "$GITHUB_OUTPUT"
    echo "system_failure=$(jq -er '.system_failure | select(type == \"boolean\")' <<< "$result")" >> "$GITHUB_OUTPUT"
```

Add job outputs:

```yaml
outputs:
  source_sha: ${{ steps.commit.outputs.source_sha }}
  reports: ${{ steps.publish.outputs.reports }}
  system_failure: ${{ steps.publish.outputs.system_failure }}
```

Route downstream jobs as follows:

```yaml
deploy:
  needs: publish
  if: ${{ always() && needs.publish.result == 'success' }}

continue:
  needs: [publish, deploy]
  if: ${{ always() && needs.publish.result == 'success' && needs.deploy.result == 'success' && needs.publish.outputs.system_failure != 'true' && inputs.continue_backlog && inputs.remaining != '0' }}
```

- [ ] **Step 4: Update workflow policy enforcement**

Change `checkEncryptedHandoff()` to require `fail-fast: false` and add a
focused mixed-batch routing check that validates:

- the publish step has `id: publish` and exports typed `reports` and
  `system_failure` values;
- the deploy condition includes `always()` and requires publisher success;
- continuation needs both `publish` and `deploy` and rejects a true system
  failure;
- max parallelism remains two.

Use this policy failure text for fail-fast drift:

```js
fail(file, "scan matrix must finish every selected repository");
```

- [ ] **Step 5: Run workflow tests and policy checks and verify GREEN**

Run:

```powershell
npm test -- tests/workflows.test.ts
npm run workflows:check
```

Expected: both commands PASS.

- [ ] **Step 6: Commit workflow routing**

```powershell
git add .github/workflows/scan-and-publish.yml scripts/check-workflow-policy.mjs tests/workflows.test.ts
git commit -m "fix(workflow): deploy partial batches"
```

### Task 3: Align production documentation

**Files:**

- Modify: `README.md`
- Modify: `docs/architecture.md`
- Modify: `docs/operations.md`

**Interfaces:**

- Consumes: the approved partial-batch behavior from Tasks 1 and 2.
- Produces: operator-facing wording that distinguishes a complete repository report from a partially successful batch.

- [ ] **Step 1: Update documentation wording**

Make these points explicit:

- every selected matrix target finishes independently;
- only complete repository reports publish;
- valid reports from a mixed batch publish together;
- unsuccessful targets alone enter retry state;
- a system-scoped failure still engages the circuit for subsequent batches;
- "no degraded report" refers to an individual repository report, not
  discarding valid reports from peer repositories;
- no Wandlight or Recursion reset is required for this orchestration-only
  release.

- [ ] **Step 2: Run formatting and consistency checks**

Run:

```powershell
npx.cmd prettier --check README.md docs/architecture.md docs/operations.md
rg -n -i "discard.*batch|publish a partial report|fail-fast" README.md docs/architecture.md docs/operations.md
git diff --check
```

Expected: Prettier PASS, no wording claims that a peer failure discards valid
reports, and `git diff --check` emits no output.

- [ ] **Step 3: Commit documentation**

```powershell
git add README.md docs/architecture.md docs/operations.md
git commit -m "docs: explain mixed batch recovery"
```

### Task 4: Full verification and production release

**Files:**

- Verify all files changed in Tasks 1-3.

**Interfaces:**

- Consumes: the completed implementation branch.
- Produces: a reviewed pull request, merged protected-main commit, verified Actions run, and resumed catalog processing.

- [ ] **Step 1: Run complete local verification**

Run:

```powershell
npm run format:check
npm run typecheck
npm test
npm run workflows:check
npm run build
git diff --check origin/main...HEAD
git status --short
```

Expected: every command PASS and the worktree is clean after committed changes.

- [ ] **Step 2: Review the complete branch diff**

Run:

```powershell
git diff --stat origin/main...HEAD
git diff origin/main...HEAD -- src/publish/artifact-batch.ts src/cli/publish.ts .github/workflows/scan-and-publish.yml scripts/check-workflow-policy.mjs tests/artifact-batch.test.ts tests/workflows.test.ts README.md docs/architecture.md docs/operations.md
```

Expected: changes stay within the approved orchestration, workflow, tests, and
documentation scope.

- [ ] **Step 3: Push and open the protected-main pull request**

```powershell
git push -u origin codex/partial-batch-publishing
gh pr create --repo MentallyQuill/TavernKeeper --base main --head codex/partial-batch-publishing --title "Retain successful reports from mixed scan batches" --body "## Summary`n- publish every complete success from a mixed five-target batch`n- retry only unsuccessful targets while preserving the system circuit`n- finish every selected matrix job before serialized publication`n`n## Verification`n- npm run check`n- npm run build`n`nNo scanner, prompt, report-output, or risk-synthesis behavior changes. No Wandlight or Recursion reset is required."
```

- [ ] **Step 4: Verify CI, merge, and verify production main**

Use `gh pr checks --watch`, merge only after all required checks pass, then
verify the exact main SHA through the CI and workflow metadata. Do not bypass a
failed required check.

- [ ] **Step 5: Resume the production queue once**

If the live operations state contains a transient system circuit from the old
batch behavior, dispatch one protected `resume`, verify the environment and
approval authority, approve it, and let the built-in reconcile continuation
run. Preserve every retry entry.

- [ ] **Step 6: Prove mixed-batch behavior live**

For the first naturally mixed production batch, verify all of the following:

- every one of the five matrix jobs reaches a terminal outcome without
  fail-fast cancellation;
- the publisher reports `partial` with a nonzero `reports` count;
- successful report IDs appear in `reports/index.json` on main;
- only failed targets remain in retry state;
- Pages deploys the exact publisher commit and Tavernary importer wake succeeds;
- no successful repository is selected again for the same SHA;
- a system failure leaves the circuit engaged and suppresses ordinary
  continuation.

If the first production batch is all-success, verify normal deployment and
continuation, then keep the mixed-batch proof pending until it occurs naturally;
do not induce a failure.
