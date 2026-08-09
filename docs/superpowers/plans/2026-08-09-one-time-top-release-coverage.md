# One-Time Top and Latest-Release Coverage Implementation Plan

> **For Codex:** Use `superpowers:executing-plans` and
> `superpowers:subagent-driven-development` to execute this plan task by task.

**Goal:** Select the current top 20 popular Tavernary repositories and the 20
repositories with the newest qualifying GitHub releases, then scan their
deduplicated current targets exactly once through the ordinary queue while
respecting the 48-hour cooldown.

**Architecture:** Add a distinct, auditable coverage campaign to schema-3
operations state. A protected input-free GitHub Action computes one atomic
selection from the V3 Tavernary manifest and GitHub's latest-release API,
commits the fixed campaign once, and dispatches ordinary reconciliation.
Reconciliation queues only the campaign's remaining current targets, preserves
ordinary retry and cooldown behavior, and completes each member only after a
post-campaign report for its current SHA and scanner policy exists.

**Tech stack:** TypeScript, Node.js ESM, Zod, Vitest, YAML, GitHub Actions,
GitHub REST API, GitHub CLI.

---

## Task 1: Persist and reconcile the bounded coverage campaign

**Files:**

- Modify: `src/operations/state.ts`
- Modify: `src/operations/migrate-state.ts`
- Modify: `src/queue/reconcile.ts`
- Modify: `src/queue/backlog.ts`
- Modify: `src/cli/staff-request.ts`
- Test: `tests/state-migration.test.ts`
- Test: `tests/queue-sync.test.ts`
- Test: `tests/backlog.test.ts`
- Test: `tests/cli.test.ts`

### Step 1: Write failing state and reconciliation tests

Add fixtures proving:

- old schema-3 state parses with an empty `coverage_campaigns` collection;
- selected component lists are unique/sorted, contain no more than 20 IDs,
  produce the exact union, and contain every remaining ID;
- the first campaign reconciliation queues only selected current targets;
- a same-SHA report published before campaign creation does not complete the
  member and creates a 48-hour deadline;
- an absent report or an expired deadline is immediately runnable;
- staff and policy work retain their existing priority/cooldown authority;
- retries retain their failure deadline;
- a qualifying post-campaign current-SHA report removes only that ID from
  `remaining_repository_ids` while preserving the original lists;
- a removed manifest member is removed from remaining; and
- the campaign becomes permanently completed only when remaining is empty.

Run:

```powershell
npm.cmd test -- tests/state-migration.test.ts tests/queue-sync.test.ts tests/backlog.test.ts tests/cli.test.ts
```

Expected: FAIL because coverage campaigns and the `coverage` reason do not yet
exist.

### Step 2: Implement the state contract

Add `CoverageCampaignSchema` with:

- fixed ID;
- scanner policy version;
- creation timestamp;
- active/completed status;
- sorted popular IDs;
- sorted latest-release IDs;
- exact sorted union in `repository_ids`; and
- sorted `remaining_repository_ids` subset.

Default the operations-state collection to `[]`, include it in initial state
and canonical serialization, and preserve it through migration.

### Step 3: Implement queue semantics

Advance coverage campaigns before eligibility. Active membership uses only
`remaining_repository_ids` under the current scanner policy. Coverage may make
the current target eligible, but it must never set `staff_requested`, bypass
`rescan_not_before`, bypass `not_before`, reset failures, or receive policy
priority.

For a selected current SHA:

- no report means no rescan delay;
- an earlier report at the same or prior SHA uses `completed_at + 48 hours`;
- staff and policy authority retain their existing bypass; and
- a post-campaign report at the current SHA/policy completes the member.

Add `coverage` to backlog and scan-request reasons. Use precedence retry,
staff, policy, coverage, then ordinary new/changed reasoning.

### Step 4: Verify and commit

```powershell
npm.cmd test -- tests/state-migration.test.ts tests/queue-sync.test.ts tests/backlog.test.ts tests/cli.test.ts
npm.cmd run typecheck
git diff --check
git add src/operations/state.ts src/operations/migrate-state.ts src/queue/reconcile.ts src/queue/backlog.ts src/cli/staff-request.ts tests/state-migration.test.ts tests/queue-sync.test.ts tests/backlog.test.ts tests/cli.test.ts
git commit -m "feat(queue): add bounded coverage campaign"
```

Expected: PASS.

## Task 2: Select the one-time cohort atomically

**Files:**

- Create: `src/cli/coverage-campaign.ts`
- Create: `src/coverage/select-campaign.ts`
- Modify: `package.json`
- Test: `tests/coverage-campaign.test.ts`
- Test: `tests/cli.test.ts`

### Step 1: Write failing selector tests

Cover:

- V3 popularity ranks select exactly ranks 1 through 20;
- each manifest repository is queried at the GitHub latest-release endpoint;
- `404` means no qualifying release;
- release ranking uses `created_at` descending, then repository ID ascending;
- draft/prerelease responses and malformed identity/time fields fail closed;
- auth, rate-limit, transport, and non-404 HTTP failures abort the whole
  selection without a state write;
- lookups never exceed the fixed concurrency bound;
- overlap is deduplicated in the sorted union;
- a pre-existing fixed campaign ID is idempotent and never reactivated; and
- the CLI writes state only after every selection and schema check succeeds.

Use injected `fetch` and clock functions; tests must not call the network.

Run:

```powershell
npm.cmd test -- tests/coverage-campaign.test.ts tests/cli.test.ts
```

Expected: FAIL because the selector does not exist.

### Step 2: Implement bounded GitHub selection

Require manifest schema 3 and the current scanner policy. Use the fixed campaign
ID `one-time-top20-popular-latest-release-v1`. Query only
`https://api.github.com/repos/{owner}/{repo}/releases/latest` with redirect
rejection, a bounded timeout and response size, GitHub JSON accept/version
headers, and the workflow token. Do not retain release body, assets, URLs, or
other unneeded fields.

Perform at most eight lookups concurrently. Parse only `created_at`, `draft`,
and `prerelease`; accept only non-draft/non-prerelease releases. Finish all
selection and state validation before atomically replacing
`operations/state.json`.

### Step 3: Verify and commit

```powershell
npm.cmd test -- tests/coverage-campaign.test.ts tests/cli.test.ts
npm.cmd run typecheck
git diff --check
git add src/cli/coverage-campaign.ts src/coverage/select-campaign.ts tests/coverage-campaign.test.ts tests/cli.test.ts package.json
git commit -m "feat(scans): select one-time coverage cohort"
```

Expected: PASS.

## Task 3: Add the protected one-time workflow

**Files:**

- Create: `.github/workflows/coverage-campaign.yml`
- Modify: `scripts/check-workflow-policy.mjs`
- Modify: `tests/workflows.test.ts`
- Modify: `docs/operations.md`
- Modify: `docs/architecture.md`
- Modify: `README.md` if it enumerates staff workflows

### Step 1: Write failing workflow-policy tests

Assert the new workflow:

- has only `workflow_dispatch` and no inputs or schedule;
- uses non-canceling global scan concurrency;
- has a single state-mutation job protected by `tavernkeeper-staff`;
- starts with least-privilege `contents: read` and `actions: write`;
- uses the existing Publisher App credentials only to push the state commit;
- passes only the GitHub token to the selection step;
- retries push conflicts by resetting the ephemeral checkout to current main
  and rerunning the atomic fixed-ID operation;
- treats an already-created campaign as success without a second commit; and
- dispatches `reconcile.yml` only after committed or already-present state.

Run:

```powershell
npm.cmd test -- tests/workflows.test.ts
npm.cmd run workflows:check
```

Expected: FAIL because the workflow is not allowlisted.

### Step 2: Implement workflow and documentation

Create the input-free protected workflow and add exact trigger, permission,
mutation, secret-placement, and fixed push-loop policy checks. Document that it
is a one-time coverage operation, not an ongoing schedule or catalog rescan;
overlap may reduce the cohort below 40 and every target still respects the
48-hour rule.

### Step 3: Verify and commit

```powershell
npm.cmd test -- tests/workflows.test.ts
npm.cmd run workflows:check
npm.cmd run typecheck
npx.cmd prettier --check .github/workflows/coverage-campaign.yml scripts/check-workflow-policy.mjs tests/workflows.test.ts docs/operations.md docs/architecture.md README.md
git diff --check
git add .github/workflows/coverage-campaign.yml scripts/check-workflow-policy.mjs tests/workflows.test.ts docs/operations.md docs/architecture.md README.md
git commit -m "feat(workflow): schedule one-time coverage"
```

Expected: PASS. Omit `README.md` from staging if no edit is required.

## Task 4: Full verification and release proof

Run:

```powershell
npm.cmd run check
npm.cmd run build
git diff --check
git status --short
```

Request independent specification and code-quality review. Before live use,
verify the committed campaign selection against the manifest and GitHub release
timestamps, verify overlap/deduplication, and inspect the first reconcile plan
while the emergency stop is still active. The plan must contain no runnable
targets until the protected resume operation clears the stop.
