# TavernKeeper Publisher Full Verification Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Migrate every TavernKeeper Publisher workflow to Client ID and prove both protected environments can write through protected `main` while ordinary owner pushes remain blocked.

**Architecture:** Existing Publisher mutation jobs retain their exact data and retry behavior while only the token identifier changes. A two-job manual canary exercises `tavernkeeper-scanner` and `tavernkeeper-staff` sequentially with harmless empty commits, and the workflow-policy script makes Client ID and the two canary jobs part of the reviewed security contract.

**Tech Stack:** GitHub Actions YAML, `actions/create-github-app-token`, Node.js workflow-policy script, Vitest, YAML parser, GitHub environments, GitHub rulesets, GitHub CLI.

## Global Constraints

- Use Client ID `Iv23lijroYAkNgXRcxdW` only through `vars.TAVERNKEEPER_PUBLISHER_CLIENT_ID`.
- Keep the private key only in the two protected environment secrets.
- Preserve Contents-write plus mandatory Metadata-read as the App's complete permission set.
- Do not change scanner, publication, retry, queue, or staff-operation behavior.
- Keep ordinary `GITHUB_TOKEN` contents permission Read and disable persisted checkout credentials.
- Never force-push or grant a user, role, or generic Actions bypass.

---

### Task 1: Define the Client ID and canary contracts

**Files:**
- Modify: `tests/workflows.test.ts`
- Modify: `scripts/check-workflow-policy.mjs`
- Create: `.github/workflows/publisher-verification.yml`

**Interfaces:**
- Consumes: `publisherAction`, `mutationJobs`, `permissionProfiles`, and `checkPublisherBoundary`.
- Produces: exact Client ID enforcement for every mutation job and two reviewed canary jobs.

- [ ] **Step 1: Write failing tests**

Require every Publisher token step to contain
`client-id: ${{ vars.TAVERNKEEPER_PUBLISHER_CLIENT_ID }}`, contain no `app-id`,
and use the existing private-key secret. Add expected canary jobs
`verify-scanner` and `verify-staff`, require their environments, owner/main
guards, sequential dependency, empty commits, and non-force pushes.

- [ ] **Step 2: Run Red**

Run: `npm.cmd test -- tests/workflows.test.ts`

Expected: FAIL because production workflows still use `app-id` and the canary
does not exist.

- [ ] **Step 3: Extend the policy checker minimally**

Add `publisher-verification.yml` to the trigger and permission allowlists and
both jobs to `mutationJobs`. Change the credential matcher and token-step
contract to require `TAVERNKEEPER_PUBLISHER_CLIENT_ID` as a variable and reject
the legacy secret/input.

- [ ] **Step 4: Run the focused policy tests**

Run: `npm.cmd test -- tests/workflows.test.ts`

Expected: still FAIL only because workflow YAML has not yet migrated, proving
the policy catches the obsolete contract.

### Task 2: Migrate workflows and add the canary

**Files:**
- Modify: `.github/workflows/coverage-campaign.yml`
- Modify: `.github/workflows/policy-rescan.yml`
- Modify: `.github/workflows/reconcile.yml`
- Modify: `.github/workflows/release-holds.yml`
- Modify: `.github/workflows/scan-and-publish.yml`
- Modify: `.github/workflows/staff-operations.yml`
- Modify: `.github/workflows/targeted-scan.yml`
- Create: `.github/workflows/publisher-verification.yml`

**Interfaces:**
- Consumes: environment variable `TAVERNKEEPER_PUBLISHER_CLIENT_ID` and private-key secret.
- Produces: Client-ID-authenticated production publishers and sequential scanner/staff live canaries.

- [ ] **Step 1: Replace every legacy token input**

Replace each `app-id: ${{ secrets.TAVERNKEEPER_PUBLISHER_APP_ID }}` with
`client-id: ${{ vars.TAVERNKEEPER_PUBLISHER_CLIENT_ID }}`. Make no other change
inside production mutation jobs.

- [ ] **Step 2: Add the canary workflow**

Each canary job checks out `main` with `persist-credentials: false`, mints the
repository-scoped Contents-write token, runs `gh auth setup-git`, creates an
empty commit, and executes the canonical three-attempt `git push origin
HEAD:main` block. `verify-staff` has `needs: verify-scanner`.

- [ ] **Step 3: Run Green**

Run: `npm.cmd test -- tests/workflows.test.ts`

Run: `npm.cmd run workflows:check`

Expected: both pass and the policy reports every workflow reviewed.

### Task 3: Update documentation and run the full gate

**Files:**
- Modify: `docs/operations.md`
- Modify: `docs/superpowers/specs/2026-08-01-tavernkeeper-publisher-app-design.md`
- Modify: `docs/superpowers/plans/2026-08-01-tavernkeeper-publisher-app.md`

**Interfaces:**
- Consumes: the Client ID contract from Tasks 1-2.
- Produces: current operator guidance with no legacy App ID references.

- [ ] **Step 1: Replace stale documentation references**

Describe the Client ID as an environment variable, retain the private key as an
environment secret, and document the repeatable two-lane canary.

- [ ] **Step 2: Run the full local gate**

Run: `npm.cmd run check`

Run: `git diff --check`

Expected: formatting, typecheck, 811-or-more tests, workflow policy, and diff
checks all pass.

### Task 4: Review, merge, and prove both environments

**Files:**
- Live GitHub state only

**Interfaces:**
- Consumes: tested feature branch and ruleset `20197146`.
- Produces: merged Client ID migration, two App commits, two revocations, and rejected owner direct write.

- [ ] **Step 1: Review, publish, and merge through the PR lane**

Resolve every Critical or Important review issue, wait for `check` and
`scanner-toolchain`, merge the tested head SHA, and verify current `main`.

- [ ] **Step 2: Dispatch and approve the two-lane canary**

Run `publisher-verification.yml` from `main`, approve the pending
`tavernkeeper-staff` deployment as MentallyQuill, and verify both empty commits
and both `Token revoked` cleanup messages.

- [ ] **Step 3: Remove the legacy secrets**

Delete only `TAVERNKEEPER_PUBLISHER_APP_ID` from `tavernkeeper-scanner` and
`tavernkeeper-staff`, then re-read both environments to verify the Client ID
variable and private-key secret remain.

- [ ] **Step 4: Prove ordinary direct push rejection and re-audit live state**

Attempt a disposable ordinary-owner empty commit to `main`; require ruleset
rejection. Re-read ruleset actors/rules, App scope/permissions, Actions policy,
security controls, collaborators, canary run, commits, and downstream runs.
