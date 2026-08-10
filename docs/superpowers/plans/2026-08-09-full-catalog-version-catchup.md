# Full Catalog Version Catch-up Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Queue every catalog target lacking the exact current scanner/contextual version tuple, ordered new, updated, then all remaining targets, with one cold policy-4 cooldown bypass.

**Architecture:** Keep catalog observation for durable change provenance, replace incremental-only eligibility with current-version tuple eligibility, and classify automatic queue entries for deterministic priority. Retire the top-20/latest-20 campaign and clear its state during reconciliation.

**Tech Stack:** TypeScript, Zod, Vitest, YAML, GitHub Actions.

## Global Constraints

- Automatic priority is new, updated, then the rest.
- Protected staff requests remain above automatic work.
- A policy-version catch-up bypasses the 48-hour rescan delay once.
- Ordinary later changed-SHA scans retain the 48-hour delay.
- Failure retry and provider-hold timing remain authoritative.
- The top-20/latest-20 mechanism must not create eligibility.

---

### Task 1: Make version-tuple eligibility complete and ordered

**Files:**

- Modify: `src/queue/reconcile.ts`
- Modify: `src/queue/sync.ts`
- Modify: `src/queue/backlog.ts`
- Modify: `src/cli/sync-queue.ts`
- Modify: `src/cli/reconcile.ts`
- Modify: `src/cli/staff-request.ts`
- Test: `tests/queue-sync.test.ts`
- Test: `tests/backlog.test.ts`
- Test: `tests/cli.test.ts`

**Interfaces:**

- Consumes: current scanner policy and contextual policy version.
- Produces: `version` backlog reason for unmarked out-of-version entries and ordered automatic classes.

- [ ] **Step 1: Write failing eligibility and priority tests**

Cover unreported legacy targets, same-SHA contextual-policy drift, scanner-policy
drift, exact-current removal, new and updated provenance retention, staff
precedence, new-before-updated-before-version ordering, and retry deadlines.

- [ ] **Step 2: Run queue tests and verify red**

Run: `npm.cmd test -- tests/queue-sync.test.ts tests/backlog.test.ts tests/cli.test.ts`

Expected: FAIL because unchanged legacy/current-SHA policy drift is ineligible
and ticket order ignores the required class order.

- [ ] **Step 3: Implement exact version eligibility and ordering**

Thread `contextualReviewPolicyVersion` through synchronization and planning.
Define current coverage as exact target SHA plus scanner policy plus contextual
policy. Queue every mismatch. Sort staff first, then catalog `new`, catalog
`updated`, then version catch-up, preserving ticket order within a class.

- [ ] **Step 4: Implement the one-time cooldown bypass**

When the preferred report's scanner or contextual policy is stale, do not add
`rescan_not_before`. When the versions are current but SHA changed, calculate
the existing completion-plus-48-hours deadline.

- [ ] **Step 5: Run queue tests and verify green**

Run: `npm.cmd test -- tests/queue-sync.test.ts tests/backlog.test.ts tests/cli.test.ts tests/durable-queue.test.ts`

Expected: PASS.

### Task 2: Retire top-20/latest-20 eligibility

**Files:**

- Delete: `.github/workflows/coverage-campaign.yml`
- Delete: `src/cli/coverage-campaign.ts`
- Delete: `src/coverage/select-campaign.ts`
- Delete: `tests/coverage-campaign.test.ts`
- Modify: `package.json`
- Modify: `src/queue/reconcile.ts`
- Modify: `src/queue/backlog.ts`
- Modify: `src/cli/staff-request.ts`
- Modify: `scripts/check-workflow-policy.mjs`
- Modify: `tests/workflows.test.ts`
- Modify: `tests/queue-sync.test.ts`
- Modify: `tests/backlog.test.ts`

**Interfaces:**

- Preserves: the backward-compatible `coverage_campaigns` state field as an empty tombstone.
- Produces: reconciliation that clears legacy campaign state and never uses it for eligibility.

- [ ] **Step 1: Write failing retirement tests**

Assert a non-empty legacy coverage campaign is cleared, grants no eligibility
or priority, the scan-request reason enum omits `coverage`, and workflow policy
does not allow the deleted workflow.

- [ ] **Step 2: Run focused tests and verify red**

Run: `npm.cmd test -- tests/queue-sync.test.ts tests/backlog.test.ts tests/workflows.test.ts tests/cli.test.ts`

Expected: FAIL while coverage remains active.

- [ ] **Step 3: Remove the workflow/selector and clear legacy state**

Delete the protected one-time workflow and selector command, remove package and
workflow-policy entries, remove coverage reason/priority logic, and set
`coverage_campaigns: []` in every reconciled state.

- [ ] **Step 4: Verify retirement**

Run:
`npm.cmd test -- tests/queue-sync.test.ts tests/backlog.test.ts tests/workflows.test.ts tests/cli.test.ts`
`npm.cmd run workflows:check`

Expected: PASS.

### Task 3: Update operator documentation and commit

**Files:**

- Modify: `README.md`
- Modify: `docs/architecture.md`
- Modify: `docs/operations.md`

**Interfaces:**

- Documents: exact current-version tuple, priority, cooldown bypass, and retired coverage campaign.

- [ ] **Step 1: Replace incremental-only and 20+20 documentation**

Document that every out-of-version target is eligible, catalog observation is
classification rather than an eligibility gate, and the cold policy-4 pass
bypasses the 48-hour delay once.

- [ ] **Step 2: Run focused verification**

Run:
`npm.cmd test -- tests/queue-sync.test.ts tests/backlog.test.ts tests/cli.test.ts tests/workflows.test.ts`
`npm.cmd run typecheck`
`npm.cmd run workflows:check`

Expected: PASS.

- [ ] **Step 3: Commit catalog catch-up**

Run:
`git add -A .github/workflows/coverage-campaign.yml src/cli/coverage-campaign.ts src/coverage/select-campaign.ts tests/coverage-campaign.test.ts package.json src/queue/reconcile.ts src/queue/sync.ts src/queue/backlog.ts src/cli/sync-queue.ts src/cli/reconcile.ts src/cli/staff-request.ts scripts/check-workflow-policy.mjs tests/queue-sync.test.ts tests/backlog.test.ts tests/workflows.test.ts tests/cli.test.ts README.md docs/architecture.md docs/operations.md`
`git commit -m "feat(queue): scan all out-of-version projects"`

Expected: commit succeeds after focused tests pass.
