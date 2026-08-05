# Scan Liveness Hardening Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship the verified scan-reliability repair with deterministic delayed recovery, bounded resumable review execution, catalog-first queue ordering, and scanner-specific prepare failures.

**Architecture:** Keep all recovery inside GitHub Actions and the committed durable queue. A separate delayed-wake workflow sleeps outside global scan concurrency, review invocations use a sanitized timeout sentinel plus existing checkpoints, and queue/scanner behavior changes remain isolated pure TypeScript units.

**Tech Stack:** TypeScript 6, Node.js 24, Zod 4, Vitest 4, GitHub Actions, PowerShell for local verification

## Global Constraints

- Public Report V5 and Tavernary's copied schema must remain unchanged.
- Persist no prompts, source excerpts, provider bodies, paths, or secrets in queue, artifacts, logs, or checkpoints.
- Unknown scanner diagnostics, malformed output, and incomplete contextual coverage remain fatal.
- Do not modify the unrelated untracked nested `TavernKeeper/` directory.
- Publish through a protected feature branch and pull request; do not push directly to `main`.

---

### Task 1: Preserve and integrate the verified reliability repair

**Files:**

- Modify: existing scan-reliability source, workflow, documentation, and tests already present in the working tree
- Test: `tests/artifact-batch.test.ts`, `tests/retry.test.ts`, `tests/opengrep.test.ts`, `tests/contextual-review.test.ts`, `tests/scan-session.test.ts`

**Interfaces:**

- Consumes: existing Report V5, operations-state V3, prepared-session V5, and scan-package V1 contracts
- Produces: order-independent `recordFailure`, internal OpenGrep limitations, phase fallbacks, and `ContextualReviewProgressSchema`

- [ ] **Step 1: Commit the already-green reliability repair without the nested checkout**

Stage only the tracked implementation and test files, verify the staged diff excludes `TavernKeeper/`, and commit with `fix: make scan recovery resumable`.

- [ ] **Step 2: Fetch current protected main and create an isolated feature worktree**

Create `.worktrees/scan-liveness-hardening` on `codex/scan-liveness-hardening` from the current remote `main`, then cherry-pick the design and implementation commits.

- [ ] **Step 3: Re-run the focused reliability baseline**

Run:

```powershell
npm.cmd test -- tests/artifact-batch.test.ts tests/retry.test.ts tests/opengrep.test.ts tests/contextual-review.test.ts tests/scan-session.test.ts
```

Expected: all focused tests pass on current production history.

### Task 2: Prefer clean catalog work before retries

**Files:**

- Modify: `src/queue/backlog.ts`
- Test: `tests/backlog.test.ts`

**Interfaces:**

- Consumes: `ScanQueueEntry.consecutive_failures`, `staff_requested`, and `ticket`
- Produces: deterministic staff, clean, retry, ticket ordering in `planBatch`

- [ ] **Step 1: Write one failing clean-before-retry test**

Add a case whose lowest ticket is a due retry and whose next ticket is clean. Assert the clean repository is selected first while both remain runnable.

- [ ] **Step 2: Run the focused test and confirm the ordering failure**

Run `npm.cmd test -- tests/backlog.test.ts` and confirm the new assertion receives retry-first order.

- [ ] **Step 3: Implement the minimal lane ordering**

After staff priority, compare `Number(entry.consecutive_failures > 0)` before comparing tickets.

- [ ] **Step 4: Update the obsolete no-overtaking expectation**

Retain ticket ordering inside the retry lane, but require clean catalog work to precede rotated failures and later clean arrivals.

- [ ] **Step 5: Run `tests/backlog.test.ts` green**

Expected: clean-first, staff, cooldown, probe, and fail-closed tests all pass.

### Task 3: Attribute unexpected scanner failures

**Files:**

- Modify: `src/scanners/run-scanners.ts`
- Test: `tests/conditional-scanners.test.ts`

**Interfaces:**

- Consumes: `ScannerError`, `ScannerComponent`, and scanner adapter promises
- Produces: `runScanner(component, operation)` preserving typed errors and wrapping unknown errors as target-local `SCANNER_FAILED`

- [ ] **Step 1: Add one failing untyped-adapter test**

Make the OpenGrep test adapter reject with `new Error("ignored body")`; assert rejection matches `{code:"SCANNER_FAILED",scope:"repository",component:"opengrep"}` and does not expose the body.

- [ ] **Step 2: Run the focused test red**

Run `npm.cmd test -- tests/conditional-scanners.test.ts` and confirm the raw error escapes.

- [ ] **Step 3: Add the minimal scanner boundary**

Wrap each external adapter call. Re-throw `ScannerError`; convert every other value to a fixed-message, repository-scoped `ScannerError` for that adapter.

- [ ] **Step 4: Add and pass the typed-preservation case**

Prove an existing `SCANNER_TIMEOUT/system/opengrep` remains unchanged, then run the focused file green.

### Task 4: Bound and resume contextual review execution

**Files:**

- Modify: `config/contextual-review.v2.json`
- Modify: `.github/workflows/scan-and-publish.yml`
- Modify: `scripts/check-workflow-policy.mjs`
- Test: `tests/workflows.test.ts`
- Test: `tests/scan-session.test.ts`

**Interfaces:**

- Consumes: `review-progress.json`, `phase-error.json`, `MODEL_PROVIDER`, and `npm run review-target`
- Produces: `MODEL_REVIEW_TIMEOUT/target/contextual-model` sentinel, two bounded invocations, 300000 millisecond request timeout, and forty-two-minute outer ceiling

- [ ] **Step 1: Add a failing workflow-contract assertion**

Require the review step to contain GNU `timeout`, the exact timeout sentinel, retry gating for both `MODEL_PROVIDER` and `MODEL_REVIEW_TIMEOUT`, and `timeout-minutes: 42`.

- [ ] **Step 2: Run workflow tests red**

Run `npm.cmd test -- tests/workflows.test.ts` and confirm the old sixteen-minute provider-only block fails.

- [ ] **Step 3: Implement the two-invocation shell block**

Seed the fixed phase error before each invocation, run at most two twenty-minute invocations with ten-second termination grace, remove the sentinel on success, and retry only the two approved categories.

- [ ] **Step 4: Reduce the provider request timeout**

Change `config/contextual-review.v2.json` `timeoutMs` from `900000` to `300000` and update its exact contract test.

- [ ] **Step 5: Extend workflow-policy mutation coverage**

Require the sentinel, both retry categories, bounded command timeout, and outer ceiling in `scripts/check-workflow-policy.mjs`.

- [ ] **Step 6: Run config and workflow tests green**

Run `npm.cmd test -- tests/workflows.test.ts tests/scan-session.test.ts` plus `npm.cmd run workflows:check`.

### Task 5: Add deterministic delayed wake-up

**Files:**

- Create: `.github/workflows/delayed-wake.yml`
- Modify: `.github/workflows/reconcile.yml`
- Modify: `scripts/check-workflow-policy.mjs`
- Test: `tests/workflows.test.ts`

**Interfaces:**

- Consumes: `plan.outputs.requests_json`, `total_remaining`, and `next_wake_at`
- Produces: validated `wake_at` dispatch, maximum 20400-second sleep, and a later `reconcile.yml` dispatch outside global scan concurrency

- [ ] **Step 1: Add the delayed-wake filename to the explicit workflow test**

Run `npm.cmd test -- tests/workflows.test.ts` and confirm the active-set assertion fails until the workflow exists.

- [ ] **Step 2: Add failing structural assertions**

Require workflow-dispatch-only input `wake_at`, a separate cancel-replace concurrency group, `actions: write`, bounded Node timestamp parsing, capped sleep, and final reconcile dispatch. Require reconcile planning to dispatch the wake only for an empty nonterminal plan.

- [ ] **Step 3: Create the minimal workflows**

Implement `.github/workflows/delayed-wake.yml` and the conditional reconcile step using only fixed workflow names and the validated timestamp input.

- [ ] **Step 4: Add workflow-policy enforcement**

Teach `scripts/check-workflow-policy.mjs` the new active workflow and exact bounded wake invariants.

- [ ] **Step 5: Run workflow tests and policy green**

Run `npm.cmd test -- tests/workflows.test.ts` and `npm.cmd run workflows:check`.

### Task 6: Verify, review, and publish through protected main

**Files:**

- Verify: every changed file

**Interfaces:**

- Consumes: completed tasks and protected GitHub branch rules
- Produces: merged main SHA plus live reconcile, publisher, queue, and delayed-wake evidence

- [ ] **Step 1: Run the full local gate**

Run `npm.cmd run check`, `npm.cmd run build`, `npm.cmd run contracts:generate`, verify Report V5 generated schema has no diff, and run `git diff --check`.

- [ ] **Step 2: Perform an independent code review**

Review queue fairness, timeout privacy, wake injection resistance, workflow permissions, checkpoint behavior, public-schema compatibility, and unrelated-file isolation. Resolve every important finding and rerun affected tests.

- [ ] **Step 3: Commit and push the feature branch**

Commit with `fix: harden autonomous scan recovery`, push `codex/scan-liveness-hardening`, and open a pull request describing live evidence and verification.

- [ ] **Step 4: Wait for required checks and merge**

Use GitHub CLI with network permission, inspect failures if any, merge only when required checks pass, and record the exact merged main SHA.

- [ ] **Step 5: Prove the merged runtime**

Verify merged CI, dispatch the ordinary reconcile workflow, and inspect job-level outcomes plus committed `operations/state.json` and `reports/index.json`. Confirm publisher advancement, clean-first selection or a bounded recovery probe, and delayed-wake scheduling when the plan has a future wake.
