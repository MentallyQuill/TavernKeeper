# Progress-Aware Contextual Review Cutoff Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Prevent a contextual review with no checkpoint progress from holding batch publication for all three twenty-minute passes.

**Architecture:** Keep retry control in the existing scan workflow. Compare the sanitized completed-group count around each invocation, permit timeout retries only after progress, and retain one no-progress retry for a transient shared provider failure.

**Tech Stack:** GitHub Actions, Bash, Node.js 24, Vitest, workflow policy validation

## Global Constraints

- Preserve the existing three-pass, twenty-minute-per-pass, sixty-two-minute outer fail-closed boundaries.
- Never print or persist checkpoint narratives, paths, prompts, provider responses, or source excerpts.
- Do not change Report V5, operations-state V3, or Tavernary schemas.
- Preserve the unrelated nested `TavernKeeper/` directory in the primary checkout.
- Publish through a protected feature branch and pull request.

---

### Task 1: Specify the progress-aware retry contract

**Files:**

- Modify: `tests/workflows.test.ts`
- Modify: `scripts/check-workflow-policy.mjs`

**Interfaces:**

- Consumes: parsed `scan-and-publish.yml` review step
- Produces: regression coverage for `progress_count`, progress comparison, and one no-progress provider retry

- [ ] **Step 1: Add failing workflow assertions**

Require the review shell to read `review-progress.json`, capture counts before and after each pass, retry a timeout only after an increased count, and cap no-progress provider retries at one.

- [ ] **Step 2: Run the focused test red**

Run `npm.cmd test -- tests/workflows.test.ts` and confirm the new assertions fail against production main.

- [ ] **Step 3: Extend workflow-policy mutation checks**

Require the same progress-aware invariants in `scripts/check-workflow-policy.mjs` so later workflow edits cannot silently remove them.

### Task 2: Implement the minimal workflow cutoff

**Files:**

- Modify: `.github/workflows/scan-and-publish.yml`

**Interfaces:**

- Consumes: `$TAVERNKEEPER_SESSION_ROOT/review-progress.json` and `phase-error.json`
- Produces: retry decisions based on numeric checkpoint advancement

- [ ] **Step 1: Add a body-free progress counter**

Use Node.js to emit only the validated nonnegative completed-group count, returning zero when no checkpoint exists.

- [ ] **Step 2: Compare progress around each invocation**

Capture `progress_before` and `progress_after`. Continue after a timeout only when `progress_after > progress_before`.

- [ ] **Step 3: Bound provider recovery**

Allow exactly one `MODEL_PROVIDER/shared/contextual-model` retry without progress. Require progress for any later pass.

- [ ] **Step 4: Run focused tests green**

Run `npm.cmd test -- tests/workflows.test.ts` and `npm.cmd run workflows:check`.

### Task 3: Verify and publish

**Files:**

- Verify: all changed files

**Interfaces:**

- Consumes: approved implementation and protected branch rules
- Produces: merged main SHA and live recovery evidence

- [ ] **Step 1: Run the full local gate**

Run `npm.cmd run check`, `npm.cmd run build`, and `git diff --check`.

- [ ] **Step 2: Review the complete diff**

Confirm checkpoint privacy, timeout semantics, provider retry count, schema compatibility, and unrelated-file isolation.

- [ ] **Step 3: Commit, push, and open a pull request**

Commit the approved design, tests, and implementation on `codex/progress-aware-review-cutoff`, push it, and open a ready pull request.

- [ ] **Step 4: Merge after required checks pass**

Inspect all GitHub Actions checks, resolve any failure, merge through protected main, and record the exact merge SHA.

- [ ] **Step 5: Prove the merged runtime**

Dispatch ordinary reconciliation and verify job-level scan outcomes, committed operational-state advancement, batch publication, and automatic continuation.
