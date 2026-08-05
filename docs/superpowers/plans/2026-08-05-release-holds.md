# Release Holds Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add and run a staff-gated GitHub Action that releases automatic recovery holds and resumes TavernKeeper scanning.

**Architecture:** Extend the existing operational-state and retry CLI boundary with one idempotent `release-holds` transition. Add a dedicated manual workflow that persists the transition through the publisher app and dispatches the existing reconciler.

**Tech Stack:** TypeScript, Zod, Vitest, GitHub Actions YAML, GitHub CLI

## Global Constraints

- Preserve the emergency stop, scan queue, retry histories, active scans, and policy campaigns.
- Clear all `automatic_holds` entries and update `updated_at`.
- Require the `tavernkeeper-staff` environment and `tavernkeeper-global-scan` concurrency group.
- Dispatch `reconcile.yml` after the release operation, including when there were no holds.
- Do not modify the unrelated untracked `TavernKeeper/` directory.

---

### Task 1: State transition and CLI contract

**Files:**
- Modify: `tests/operations-state.test.ts`
- Modify: `src/operations/state.ts`
- Modify: `src/cli/retry.ts`

**Interfaces:**
- Produces: `releaseAutomaticHolds(state: OperationsState, at: string): OperationsState`
- Produces: `TAVERNKEEPER_OPERATION={"operation":"release-holds"}`

- [ ] **Step 1: Write the failing state-transition test**
- [ ] **Step 2: Run the focused test and confirm it fails because the transition is absent**
- [ ] **Step 3: Implement `releaseAutomaticHolds` and add the CLI discriminator**
- [ ] **Step 4: Run the focused test and confirm it passes**

### Task 2: Manual GitHub Action

**Files:**
- Modify: `tests/workflows.test.ts`
- Create: `.github/workflows/release-holds.yml`
- Modify: `scripts/check-workflow-policy.mjs`

**Interfaces:**
- Consumes: `release-holds` retry CLI operation
- Produces: manual `Release Holds` workflow

- [ ] **Step 1: Write failing workflow-shape and policy tests**
- [ ] **Step 2: Run focused workflow tests and confirm the workflow is missing**
- [ ] **Step 3: Add the minimal staff-gated, idempotent workflow and policy allowlist**
- [ ] **Step 4: Run focused workflow and policy checks**

### Task 3: Verify, publish, and operate

**Files:**
- Modify: none

**Interfaces:**
- Consumes: merged `release-holds.yml` on `main`
- Produces: released live holds and a dispatched reconciliation run

- [ ] **Step 1: Run typecheck, unit tests, workflow-policy check, and build**
- [ ] **Step 2: Review the exact diff and commit the approved scope**
- [ ] **Step 3: Push the feature branch, open a PR, wait for required checks, and merge it**
- [ ] **Step 4: Dispatch `release-holds.yml` on `main` and wait for completion**
- [ ] **Step 5: Verify live state has no released holds and an actual scan job starts**
