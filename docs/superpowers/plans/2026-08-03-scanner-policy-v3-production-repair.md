# Scanner Policy V3 Production Repair Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Follow superpowers:test-driven-development for every behavior change and superpowers:verification-before-completion before each release claim.

**Goal:** Make known OpenGrep parser-limit warnings nonfatal without weakening fail-closed scanner behavior, move both products to scanner policy 3, remove remaining Node 20 artifact actions, reset the two canary histories, and safely resume the priority queue.

**Architecture:** Keep diagnostic classification inside the OpenGrep adapter because it is an adapter-specific interpretation of OpenGrep's JSON contract. The versioned scanner policy marks the behavior boundary, while Technical Report V5 stays unchanged. Tavernary continues to accept only the active scanner-policy version for catalog status. Release recovery remains operationally separate from implementation: the queue stays paused, a dedicated reset removes only two canaries, and targeted scans prove the new behavior before resumption.

**Tech Stack:** TypeScript 6, Node.js 24, Zod 4, Vitest 4, GitHub Actions, GitHub Pages, GitHub CLI.

## Global constraints

- Preserve every valid finding when only approved parser warnings are present.
- Tolerate only exact policy-v3 diagnostic shapes; unknown, malformed, error-level, nonzero-exit, and execution failures stay fatal.
- Do not exclude minified or vendored files.
- Do not change Technical Report V5 or the Tavernary card/tree-link design.
- Pin GitHub Actions by immutable commit and enforce the exact Node 24 artifact pins.
- Keep the production queue staff-paused until both canaries have new policy-3 reports.
- Delete history only for Wandlight repository ID `1254077407` and Recursion repository ID `1285208664`.
- Preserve the user-owned untracked `F:\git\TavernKeeper\TavernKeeper\` directory and unrelated worktrees.

---

### Task 1: Lock the OpenGrep diagnostic contract with failing tests

**Files:**

- Modify: `tests/opengrep.test.ts`

- [ ] Add a runner helper that can return a configurable exit code and a report helper that can include diagnostics.
- [ ] Add a test proving code-2 `warn` / `Other syntax error` completes and preserves findings.
- [ ] Add a test proving code-3 `warn` / `PartialParsing` tuple completes and preserves findings.
- [ ] Add table tests proving unknown warnings, recognized diagnostics at error level, malformed diagnostic shapes, and nonzero exits reject with `SCANNER_FAILED` or `MALFORMED_SCANNER_OUTPUT` as appropriate.
- [ ] Run `npm.cmd test -- tests/opengrep.test.ts` and confirm the approved-warning tests fail against the current adapter.

### Task 2: Implement the bounded adapter classification

**Files:**

- Modify: `src/scanners/opengrep.ts`

- [ ] Add strict Zod diagnostic shapes for the two accepted parser limitations.
- [ ] Parse the overall report without weakening result validation.
- [ ] Complete only when every reported diagnostic matches an approved warning; otherwise preserve the existing fail-closed error classes.
- [ ] Keep execution errors and nonzero exit handling unchanged.
- [ ] Run `npm.cmd test -- tests/opengrep.test.ts` and confirm all adapter tests pass.
- [ ] Run `npm.cmd typecheck`.

### Task 3: Move TavernKeeper to scanner policy 3

**Files:**

- Rename: `config/scanner-policy.v2.json` to `config/scanner-policy.v3.json`
- Modify: `src/config/policy.ts`
- Modify: `src/orchestrator/session.ts`
- Modify: `src/report/contextual-report.ts`
- Modify: `src/cli/prepare-target.ts`
- Modify: `src/cli/policy-rescan.ts`
- Modify: `scripts/check-workflow-policy.mjs`
- Modify: `tests/policy.test.ts`
- Modify: `tests/workflows.test.ts`
- Modify: `tests/e2e/scan-fixtures.test.ts`
- Modify: version-sensitive fixtures and unit tests found by `rg "scanner-policy\\.v2|scanner_policy_version: \\"2\\"|z\\.literal\\(\\"2\\"\\)"`.
- Modify: `docs/operations.md`

- [ ] First update policy/version expectations so focused policy, workflow, session, and contextual-report tests fail against version 2.
- [ ] Rename the versioned policy file and schema/type exports to V3, set its version to `3`, and update all runtime load paths and literals.
- [ ] Update version-sensitive fixtures while retaining intentionally historical-policy tests where their purpose is rejection or history compatibility.
- [ ] Document bounded nonfatal parser warnings, fail-closed exceptions, and the reset requirement for behavior/output policy changes.
- [ ] Run focused policy, workflow, session, contextual-report, backlog, CLI, and E2E fixture tests.

### Task 4: Pin Node 24 artifact actions exactly

**Files:**

- Modify: `.github/workflows/scan-and-publish.yml`
- Modify: `scripts/check-workflow-policy.mjs`
- Modify: `tests/workflows.test.ts`

- [ ] Add failing expectations for exactly one upload at `actions/upload-artifact@043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` and exactly one download at `actions/download-artifact@3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c`.
- [ ] Replace the old action pins and preserve current artifact paths, encryption, retention, and trust boundaries.
- [ ] Run `npm.cmd test -- tests/workflows.test.ts` and `npm.cmd run workflows:check`.

### Task 5: Verify and publish the TavernKeeper implementation

- [ ] Run `npm.cmd install` if dependencies are absent or lockfile state requires it.
- [ ] Run `npm.cmd run check`.
- [ ] Run `npm.cmd run build`.
- [ ] Review `git diff --check`, the complete diff, and version-reference search results.
- [ ] Commit the implementation separately from the design and plan checkpoints.
- [ ] Push `codex/scanner-policy-v3`, open a ready pull request, verify all checks, merge through protected `main`, and record the exact merge SHA.

### Task 6: Move Tavernary's active reader to policy 3

**Files:**

- Modify: `scripts/security/tavernkeeper-reports.mjs`
- Modify: `scripts/security/tavernkeeper-reports.d.mts`
- Modify: `scripts/build-tavernkeeper-test-export.mjs`
- Modify: `tests/fixtures/tavernkeeper/scan-report.v5.valid.json`
- Modify: `tests/fixtures/tavernkeeper/report-index.v5.valid.json`
- Modify: active-version expectations in `tests/unit/tavernkeeper-reports.test.ts`, `tests/unit/tavernkeeper-status.test.ts`, `tests/unit/tavernkeeper-history-page.test.tsx`, and `tests/unit/build-catalog.test.ts`.

- [ ] First change test fixtures/expectations to policy 3 and confirm focused report/status tests fail against the active policy-2 constant.
- [ ] Set the active runtime and declaration literals to `3`; update generated test-export policy identity.
- [ ] Keep an explicit stale-policy test proving policy 2 no longer supplies an active card assessment.
- [ ] Run focused TavernKeeper import/status/history/build-catalog tests.
- [ ] Run Tavernary's complete check and production build commands from `package.json`.
- [ ] Review, commit, push, open a ready pull request, verify checks, merge through protected `main`, and record the exact merge SHA.

### Task 7: Deploy exact implementation SHAs while paused

- [ ] Dispatch or observe TavernKeeper Pages deployment for its policy-v3 merge SHA and approve only the expected protected environment.
- [ ] Dispatch or observe Tavernary Pages deployment for its policy-v3 merge SHA and approve only the expected protected environment.
- [ ] Verify both deployments use the exact merge SHAs and contain no Node 20 action annotations.
- [ ] Verify Tavernary treats policy-2 canary summaries as inactive before the destructive reset.

### Task 8: Reset only Wandlight and Recursion

**Files:**

- Delete: `reports/github/1254077407/**`
- Delete: `reports/github/1285208664/**`
- Modify: `reports/index.json`

- [ ] Start a dedicated reset branch from the deployed TavernKeeper policy-v3 `main`.
- [ ] Resolve and enumerate the exact tracked files for both repository IDs before deletion.
- [ ] Remove both report trees and both preferred-index entries; leave every other repository untouched.
- [ ] Run TavernKeeper report/site/workflow validation and build checks against the empty canary index.
- [ ] Commit, push, open, verify, and merge the dedicated reset pull request.
- [ ] Deploy the exact reset merge SHA.
- [ ] Run Tavernary import and verify its stored summaries and live catalog contain no Wandlight or Recursion scan assessment/history.

### Task 9: Produce clean policy-3 canaries

- [ ] Trigger one targeted scan for Wandlight (`1254077407`) while the general queue remains paused; approve only expected scanner/deploy environments.
- [ ] Verify scan, contextual review, publication, Pages deployment, and Tavernary import complete successfully.
- [ ] Trigger one targeted scan for Recursion (`1285208664`) and repeat the same proof.
- [ ] Verify each `history.json` contains exactly one entry, scanner policy `3`, and no policy-2 report ID.
- [ ] Verify each Tavernary card is current, links to the immutable Technical Report, and its source link targets `/tree/{full_sha}`.
- [ ] Verify scan/deploy/import runs have no Node 20 action annotations.

### Task 10: Clear retries and resume the priority queue

- [ ] While still staff-paused, use the supported staff retry operation for failed repository IDs `599524116` and `26291683`; approve the operations and confirm no scans dispatch while paused.
- [ ] Verify retry entries and the prior system circuit breaker are cleared without changing the coverage-start timestamp.
- [ ] Issue the supported staff resume operation and approve it.
- [ ] Verify the first resumed batch again follows the established `top_30` priority order.
- [ ] Verify scan jobs publish successfully, the circuit breaker remains clear, Pages deploys, and Tavernary imports the new results.
- [ ] Capture final authoritative state, exact deployment SHAs, workflow URLs, annotations, canary history counts, and live tree links for handoff.
