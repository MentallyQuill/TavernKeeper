# Bounded Two-Lane Catalog Scanning Implementation Plan

> **For Codex:** Execute task-by-task with red-green-refactor discipline. Keep the
> live staff emergency stop in place until the merged selector has committed the
> freshly calculated cohort.

**Goal:** Restore new/updated plus one-time 20+20 eligibility, maintain two global
scan slots, and publish each completed repository independently.

**Architecture:** Reconciliation becomes a committed synchronize-and-claim
transition over the existing durable JSON state. It fans claimed targets into
single-request reusable workflows. Each child applies and publishes one encrypted
outcome, replays its deterministic transition after push races, and dispatches
reconciliation to refill its released slot.

**Tech stack:** TypeScript 6, Node.js 24, Zod, Vitest, GitHub Actions, GitHub CLI.

---

## Task 1: Restore the fresh one-time coverage campaign

**Files:**

- Add: `src/coverage/select-campaign.ts`
- Add: `src/cli/coverage-campaign.ts`
- Add: `.github/workflows/coverage-campaign.yml`
- Modify: `src/operations/state.ts`
- Modify: `package.json`
- Test: `tests/coverage-campaign.test.ts`
- Test: `tests/state-migration.test.ts`

1. Restore campaign contract and selector tests, updating the fixed identifier for
   the new requested recalculation.
2. Run the focused tests and confirm they fail because selection/CLI support is
   absent.
3. Implement bounded popularity and stable-release selection with atomic failure,
   response limits, and idempotent state creation.
4. Add the protected workflow and package script.
5. Run focused tests until green, then refactor duplicated campaign helpers.

## Task 2: Restore bounded queue eligibility and ordering

**Files:**

- Modify: `src/queue/reconcile.ts`
- Modify: `src/queue/backlog.ts`
- Modify: `src/queue/durable-queue.ts`
- Modify: `src/cli/reconcile.ts`
- Modify: `src/cli/sync-queue.ts`
- Test: `tests/queue-sync.test.ts`
- Test: `tests/backlog.test.ts`
- Test: `tests/durable-queue.test.ts`

1. Add failing cases proving version-only entries are removed, new and updated
   entries survive, selected campaign members are eligible, and priority is
   new/updated/coverage.
2. Restore coverage advancement and cooldown-aware eligibility while retaining
   contextual-policy-v4 exact coverage checks and catalog observation metadata.
3. Remove the full-catalog `version` reason and make ordinary missing policy tuples
   ineligible.
4. Run focused queue tests and refactor the eligibility predicate into one shared
   source of truth.

## Task 3: Add durable two-slot claiming and stale recovery

**Files:**

- Add: `src/queue/claims.ts`
- Add: `src/cli/claim-scans.ts`
- Modify: `src/operations/state.ts`
- Modify: `package.json`
- Test: `tests/claims.test.ts`
- Test: `tests/cli.test.ts`

1. Write failing tests for zero/one/two available slots, exact-target claim
   identity, no duplicate claims, stopped/held queues, and two-hour expiry.
2. Implement a pure synchronize-and-claim transition that returns both the next
   state and single-target scan requests.
3. Implement the CLI that fetches the manifest, reads index/state, writes the
   claimed state atomically, and emits scheduling metadata.
4. Run focused tests and ensure serialization keeps active identities sorted and
   unique.

## Task 4: Convert orchestration to independent single-target lanes

**Files:**

- Modify: `.github/workflows/reconcile.yml`
- Modify: `.github/workflows/scan-and-publish.yml`
- Modify: `.github/workflows/retry.yml`
- Modify: `.github/workflows/targeted-scan.yml`
- Modify: `scripts/check-workflow-policy.mjs`
- Test: `tests/workflows.test.ts`

1. Add failing workflow-policy tests for committed claims, reusable-workflow
   matrix fan-out capped at two, a single request per child, explicit job
   timeouts, and removal of batch-wide publication.
2. Replace reconcile's read-only batch plan with an optimistic
   fetch/reapply/commit claim operation. On push conflict, rerun claiming against
   current `main` before exposing final outputs.
3. Invoke one reusable child per claimed request with `max-parallel: 2`.
4. Remove prepare/scan matrices from the child workflow and make each artifact,
   publisher invocation, deployment, and continuation target-specific.
5. Run workflow tests and the workflow policy checker until green.

## Task 5: Make publication safe under parallel completion

**Files:**

- Modify: `.github/workflows/scan-and-publish.yml`
- Modify: `src/publish/artifact-batch.ts`
- Modify: `src/publish/publisher.ts`
- Modify: `src/cli/publish.ts`
- Test: `tests/artifact-batch.test.ts`
- Test: `tests/publisher.test.ts`
- Test: `tests/workflows.test.ts`

1. Add failing tests proving one outcome applies one transition and clears only its
   matching active claim.
2. Preserve the encrypted artifact while plaintext is removed; on push rejection,
   reset to current `origin/main`, decrypt again into a clean temporary directory,
   and reapply publication before recommitting.
3. Ensure a report deploy starts immediately after that target's commit and the
   continuation dispatch does not wait on peer workflows.
4. Run publication and workflow tests until green.

## Task 6: Documentation, generated contracts, and full validation

**Files:**

- Modify: `README.md`
- Modify: `docs/architecture.md`
- Modify: `docs/operations.md`
- Modify: generated schemas only if contract generation changes them

1. Document frozen 20+20 scope, exact priority, two durable slots, independent
   publication, lease recovery, and operator cutover/recovery commands.
2. Run `npm.cmd run format` on explicitly changed files.
3. Run `npm.cmd run check`.
4. Run `npm.cmd run build`.
5. Run `npm.cmd run test:e2e`.
6. Review `git diff --check`, the complete diff, and secret/permission boundaries.

## Task 7: Publish and perform the protected live cutover

1. Commit the implementation intentionally and push
   `codex/bounded-two-lane-scanning`.
2. Open a pull request, wait for hosted CI, review the final PR diff, and merge.
3. While still stopped, dispatch reconciliation and verify the catalog-wide queue
   collapses to only genuine new/updated/staff/policy work.
4. Dispatch and approve the protected fresh coverage workflow. Verify exactly 20
   popular IDs, up to 20 latest-release IDs, the exact deduplicated union, and no
   claims while stopped.
5. Resume the queue and verify two distinct single-target child pipelines are in
   progress.
6. Verify the first completed target creates a report commit and Pages deployment
   while the peer is still running, then report live queue, active-slot, campaign,
   report-index, and workflow evidence.
