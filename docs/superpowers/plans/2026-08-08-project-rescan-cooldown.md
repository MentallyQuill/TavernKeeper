# Project Rescan Cooldown Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Defer automatic changed-SHA rescans until 48 hours after a repository's latest completed report.

**Architecture:** Queue synchronization records an optional report-derived `rescan_not_before` timestamp on automatic changed-SHA entries. Batch planning combines that timestamp with the existing retry cooldown while bypassing it for staff requests and active policy campaigns.

**Tech Stack:** TypeScript 6, Zod 4, Vitest 4, Node.js 24

## Global Constraints

- Use a rolling 48-hour interval from the latest preferred report's `completed_at`.
- Apply the interval only to automatic rescans caused by a changed upstream SHA.
- Do not delay first scans, staff requests, policy campaigns, or failure retries.
- Repeated pushes update the queued SHA without extending the report-derived deadline.
- Preserve existing ticket fairness and schema-3 state compatibility.
- Do not modify the unrelated untracked nested `TavernKeeper/` tree.

---

### Task 1: Represent and synchronize automatic rescan eligibility

**Files:**

- Modify: `src/operations/state.ts`
- Modify: `src/queue/reconcile.ts`
- Test: `tests/queue-sync.test.ts`

**Interfaces:**

- Consumes: preferred `ReportIndexV5.reports[].completed_at` and manifest target identity.
- Produces: optional `ScanQueueEntry.rescan_not_before?: string`, derived as the latest repository report completion plus 48 hours.

- [ ] **Step 1: Write failing queue-synchronization tests**

Add literal fixtures and assertions proving that a changed-SHA entry receives
`rescan_not_before: "2026-08-04T12:00:00.000Z"` from a report completed at
`"2026-08-02T12:00:00.000Z"`, that another SHA replacement retains that exact
deadline, and that first-scan, staff-requested, and active-policy entries do not
carry the field.

- [ ] **Step 2: Run the focused tests and verify RED**

Run: `npm.cmd test -- tests/queue-sync.test.ts`

Expected: FAIL because queue entries do not expose or derive
`rescan_not_before`.

- [ ] **Step 3: Add the optional state field and derivation**

Extend `ScanQueueEntrySchema` with:

```ts
rescan_not_before: z.iso.datetime().optional(),
```

In `reconcileCurrentScanQueue`, locate the preferred report for each repository.
For an automatic target whose SHA differs from that report, derive:

```ts
new Date(Date.parse(report.completed_at) + 48 * 60 * 60 * 1_000).toISOString();
```

Apply it to seeded, replaced, and already-retained automatic changed-SHA
entries, so rollout also normalizes queue work committed before this feature.
Re-derive it from the report when the manifest SHA changes again. Omit or clear
it for first scans, staff entries, policy campaigns, and exact-SHA coverage.

- [ ] **Step 4: Run the focused tests and verify GREEN**

Run: `npm.cmd test -- tests/queue-sync.test.ts`

Expected: all queue synchronization tests pass.

- [ ] **Step 5: Commit the state and synchronization behavior**

```powershell
git add -- src/operations/state.ts src/queue/reconcile.ts tests/queue-sync.test.ts
git commit -m "feat(queue): defer automatic rescans"
```

### Task 2: Enforce the deadline in batch planning

**Files:**

- Modify: `src/queue/backlog.ts`
- Test: `tests/backlog.test.ts`
- Modify: `docs/operations.md`

**Interfaces:**

- Consumes: `ScanQueueEntry.not_before`, optional `rescan_not_before`, staff flag, active policy campaigns, and the planner's `now`.
- Produces: plans whose `targets`, `delayedEntries`, and `nextWakeAt` reflect the effective automatic rescan cooldown.

- [ ] **Step 1: Write failing planner boundary tests**

Create a changed-SHA queue entry with
`rescan_not_before: "2026-08-04T12:00:00.000Z"`. Assert that planning at
`"2026-08-04T11:59:59.999Z"` returns no target, one delayed entry, and the
literal next wake timestamp. Assert that planning at the exact deadline returns
the target. Add cases proving staff and active policy entries remain runnable,
and a retry entry continues to follow `not_before` without a rescan delay.

- [ ] **Step 2: Run the focused tests and verify RED**

Run: `npm.cmd test -- tests/backlog.test.ts`

Expected: FAIL because the planner ignores `rescan_not_before`.

- [ ] **Step 3: Compute effective entry eligibility**

Add focused helpers in `src/queue/backlog.ts` that determine whether an entry is
an active policy target and return its effective future timestamps. Ignore
`rescan_not_before` for staff requests, entries with a failure streak, and
active policy targets; otherwise combine it with `not_before` by using the
later applicable timestamp. Use this logic consistently for runnable selection,
delayed counts, hold probes, and `nextWakeAt`.

- [ ] **Step 4: Document the automatic rescan interval**

Update `docs/operations.md` to state that changed-SHA automatic rescans enter the
durable queue immediately but cannot run until 48 hours after the latest
completed report. State that further pushes replace the queued SHA without
moving the deadline, and list the four excluded scan types.

- [ ] **Step 5: Run focused tests and verify GREEN**

Run: `npm.cmd test -- tests/queue-sync.test.ts tests/backlog.test.ts`

Expected: all focused tests pass.

- [ ] **Step 6: Run the complete verification gate**

Run: `npm.cmd run check`

Expected: formatting, type checking, all Vitest tests, and workflow policy checks pass.

- [ ] **Step 7: Commit the planner and documentation**

```powershell
git add -- src/queue/backlog.ts tests/backlog.test.ts docs/operations.md
git commit -m "feat(queue): enforce 48-hour rescan limit"
```

### Task 3: Review and publish

**Files:**

- Review: all changes since `main`

**Interfaces:**

- Consumes: the complete feature-branch diff and successful verification output.
- Produces: a reviewed pull request merged into `main`.

- [ ] **Step 1: Request an independent code review**

Review the diff from the branch point through `HEAD` against the approved design
and require all critical or important findings to be resolved.

- [ ] **Step 2: Re-run verification after review fixes**

Run: `npm.cmd run check`

Expected: the complete gate passes after the final diff.

- [ ] **Step 3: Push and open a ready pull request**

Push `codex/project-rescan-48h-cooldown`, open a ready PR targeting `main`, and
include behavior, scope exclusions, and verification in the PR body.

- [ ] **Step 4: Wait for required checks and merge**

Wait for every required PR check to finish successfully, merge through the
repository's protected-branch route, and verify the PR reports a merged commit
on `main`.
