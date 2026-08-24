# Durable Report Freshness Recovery Implementation Plan

> **For Codex:** Execute task-by-task with red-green-refactor discipline. Keep the
> live emergency stop in place until the repository-global lineage canary passes.

**Goal:** Repair report lineage and continuously converge every manifest target to
the exact current SHA, scanner policy, and contextual-review policy.

**Architecture:** One shared helper derives the next repository-global report
version and predecessor. The publisher enforces that chain before immutable
writes. Durable queue synchronization admits missing exact tuples while existing
provenance and priority preserve staff/policy, new, updated, coverage, and tail
ordering.

**Tech stack:** TypeScript 6, Node.js 24, Zod, Vitest, GitHub Actions, GitHub CLI.

---

## Task 1: Lock repository-global lineage with regressions

**Files:**

- Add: `src/publish/report-lineage.ts`
- Modify: `src/cli/reconcile.ts`
- Modify: `src/cli/targeted-scan.ts`
- Test: `tests/cli.test.ts`

1. Add failing reconcile and targeted-scan expectations proving an existing
   repository version 3 produces version 4 and supersedes that preferred report
   even when its policy or target differs.
2. Run the focused test and confirm the old version-1 behavior fails.
3. Implement one pure repository-global lineage helper and use it from both
   request builders.
4. Run the focused test until green and remove duplicated lineage logic.

## Task 2: Enforce lineage at publication

**Files:**

- Modify: `src/publish/publisher.ts`
- Test: `tests/publisher.test.ts`

1. Add a failing integration test proving a non-advancing candidate is rejected
   before its immutable directory is written.
2. Validate every candidate against the current preferred repository report.
3. Preserve atomic mixed-batch prevalidation and preferred-index ordering.
4. Run publisher tests until green.

## Task 3: Reconcile every missing exact tuple

**Files:**

- Modify: `src/queue/reconcile.ts`
- Modify: `src/queue/backlog.ts`
- Test: `tests/bounded-queue.test.ts`
- Test: `tests/backlog.test.ts`
- Test: `tests/queue-sync.test.ts`

1. Add failing cases for no report, scanner-policy drift,
   contextual-review-policy drift, and an exact-current report.
2. Admit missing exact tuples while retaining catalog-change provenance,
   monotonic tickets, retry state, cooldowns, campaigns, and staff authority.
3. Classify ordinary tail freshness with the existing `changed` request reason.
4. Prove staff/policy, new, updated, coverage, and ordinary-tail priority remains
   deterministic.

## Task 4: Document the new invariant

**Files:**

- Modify: `README.md`
- Modify: `docs/architecture.md`
- Modify: `docs/operations.md`

1. Replace the obsolete new/updated-only wording with exact-tuple continuous
   eligibility and the complete priority order.
2. Document repository-global report lineage and publisher fail-closed behavior.
3. Keep target-local safety failures and cost limits explicit.

## Task 5: Verify and integrate

1. Format only the changed paths.
2. Run focused tests, `npm.cmd run check`, `npm.cmd run build`, and
   `npm.cmd run test:e2e`.
3. Inspect `git diff --check`, the full diff, generated artifacts, and
   secret/permission boundaries.
4. Commit, push `codex/report-version-recovery`, open a pull request, wait for
   hosted checks, review the final PR diff, and merge without weakening branch
   protections.

## Task 6: Execute the protected live recovery

1. Keep ordinary work stopped and set the policy-V5 canary gate.
2. Queue the known looped repository as the single staff canary and reconcile.
3. Verify the new report advances and supersedes the former preferred report,
   becomes preferred, and stays out of the reconciled queue.
4. Resume the bounded two-slot queue.
5. Verify live state, report-index exact tuples, issue reconciliation, Actions,
   and Pages deployment. Leave genuine target-local safety incidents open and
   report their exact status separately from the repaired platform defect.
