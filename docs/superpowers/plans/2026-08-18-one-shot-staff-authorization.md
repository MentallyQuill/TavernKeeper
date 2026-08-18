# One-Shot Staff Authorization Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Make every `staff_requested` flag authorize exactly one claimed scan attempt and add a supported idempotent revocation operation.

**Architecture:** The durable queue remains the source of target and retry history. `claimScanSlots` consumes `staff_requested` on only the queue entries it successfully claims, in the same returned state that records active leases. A new `revoke` staff operation removes the flag without deleting the queue entry, cooldown, or failure history.

**Tech Stack:** TypeScript 6, Zod 4, Vitest 4, GitHub Actions YAML, Node.js 24

**Spec:** `docs/2026-08-18-single-scan-authorization-retry-incident.md`

## Global Constraints

- Keep `MODEL_COST_MAINTENANCE` active until all repair and diagnostic work is complete.
- Do not dispatch a model-backed target scan.
- Preserve queue tickets, retry cooldowns, failure counts, and failure history.
- Consume authorization only for targets that actually receive an active-scan lease.
- All state transitions must remain idempotent and schema-valid.

---

### Task 1: Consume staff authorization at claim

**Files:**

- Modify: `tests/claims.test.ts`
- Modify: `tests/claim-scans.test.ts`
- Modify: `src/queue/claims.ts`

**Interfaces:**

- Consumes: `claimScanSlots({ state, plannedTargets, now, runId })`
- Produces: returned `state.scan_queue.entries` with `staff_requested` absent for each claimed target

- [x] **Step 1: Write the failing direct-claim regression test**

Add a test that queues one target with `{ staffRequested: true }`, claims it, and asserts that the returned queue entry has no `staff_requested` property while the claimed `PlannedTarget.queueEntry` still records why it was selected.

- [x] **Step 2: Run the direct-claim test and verify RED**

Run: `npm.cmd test -- tests/claims.test.ts`

Expected: FAIL because the returned state still contains `staff_requested: true`.

- [x] **Step 3: Implement atomic consumption**

In `claimScanSlots`, build the claimed repository-ID set and map `state.scan_queue.entries` before parsing `nextState`:

```ts
const claimedRepositoryIds = new Set(
  claimed.map(({ target }) => target.repository_id),
);
const queueEntries = state.scan_queue.entries.map((entry) => {
  if (!claimedRepositoryIds.has(entry.repository_id)) return entry;
  const { staff_requested: _consumed, ...consumed } = entry;
  return consumed;
});
```

Use `queueEntries` in the returned operations state. Do not mutate `claimed`, because downstream request construction still needs the planned reason.

- [x] **Step 4: Run the direct-claim test and verify GREEN**

Run: `npm.cmd test -- tests/claims.test.ts`

Expected: all claim tests pass.

- [x] **Step 5: Add orchestration regression coverage**

Add a `buildScanClaims` test whose initial state contains one `staff_requested` target under `POLICY_V5_CANARY_GATE`. Assert one request is returned, its reason is `staff`, the active lease exists, and the persisted queue entry no longer contains `staff_requested`.

- [x] **Step 6: Run claim orchestration tests**

Run: `npm.cmd test -- tests/claims.test.ts tests/claim-scans.test.ts tests/backlog.test.ts`

Expected: all tests pass.

### Task 2: Add idempotent staff revocation

**Files:**

- Modify: `tests/durable-queue.test.ts`
- Modify: `tests/cli.test.ts`
- Modify: `src/queue/durable-queue.ts`
- Modify: `src/cli/retry.ts`

**Interfaces:**

- Produces: `revokeQueuedTargetStaffRequest(state, repositoryId): OperationsState`
- Produces: `TAVERNKEEPER_OPERATION={"operation":"revoke","repository_id":N}`

- [x] **Step 1: Write failing queue revocation tests**

Test that revocation removes only `staff_requested`, preserves `ticket`, `not_before`, failure counters, `failure_history`, and other entries, and returns an equal state when the flag is already absent.

- [x] **Step 2: Run durable queue tests and verify RED**

Run: `npm.cmd test -- tests/durable-queue.test.ts`

Expected: FAIL because `revokeQueuedTargetStaffRequest` is not exported.

- [x] **Step 3: Implement the queue operation**

Add `revokeQueuedTargetStaffRequest` beside `prioritizeQueuedTargetRetry`. Validate the positive repository ID, require that the repository is queued, remove only `staff_requested`, and parse the result through `OperationsStateSchema`.

- [x] **Step 4: Run durable queue tests and verify GREEN**

Run: `npm.cmd test -- tests/durable-queue.test.ts`

Expected: all durable queue tests pass.

- [x] **Step 5: Write the failing CLI operation test**

Extend `applyRetryOperation` coverage with `{ operation: "revoke", repository_id: 42 }`. Assert the flag is absent, the emergency stop remains unchanged, and `updated_at` advances only when revocation changes state.

- [x] **Step 6: Run the CLI test and verify RED**

Run: `npm.cmd test -- tests/cli.test.ts`

Expected: FAIL because `OperationSchema` rejects `revoke`.

- [x] **Step 7: Wire the CLI operation**

Add the strict `revoke` schema member, call `revokeQueuedTargetStaffRequest`, and preserve idempotent timestamps by returning the original state when no field changed.

- [x] **Step 8: Run CLI and queue tests**

Run: `npm.cmd test -- tests/cli.test.ts tests/durable-queue.test.ts`

Expected: all tests pass.

### Task 3: Expose revocation through the protected staff workflow

**Files:**

- Modify: `tests/workflows.test.ts`
- Modify: `.github/workflows/staff-operations.yml`
- Modify: `scripts/check-workflow-policy.mjs`
- Modify: `docs/operations.md`

**Interfaces:**

- Consumes: workflow input `operation=revoke`, `repository_id=<positive integer>`
- Produces: Publisher-authenticated state-only commit without reconciliation dispatch

- [x] **Step 1: Write failing workflow contract tests**

Assert `revoke` is an allowed operation, uses the same sanitized request construction as `retry`, retains the Publisher boundary, and does not dispatch reconciliation for `pause`, `migrate`, or `revoke`.

- [x] **Step 2: Run workflow tests and verify RED**

Run: `npm.cmd test -- tests/workflows.test.ts`

Expected: FAIL because the workflow has no `revoke` option.

- [x] **Step 3: Update workflow and policy**

Add `revoke` to the choice list, route both `retry` and `revoke` through the repository-ID request builder, exclude `revoke` from the reconcile-dispatch condition, and update the canonical policy string exactly.

- [x] **Step 4: Document the operation**

Add the command and its one-field-only semantics to `docs/operations.md`.

- [x] **Step 5: Run workflow and focused queue verification**

Run: `npm.cmd test -- tests/workflows.test.ts tests/claims.test.ts tests/claim-scans.test.ts tests/durable-queue.test.ts tests/cli.test.ts`

Run: `npm.cmd run workflows:check`

Expected: all tests pass and workflow policy reports success.
