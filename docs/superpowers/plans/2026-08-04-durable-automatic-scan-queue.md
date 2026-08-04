# Durable Automatic Scan Queue Implementation Plan

> **For Codex:** Execute this plan in order with test-driven development. Do not introduce any automatic staff gate, terminal retry, or deployment dependency while translating the approved design.

**Goal:** Replace TavernKeeper's derived/terminal retry system and Tavernary's all-or-nothing importer with small persisted ticket queues whose failures rotate to the then-current tail and remain automatically retryable.

**Architecture:** TavernKeeper schema version 3 stores the complete eligible scan order in `operations/state.json`. A protected queue-sync job materializes catalog changes before the reconciler selects the lowest due tickets. Scan publication records success or rotates each failure, while Pages reconciliation runs independently. Tavernary stores a parallel report-import ticket ledger and handles each synthesis inside its own error boundary.

**Tech stack:** TypeScript 6, Node.js 24, Zod 4, Vitest 4, GitHub Actions, JavaScript `.mjs` importer scripts.

**Approved design:** `docs/superpowers/specs/2026-08-04-durable-automatic-scan-queue-design.md`

---

## Cross-task coordination boundary

The Codex task **Scan Failure Resilience** (`019fcb70-17a9-7e50-8ca4-2e3d6f5de175`) is concurrently inspecting the live failed runs. At plan time it is working read-only from `main`/a temporary audit copy and has not created an implementation branch.

Ownership is divided as follows:

- **Scan Failure Resilience owns:** live incident inventory; reproduction of SillyBunny, Marinara, Lumiverse, and related scanner/model failures; scanner-specific root causes; failure-descriptor evidence; and any narrowly scoped fixes inside acquisition, inventory, history, `src/scanners/**`, contextual review/model, or target evidence preparation.
- **This plan owns:** schema-3 queue state and migration; durable ticket allocation; scheduling/retry transitions; publication state recording; `reconcile`, `retry`, `targeted-scan`, `scan-and-publish`, and Pages liveness; Tavernary's import ledger/workflow; operations documentation; protected integration; and live proof of queue movement.
- **Shared interface:** a scan phase returns one sanitized `FailureDescriptor`. This plan may change only the fallback scheduling classification in `src/operations/failure.ts`; it will not change scanner-specific detection or model response semantics. The other task must not make failure descriptors capable of pausing, exhausting, or bypassing the durable queue.
- **Integration order:** if Scan Failure Resilience produces a narrow patch first, rebase this branch onto that merged `main` and rerun the queue gates. Otherwise merge the durable queue first and have the narrow scanner patch rebase onto schema 3. Never combine unrelated incident fixes into the queue PR merely to avoid a rebase.

Before editing any scanner/model file or any queue/state/workflow file not assigned above, re-inspect the other task's latest activity and branch/worktree state. This preserves parallel progress without giving either task ambiguous ownership.

---

## Task 1: Define TavernKeeper schema version 3 and queue primitives

**Files:**

- Create: `src/queue/durable-queue.ts`
- Modify: `src/operations/state.ts`
- Modify: `src/operations/retry-schedule.ts`
- Test: `tests/operations-state.test.ts`
- Create: `tests/durable-queue.test.ts`

**Step 1: Write failing schema tests**

Add tests that require:

- `scan_queue.next_ticket` and queue entries with unique positive tickets;
- a nullable explicit `emergency_stop` instead of automatic `pause`;
- a queue entry with unbounded `consecutive_failures`, `total_failures`, nullable `not_before`/`last_failure`, and derived `chronic` consistency;
- canonical serialization by ascending ticket;
- rejection of duplicate repository identities, duplicate tickets, invalid timestamps, and `next_ticket` values not greater than every issued ticket.

Run:

```powershell
npm.cmd test -- tests/operations-state.test.ts tests/durable-queue.test.ts
```

Expected: FAIL because schema version 3 and durable queue functions do not exist.

**Step 2: Implement the minimal state types**

In `state.ts`, replace the schema-2 retry/hold fields with:

```ts
interface ScanQueueEntry {
  source_id: string;
  repository_id: number;
  repository: string;
  target_sha: string;
  ticket: number;
  consecutive_failures: number;
  total_failures: number;
  not_before: string | null;
  last_failure: FailureDescriptor | null;
  last_failed_at: string | null;
  chronic: boolean;
}
```

Retain `coverage_started_at`, `active_scans`, and `policy_campaigns`. Replace `pause` with `emergency_stop`, whose schema permits only `kind: "staff"`. Sort queue entries by ticket during serialization.

In `durable-queue.ts`, implement pure helpers for queue lookup, next-ticket allocation, due ordering, success removal, SHA replacement, and failure rotation. Use `Number.isSafeInteger` through Zod constraints.

**Step 3: Change retry timing to last-failure capped timing**

Expose a helper whose delays are 5 minutes, 30 minutes, 2 hours, and then 6 hours for every later failure. Base each timestamp on `last_failed_at`, not the first failure.

**Step 4: Run focused tests**

```powershell
npm.cmd test -- tests/operations-state.test.ts tests/durable-queue.test.ts
```

Expected: PASS.

**Step 5: Commit**

```powershell
git add src/operations/state.ts src/operations/retry-schedule.ts src/queue/durable-queue.ts tests/operations-state.test.ts tests/durable-queue.test.ts
git commit -m "feat: add durable scan queue state"
```

## Task 2: Reconcile manifests into stable tickets and migrate live state

**Files:**

- Modify: `src/operations/migrate-state.ts`
- Modify: `src/cli/migrate-state.ts`
- Create: `src/cli/sync-queue.ts`
- Modify: `package.json`
- Modify: `tests/state-migration.test.ts`
- Modify: `tests/durable-queue.test.ts`
- Modify: `tests/cli.test.ts`

**Step 1: Write failing synchronization and migration tests**

Cover these exact cases:

- initial manifest seeding follows V3 `popularity_rank` and assigns consecutive tickets;
- a newly discovered project is appended after every existing ticket;
- a changed SHA preserves its existing ticket and resets the consecutive streak/cooldown;
- covered and ineligible targets leave the queue;
- active campaigns add otherwise-covered targets;
- schema-2 target retries, exhausted targets, security failures, and shared holds become ordinary queue entries;
- a schema-2 automatic pause is discarded, while a schema-2 staff pause becomes `emergency_stop`;
- repeated synchronization without input changes is byte-stable.

Run:

```powershell
npm.cmd test -- tests/state-migration.test.ts tests/durable-queue.test.ts tests/cli.test.ts
```

Expected: FAIL on the new migration and CLI contracts.

**Step 2: Implement pure synchronization**

Add `syncScanQueue({ manifest, index, state, now, scannerPolicyVersion })`. It must accept schema-2 or schema-3 input, migrate legacy entries first, reconcile coverage/current SHAs, append missing targets in popularity order, and return `{ state, changed, summary }`.

The legacy migration must deduplicate multiple legacy retry/hold references by repository, retain the highest known failure count, and assign those targets in deterministic current catalog order during initial materialization. It must never emit an automatic stop.

**Step 3: Implement the queue-sync CLI**

`npm run --silent queue:sync` fetches the fixed Tavernary manifest, reads the committed report index from the checkout, reads `operations/state.json`, writes the canonical synchronized state, and prints only a sanitized JSON summary. `--check` validates that synchronization would be a no-op without writing.

Use the committed report index for queue coverage so scan assignment does not depend on Pages availability.

**Step 4: Run focused tests and commit**

```powershell
npm.cmd test -- tests/state-migration.test.ts tests/durable-queue.test.ts tests/cli.test.ts
git add src/operations/migrate-state.ts src/cli/migrate-state.ts src/cli/sync-queue.ts package.json tests/state-migration.test.ts tests/durable-queue.test.ts tests/cli.test.ts
git commit -m "feat: synchronize catalog into scan tickets"
```

## Task 3: Schedule strictly by due ticket and rotate every failure

**Files:**

- Modify: `src/queue/backlog.ts`
- Modify: `src/operations/retry.ts`
- Modify: `src/operations/failure.ts`
- Modify: `src/cli/reconcile.ts`
- Modify: `src/cli/retry.ts`
- Modify: `src/cli/exhausted.ts`
- Test: `tests/backlog.test.ts`
- Test: `tests/retry.test.ts`
- Test: `tests/failure.test.ts`

**Step 1: Write failing liveness tests**

Require:

- selection by ascending due ticket, capped at five;
- cooling entries are skipped without ticket mutation;
- a formerly cooling entry precedes later tickets as soon as it is due;
- failure assigns exactly the current `next_ticket` and increments it once;
- the fifth and sixth failures remain queued and `terminal` is always false;
- later catalog arrivals have larger tickets than a previously rotated failure;
- success removes only the exact immutable target;
- unknown system/orchestrator errors classify as target-local diagnostic failures and never as security/global stops;
- an explicit emergency stop is the sole reason a normal plan is blocked.

Run:

```powershell
npm.cmd test -- tests/backlog.test.ts tests/retry.test.ts tests/failure.test.ts
```

Expected: FAIL on retry-first, exhaustion, holds, and automatic pause behavior.

**Step 2: Replace derived backlog behavior**

Make `planBatch` join queue entries to current manifest metadata, select lowest due tickets, and derive `new`, `changed`, `policy`, or `retry` only for request/report metadata. Remove lane aging, retry-first sorting, shared recovery probes, exhaustion skips, and automatic blocked states.

Return:

```ts
{
  (targets,
    totalRemaining,
    runnableRemaining,
    delayedEntries,
    nextWakeAt,
    emergencyStopped);
}
```

**Step 3: Replace retry transitions**

`recordFailure` calls the queue rotation helper for every diagnostic domain. Its notification becomes `"chronic"` at five failures and on subsequent incident-worthy recurrences, but `terminal` remains false. `recordSuccess` removes the exact entry. Delete production dependence on shared holds and exhausted lists.

**Step 4: Improve fallback classification**

Keep explicit security diagnostics for reporting, but make an unknown orchestrator exception `{ domain: "target", component: "orchestrator" }`. No classifier result may directly control global scheduling.

**Step 5: Run focused tests and commit**

```powershell
npm.cmd test -- tests/backlog.test.ts tests/retry.test.ts tests/failure.test.ts
git add src/queue/backlog.ts src/operations/retry.ts src/operations/failure.ts src/cli/reconcile.ts src/cli/retry.ts src/cli/exhausted.ts tests/backlog.test.ts tests/retry.test.ts tests/failure.test.ts
git commit -m "feat: rotate scan failures without blocking"
```

## Task 4: Make publication queue-authoritative

**Files:**

- Modify: `src/publish/artifact-batch.ts`
- Modify: `src/publish/publisher.ts`
- Modify: `src/cli/publish.ts`
- Test: `tests/artifact-batch.test.ts`
- Test: `tests/publisher.test.ts`
- Test: `tests/scan-atomicity.test.ts`

**Step 1: Write failing mixed-batch tests**

Prove that a batch containing successes plus target/shared/security/unknown failures:

- publishes every complete successful report;
- removes successful tickets;
- rotates each failed ticket once in deterministic requested-target order;
- returns no `continuation_blocked`, `terminal_failures`, or hold counts;
- returns queue telemetry including remaining, due, delayed, next wake, and chronic incidents;
- never publishes a candidate paired with a failure or a candidate that fails exact-target authentication.

Run:

```powershell
npm.cmd test -- tests/artifact-batch.test.ts tests/publisher.test.ts tests/scan-atomicity.test.ts
```

Expected: FAIL on the legacy hold/exhaustion result contract.

**Step 2: Implement outcome recording**

Keep the existing encrypted, authenticated artifact boundary. Apply successful and failed outcomes to the ledger, publish only complete reports, serialize one state update, and return automatic-continuation telemetry. Sort outcomes by their request order before allocating failure tickets so filesystem traversal cannot change queue order.

**Step 3: Run focused tests and commit**

```powershell
npm.cmd test -- tests/artifact-batch.test.ts tests/publisher.test.ts tests/scan-atomicity.test.ts
git add src/publish/artifact-batch.ts src/publish/publisher.ts src/cli/publish.ts tests/artifact-batch.test.ts tests/publisher.test.ts tests/scan-atomicity.test.ts
git commit -m "feat: persist scan outcomes in queue order"
```

## Task 5: Decouple TavernKeeper queue, scanning, and Pages workflows

**Files:**

- Modify: `.github/workflows/reconcile.yml`
- Modify: `.github/workflows/scan-and-publish.yml`
- Modify: `.github/workflows/targeted-scan.yml`
- Modify: `.github/workflows/retry.yml`
- Modify: `.github/workflows/deploy-pages.yml`
- Modify: `scripts/check-workflow-policy.mjs`
- Modify: `tests/workflows.test.ts`

**Step 1: Write failing workflow tests first**

Require:

- queue synchronization uses one reviewed Publisher App token consumer with bounded non-force push retries;
- planning reads the just-synchronized committed state;
- reconciliation contains no live Pages digest prerequisite;
- scan continuation depends on queue work/cooldown only and does not need deployment;
- Pages deployment and next reconciliation are independent jobs after publication;
- a Tavernary targeted wake validates the repository ID but appends through normal queue reconciliation instead of bypassing existing tickets;
- legacy strings `continuation_blocked`, `shared_holds`, `security_holds`, `terminal_failures`, and `deploy_required` are absent from common scheduling;
- workflow policy still pins actions, isolates secrets, authenticates artifacts, and limits each Publisher token to its reviewed push block.

Run:

```powershell
npm.cmd test -- tests/workflows.test.ts
```

Expected: FAIL on the current deployment gate and continuation dependency.

**Step 2: Add the protected sync job**

In `reconcile.yml`, add a serialized job that checks out `main`, creates the existing Publisher App token, runs queue synchronization, and commits/pushes only `operations/state.json` when changed. Use the same three-attempt pull/retry/no-force pattern as report publication. The plan job checks out `main` after sync and consumes only committed state.

**Step 3: Remove deployment gating and bypasses**

Delete the live Pages digest comparison and `recover-pages` prerequisite. Have report publication fan out to:

- an automatic Pages deployment request; and
- the next reconciliation when queue work remains.

Neither job needs the other. Change targeted wake handling to enter the normal synchronization/reconciliation path.

**Step 4: Extend workflow policy and run checks**

```powershell
npm.cmd test -- tests/workflows.test.ts
npm.cmd run workflows:check
```

Expected: PASS.

**Step 5: Commit**

```powershell
git add .github/workflows/reconcile.yml .github/workflows/scan-and-publish.yml .github/workflows/targeted-scan.yml .github/workflows/retry.yml .github/workflows/deploy-pages.yml scripts/check-workflow-policy.mjs tests/workflows.test.ts
git commit -m "feat: decouple scan and deployment loops"
```

## Task 6: Update TavernKeeper state, documentation, and full verification

**Files:**

- Modify: `operations/state.json`
- Modify: `docs/architecture.md`
- Modify: `docs/operations.md`
- Modify as required: tests that construct schema-2 state fixtures

**Step 1: Convert remaining fixtures through public helpers**

Update test builders to produce schema-3 state. Keep explicit migration fixtures for schema versions 1 and 2. Do not mechanically preserve obsolete hold assertions.

**Step 2: Update operational documentation**

Document ticket order, automatic rotation, chronic incidents, explicit emergency stop, independent deployment, and the five-minute recovery cadence. Remove instructions that tell staff to resume common failures.

**Step 3: Materialize a checked-in schema-3 state**

Run the queue sync against current fixed inputs or use the tested migration CLI to produce canonical schema-3 state. Confirm it contains no automatic stop and no exhausted/no-man's-land retry state.

**Step 4: Run the complete TavernKeeper gate**

```powershell
npm.cmd run check
git diff --check
git status --short
```

Expected: formatting, typecheck, all unit/e2e-independent tests, workflow policy, and diff checks pass.

**Step 5: Commit**

```powershell
git add operations/state.json docs/architecture.md docs/operations.md src tests
git commit -m "docs: document automatic queue recovery"
```

## Task 7: Create the Tavernary worktree and establish importer RED tests

**Repository/worktree:** `F:\git\TavernKeeper\.worktrees\tavernary-durable-security-import`

**Files:**

- Modify: `scripts/security/import-tavernkeeper-reports.mjs`
- Create: `scripts/security/tavernkeeper-import-state.mjs`
- Create: `data/security/tavernkeeper-import-state.json`
- Modify: `tests/unit/tavernkeeper-reports.test.ts`
- Modify: `tests/unit/tavernkeeper-synthesis.test.ts`
- Modify: `tests/unit/workflows.test.ts`

**Step 1: Create an isolated Tavernary branch from current `origin/main`**

```powershell
git -c safe.directory=F:/git/Tavernary -C F:\git\Tavernary pull --ff-only origin main
git -c safe.directory=F:/git/Tavernary -C F:\git\Tavernary worktree add F:\git\TavernKeeper\.worktrees\tavernary-durable-security-import -b codex/durable-tavernkeeper-import origin/main
npm.cmd install
npm.cmd test -- tests/unit/tavernkeeper-reports.test.ts tests/unit/tavernkeeper-synthesis.test.ts tests/unit/workflows.test.ts
```

Expected: the existing focused baseline passes before edits.

**Step 2: Write failing per-report and ordering tests**

Require:

- discovered report IDs receive stable monotonic tickets;
- one synthesis throw/validation failure rotates only that report and processing continues;
- successes after a failure are present in the saved snapshot;
- a fifth failure remains queued and chronic;
- later report discoveries receive tickets after a previously requeued failure;
- a failed replacement retains the previous successful preferred report;
- state/snapshot output is canonical and repeatable.

Run the same focused test command. Expected: FAIL before implementation.

## Task 8: Implement Tavernary's durable per-report import loop

**Files:** same as Task 7.

**Step 1: Implement the import ledger module**

Use a schema-version-1 JSON document with `next_ticket` and entries containing `report_id`, `ticket`, `attempts`, `not_before`, `last_failure`, and `chronic`. Provide pure reconcile, due selection, success, and rotate helpers. Use the same 5m/30m/2h/6h capped cooldown policy.

**Step 2: Put every synthesis behind its own boundary**

Refactor the importer to:

1. reconcile deployed index additions into the ledger;
2. process due entries by ticket;
3. catch and sanitize each report's synthesis error;
4. continue later due reports;
5. update preferred IDs only for successfully synthesized reports;
6. atomically write the final snapshot and ledger even when some reports remain pending;
7. exit successfully for handled per-report failures and expose pending/due/next-wake telemetry.

**Step 3: Run focused tests and commit**

```powershell
npm.cmd test -- tests/unit/tavernkeeper-reports.test.ts tests/unit/tavernkeeper-synthesis.test.ts
git add scripts/security/import-tavernkeeper-reports.mjs scripts/security/tavernkeeper-import-state.mjs data/security/tavernkeeper-import-state.json tests/unit/tavernkeeper-reports.test.ts tests/unit/tavernkeeper-synthesis.test.ts
git commit -m "feat: retry TavernKeeper imports independently"
```

## Task 9: Decouple Tavernary import continuation from deployment

**Files:**

- Modify: `.github/workflows/import-tavernkeeper-reports.yml`
- Modify as required: Tavernary deployment reusable workflow
- Modify: `tests/unit/workflows.test.ts`

**Step 1: Add failing workflow assertions**

Require the import/commit job to succeed with partial report outcomes, an independent continuation dispatch when pending due work exists, and a deployment job that does not gate continuation. Retain the six-hour schedule as the durable fallback.

**Step 2: Implement independent fan-out**

After committing snapshot/ledger changes, dispatch or call deployment and continuation as siblings. A deployment failure may raise an incident but must not make pending imports terminal or prevent the next scheduled run.

**Step 3: Run Tavernary gates and commit**

```powershell
npm.cmd test -- tests/unit/workflows.test.ts
npm.cmd run check
git diff --check
git status --short
git add .github/workflows/import-tavernkeeper-reports.yml tests/unit/workflows.test.ts
git commit -m "feat: decouple security import deployment"
```

## Task 10: Review, publish through protected branches, and prove live progress

**Step 1: Review both complete diffs**

Inspect each branch from its merge base, confirm only intended files changed, and run a dedicated code-review pass focused on queue invariants, migration safety, credential boundaries, and workflow recursion/concurrency.

**Step 2: Re-run clean verification**

In each worktree run its complete check from a clean dependency install where practical. Record exact passing output and branch SHA.

**Step 3: Push and open protected integration PRs**

Push only the two reviewed feature branches. Open PRs describing the shared invariant and repository-specific verification. Wait for required checks, address actionable failures, and merge through the repositories' protected process.

**Step 4: Verify TavernKeeper live recovery**

Using authenticated GitHub CLI calls:

- confirm the merged main SHA and successful queue-sync/reconcile workflow;
- inspect committed schema-3 state and count eligible queued projects;
- confirm the legacy automatic hold is gone;
- confirm the previously failing project has a durable ticket and no terminal state;
- observe at least one later scan/publication cycle advance independently of Pages status;
- verify exact Pages deployment SHA and live report index convergence.

**Step 5: Verify Tavernary live import**

- confirm merged main and import workflow results;
- inspect the committed import ledger/snapshot after a mixed-success run;
- prove a failing report did not prevent a later report from importing;
- verify the exact deployed Tavernary commit and hydrated security presentation.

**Step 6: Final closeout**

Report source SHAs, PR/merge state, all verification gates, exact deployed SHAs, live queue counts/progress, and any automatically cooling entries. Do not call the feature complete while either repository is only local, checks are pending, deployment truth is unknown, or live queue movement has not been observed.
