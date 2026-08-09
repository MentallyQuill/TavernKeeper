# New and Updated Projects Only Scanning Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace full-catalog queue seeding with a durable incremental cursor that scans only newly observed repository IDs and changed observed SHAs.

**Architecture:** Persist a sorted catalog observation in schema-3 operational state and durable `catalog_change` provenance on automatic queue entries. First synchronization establishes a hard baseline and removes pre-baseline work; later synchronizations atomically advance the observation and enqueue only manifest deltas, while report-backed changed-SHA work retains the rolling 48-hour deadline.

**Tech Stack:** TypeScript, Zod, Vitest, Node.js 24, GitHub Actions, committed JSON operational state.

## Global Constraints

- Keep `operations/state.json` secret-free and deterministically serialized.
- Initial baseline creation must enqueue no unreported legacy catalog target.
- New repository IDs run immediately; changed SHAs with a prior report run no earlier than `completed_at + 48 hours`.
- Same-SHA scanner-policy drift is not automatic work.
- Pre-baseline queue entries, including the canceled `envy-ai/ai_rpg` staff retry, do not survive cutover unless independently changed-SHA or active-campaign eligible.
- Emergency stop `CATALOG_WIDE_RESCAN_BLOCKED` remains active until stopped-state migration is verified.
- No external service or server is introduced; GitHub Actions and the configured model remain the only runtime resources.

---

### Task 1: Persist the incremental catalog cursor

**Files:**

- Modify: `src/operations/state.ts`
- Modify: `tests/operations-state.test.ts`

**Interfaces:**

- Produces: `CatalogChange = "new" | "updated"` on `ScanQueueEntry.catalog_change`.
- Produces: `CatalogObservation` at `OperationsState.catalog_observation`, shaped as `{ initialized_at: string; repositories: Array<{ repository_id: number; target_sha: string }> }`.
- Preserves: schema version `3`; older committed states parse with `catalog_observation` absent.

- [ ] **Step 1: Write failing state-contract tests**

Add tests that parse and deterministically serialize a state with a sorted observation and a queue entry carrying `catalog_change: "new"`:

```ts
const observed = parseOperationsState({
  ...initialOperationsState(at),
  catalog_observation: {
    initialized_at: at,
    repositories: [
      { repository_id: 42, target_sha: "a".repeat(40) },
      { repository_id: 43, target_sha: "b".repeat(40) },
    ],
  },
  scan_queue: {
    next_ticket: 2,
    entries: [{ ...entry(42, 1), catalog_change: "new" }],
  },
});
expect(serializeOperationsState(observed)).toContain('"catalog_change": "new"');
```

Add rejection cases for duplicate repository IDs, descending repository IDs, invalid SHAs, and any `catalog_change` value other than `new` or `updated`.

- [ ] **Step 2: Run the state tests and verify red**

Run: `npm.cmd test -- --run tests/operations-state.test.ts`

Expected: FAIL because strict schema-3 state rejects `catalog_observation` and queue entries reject `catalog_change`.

- [ ] **Step 3: Add the strict state schemas**

Add these contracts and integrate them into the existing strict schemas:

```ts
export const CatalogChangeSchema = z.enum(["new", "updated"]);

export const CatalogObservationSchema = z
  .strictObject({
    initialized_at: z.iso.datetime(),
    repositories: z.array(
      z.strictObject({
        repository_id: SafePositiveIntegerSchema,
        target_sha: FullShaSchema,
      }),
    ),
  })
  .refine(
    ({ repositories }) =>
      repositories.every(
        (entry, index) =>
          index === 0 ||
          repositories[index - 1]!.repository_id < entry.repository_id,
      ),
    {
      path: ["repositories"],
      message: "Observed repositories must be unique and sorted.",
    },
  );
```

Add `catalog_change: CatalogChangeSchema.optional()` to `ScanQueueEntrySchema`, add `catalog_observation: CatalogObservationSchema.nullable().optional()` to `OperationsStateSchema`, and initialize new states with `catalog_observation: null`. Export inferred types for both contracts.

- [ ] **Step 4: Run the state tests and verify green**

Run: `npm.cmd test -- --run tests/operations-state.test.ts`

Expected: all state tests pass with no warnings.

- [ ] **Step 5: Commit the state contract**

```powershell
git add src/operations/state.ts tests/operations-state.test.ts
git commit -m "feat(queue): persist catalog cursor"
```

---

### Task 2: Reconcile only manifest deltas

**Files:**

- Modify: `src/queue/reconcile.ts`
- Modify: `tests/queue-sync.test.ts`

**Interfaces:**

- Consumes: optional `OperationsState.catalog_observation` and optional `ScanQueueEntry.catalog_change` from Task 1.
- Produces: an updated observation and queue in the same returned `OperationsState`.
- Preserves: `automaticRescanNotBefore(...)` and its exact 48-hour deadline behavior.

- [ ] **Step 1: Replace the full-seeding test with failing baseline and delta tests**

Add a hard-baseline regression using pre-existing ordinary and staff entries:

```ts
test("initializes an incremental baseline without scanning legacy entries", () => {
  const legacy = manifest(target(41, 1), target(42, 2));
  const preBaseline = {
    ...appendQueuedTarget(
      appendQueuedTarget(initialOperationsState(now), legacy.repositories[0]!),
      legacy.repositories[1]!,
      { staffRequested: true },
    ),
    emergency_stop: {
      kind: "staff" as const,
      reason_code: "CATALOG_WIDE_RESCAN_BLOCKED",
      paused_at: now,
    },
  };

  const result = syncScanQueue({
    manifest: legacy,
    index: emptyIndex,
    state: preBaseline,
    now,
    scannerPolicyVersion: "4",
  });

  expect(result.state.scan_queue.entries).toEqual([]);
  expect(result.summary).toMatchObject({ seeded: 0, removed: 2 });
  expect(result.state.catalog_observation?.repositories).toEqual([
    { repository_id: 41, target_sha: target(41, 1).target_sha },
    { repository_id: 42, target_sha: target(42, 2).target_sha },
  ]);
});
```

Add separate tests that start from the returned baseline and prove:

```ts
expect(syncWith(target(43, 3)).scan_queue.entries[0]).toMatchObject({
  repository_id: 43,
  catalog_change: "new",
});

expect(syncWith(target(41, 1, "b")).scan_queue.entries[0]).toMatchObject({
  repository_id: 41,
  target_sha: "b".repeat(40),
  catalog_change: "updated",
});
```

Also assert that an unchanged unreported repository remains absent, and a report at the same SHA under scanner policy `3` does not queue merely because the current policy is `4`.

- [ ] **Step 2: Run queue synchronization tests and verify red**

Run: `npm.cmd test -- --run tests/queue-sync.test.ts`

Expected: the existing implementation seeds legacy entries and has no observation or provenance fields.

- [ ] **Step 3: Implement observation comparison and atomic advancement**

In `reconcileCurrentScanQueue`, create the prior observation map before filtering:

```ts
const observationInitialized = campaignState.catalog_observation != null;
const observedShaByRepositoryId = new Map(
  campaignState.catalog_observation?.repositories.map((entry) => [
    entry.repository_id,
    entry.target_sha,
  ]) ?? [],
);
const detectedCatalogChange = new Map<number, "new" | "updated">();
if (observationInitialized) {
  for (const target of manifest.repositories) {
    const observedSha = observedShaByRepositoryId.get(target.repository_id);
    if (observedSha === undefined)
      detectedCatalogChange.set(target.repository_id, "new");
    else if (observedSha !== target.target_sha)
      detectedCatalogChange.set(target.repository_id, "updated");
  }
}
```

Eligibility must be the union of active campaign work, post-baseline staff work, durable `catalog_change` work, detected manifest deltas, and a preferred report whose SHA differs. Do not use scanner-policy mismatch as ordinary eligibility.

When retaining or replacing an eligible entry, attach the existing or detected `catalog_change`. When seeding an eligible target, pass its detected kind or `updated` for a report-backed SHA mismatch into `blankEntry`. During baseline initialization, ignore pre-baseline staff flags.

Build and parse the next observation atomically with the queue:

```ts
const catalogObservation = {
  initialized_at:
    campaignState.catalog_observation?.initialized_at ?? input.now,
  repositories: manifest.repositories.map(({ repository_id, target_sha }) => ({
    repository_id,
    target_sha,
  })),
};
```

Include observation changes in the existing `changed` calculation and set `catalog_observation: catalogObservation` in `nextState`.

- [ ] **Step 4: Verify baseline, new-project, and unreported-update tests green**

Run: `npm.cmd test -- --run tests/queue-sync.test.ts`

Expected: all queue synchronization tests pass.

- [ ] **Step 5: Add 48-hour and repeated-update assertions under the new cursor**

Update the existing changed-SHA tests so their input state contains an initialized observation at SHA `a`. Assert SHA `b` receives `catalog_change: "updated"` and `rescan_not_before: "2026-08-04T12:00:00.000Z"`; then assert SHA `c` preserves the same ticket and deadline.

- [ ] **Step 6: Run queue and backlog suites**

Run: `npm.cmd test -- --run tests/queue-sync.test.ts tests/backlog.test.ts`

Expected: both files pass and the boundary at exactly 48 hours remains covered.

- [ ] **Step 7: Commit incremental reconciliation**

```powershell
git add src/queue/reconcile.ts tests/queue-sync.test.ts
git commit -m "fix(queue): scan only catalog changes"
```

---

### Task 3: Preserve provenance through retries and SHA replacement

**Files:**

- Modify: `src/queue/durable-queue.ts`
- Modify: `tests/durable-queue.test.ts`
- Modify: `tests/cli.test.ts`
- Modify: `tests/state-migration.test.ts`
- Modify: `docs/operations.md`

**Interfaces:**

- Consumes: `ScanQueueEntry.catalog_change` from Task 1.
- Produces: `appendQueuedTarget(..., { catalogChange?: "new" | "updated" })` and provenance-preserving replacement behavior.
- Preserves: explicit `staffRequested` behavior and target-local retry backoff.

- [ ] **Step 1: Add failing durable-transition tests**

Add a test that creates a new-project entry and rotates it after failure:

```ts
let state = appendQueuedTarget(initialOperationsState(at), target(42), {
  catalogChange: "new",
});
state = rotateFailedTarget(state, { target: target(42), failure, at }).state;
expect(state.scan_queue.entries[0]).toMatchObject({
  catalog_change: "new",
  consecutive_failures: 1,
});
```

Add a replacement test that starts with `catalogChange: "updated"`, replaces SHA `a` with SHA `b`, and expects the replacement to retain `catalog_change: "updated"`, its ticket, and total failure count.

- [ ] **Step 2: Run durable queue tests and verify red**

Run: `npm.cmd test -- --run tests/durable-queue.test.ts`

Expected: `appendQueuedTarget` rejects the new option or replacement drops provenance.

- [ ] **Step 3: Implement provenance-aware durable operations**

Change the append signature to:

```ts
options: {
  staffRequested?: boolean;
  catalogChange?: "new" | "updated";
} = {}
```

Add `catalog_change` when creating an entry. If the same SHA already exists, add missing catalog provenance without clearing `rescan_not_before`. In `replaceQueuedTargetSha`, copy `entry.catalog_change` onto the replacement. `rotateFailedTarget` already spreads the current entry and must remain unchanged.

- [ ] **Step 4: Update dependent CLI and migration fixtures**

Replace assumptions that a blank initial state seeds every manifest repository. Where a test is about staff priority, retry behavior, or policy campaigns rather than baseline behavior, initialize `catalog_observation` explicitly or append the relevant queue entries directly. Keep the targeted operator tests explicit staff requests.

In `tests/state-migration.test.ts`, expect migration to baseline ordinary catalog entries while still restoring normalized legacy retry records after the baseline is established.

- [ ] **Step 5: Rewrite operations documentation**

Replace the “initial coverage by popularity rank” and “growing catalog fairness” language with the exact incremental contract:

```md
The first incremental synchronization snapshots the current Tavernary manifest
without treating unreported legacy repositories as work. Later manifest deltas
enqueue a newly observed repository ID or a changed observed SHA. A changed SHA
with a preferred report remains delayed until 48 hours after that report's
completion. Scanner-policy changes require an explicit protected campaign.
```

Document that ticket fairness applies among new, updated, retry, and explicit staff work—not the legacy catalog.

- [ ] **Step 6: Run focused state, queue, CLI, and migration suites**

Run: `npm.cmd test -- --run tests/operations-state.test.ts tests/queue-sync.test.ts tests/durable-queue.test.ts tests/cli.test.ts tests/state-migration.test.ts tests/backlog.test.ts`

Expected: all focused tests pass with no warnings.

- [ ] **Step 7: Commit transition and documentation changes**

```powershell
git add src/queue/durable-queue.ts tests/durable-queue.test.ts tests/cli.test.ts tests/state-migration.test.ts docs/operations.md
git commit -m "fix(queue): retain change provenance"
```

---

### Task 4: Verify, release, migrate while stopped, and resume

**Files:**

- Verify: all modified files
- Live state: `operations/state.json` through existing GitHub Actions workflows only

**Interfaces:**

- Consumes: Tasks 1-3.
- Produces: merged main, a stopped catalog baseline, and resumed incremental automation.

- [ ] **Step 1: Run the complete local gate**

Run: `npm.cmd run check`

Expected: Prettier, TypeScript, all Vitest files, and all 12 workflow-policy checks pass.

- [ ] **Step 2: Inspect the exact diff and secret-free boundary**

Run:

```powershell
git diff origin/main...HEAD --check
git diff origin/main...HEAD -- src/operations/state.ts src/queue/reconcile.ts src/queue/durable-queue.ts docs/operations.md
rg -n -i "api[_-]?key|credential|raw[_-]?error|response[_-]?body|prompt" operations/state.json src/operations/state.ts
```

Expected: no whitespace errors, no unrelated edits, and no secret-bearing state field.

- [ ] **Step 3: Obtain independent review, push, and open a PR**

Review must focus on accidental legacy eligibility, baseline atomicity, changed-SHA cooldown preservation, and state compatibility. Address every Critical or Important finding, rerun `npm.cmd run check`, push `codex/new-updated-only-scanning`, and open a ready PR against `main`.

- [ ] **Step 4: Merge only after hosted checks pass**

Require both `check` and `scanner-toolchain` to pass for the exact PR head. Merge through the protected branch and record the exact merge SHA.

- [ ] **Step 5: Initialize the baseline while emergency-stopped**

Dispatch `reconcile.yml` once. Because `emergency_stop` remains set, plan and scan jobs must select zero targets. Verify all of these live invariants:

```text
emergency_stop.reason_code == CATALOG_WIDE_RESCAN_BLOCKED
catalog_observation.initialized_at is a valid ISO timestamp
catalog_observation.repositories exactly equals the current manifest ID/SHA set
scan_queue.entries contains no pre-baseline staff or ordinary legacy entry
```

Inspect every retained queue entry and prove it is independently changed-SHA or active-campaign eligible. Expect the canceled `envy-ai/ai_rpg` staff entry and ordinary legacy entries to be absent.

- [ ] **Step 6: Prove stopped synchronization is byte-stable**

Dispatch `reconcile.yml` a second time while stopped. Require `seeded: 0`, `replaced: 0`, `removed: 0`, zero planned targets, and no operational-state commit.

- [ ] **Step 7: Resume and verify incremental selection**

Run the protected `resume` staff operation. Inspect the first reconcile plan before allowing model work: it may include only retained changed-SHA targets discovered during baseline initialization. If none exist, the plan must contain zero targets and schedule no catalog continuation.

- [ ] **Step 8: Prove one real new-or-updated event**

On the next authentic Tavernary manifest delta, verify the committed observation changed for exactly that repository, its queue entry contains `catalog_change: "new"` or `"updated"`, and no unchanged unreported legacy repository was added. For an updated repository with a prior report, verify its effective due time is exactly the report completion plus 48 hours.

- [ ] **Step 9: Deploy exact merged main and verify Tavernary wake**

Run `deploy-pages.yml` with the exact merged main SHA after any report publication. Require source-on-main proof, exact public report-index verification, and successful Tavernary importer wake.
