# Terminal Unscannable Retry Policy Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bound target-local scan cost to one immediate retry, one final attempt after a seven-day cooldown, and then repository-level removal until protected manual add-back.

**Architecture:** Keep `operations/state.json` authoritative by adding repository-level unscannable tombstones beside the durable queue. Queue transitions create tombstones on the third target failure; every automatic and targeted enrollment path respects them, while a protected staff operation removes exactly one tombstone. Operational issues remain a derived view that opens for cooling targets and closes with an explicit terminal explanation.

**Tech Stack:** TypeScript 6, Node.js 24, Zod 4, Vitest 4, GitHub Actions YAML, Bash, jq, GitHub CLI

**Spec:** `docs/superpowers/specs/2026-08-26-terminal-unscannable-retry-policy-design.md`

## Global Constraints

- Only failures whose descriptor domain is `target` consume the repository attempt budget.
- Failure one has `not_before: null`; failure two has a deadline exactly seven days after `last_failed_at`; failure three removes the repository from queue and active scans.
- Tombstones are keyed by repository source identity and block SHA changes, policy campaigns, coverage campaigns, catalog changes, and targeted wakes.
- Existing schema-version-3 files without `unscannable_targets` are upgraded in memory and serialized canonically without a schema-version bump.
- Existing queued targets with at least three consecutive failures become tombstones during migration or reconciliation without another scan; attempts one and two receive the new deadlines immediately.
- Only the protected `add-back` operation removes a tombstone.
- Protected `add-back` also seeds fresh staff-requested work so an exact current report cannot suppress the requested scan.
- Shared, security, and provider hold behavior remains unchanged.
- Terminal reconciliation updates and closes an existing incident but does not create a closed-only legacy issue.
- Incident reconciliation runs after both committed queue reconciliation and committed publication, and resumes partially applied label/close operations.

---

### Task 1: Canonical Unscannable State

**Files:**

- Modify: `src/operations/state.ts`
- Modify: `tests/operations-state.test.ts`

**Interfaces:**

- Produces: `UnscannableTargetSchema`, `UnscannableTarget`, and `OperationsState.unscannable_targets`.
- Produces: compatibility behavior in `parseOperationsState(value)` for schema-version-3 state written before this policy.
- Consumes: `ScanFailureHistoryEntrySchema`, `FailureDescriptorSchema`, and the existing source/repository/SHA validation.

- [ ] **Step 1: Write failing schema and compatibility tests**

Add tests that parse a valid tombstone, reject duplicate tombstone repository IDs, reject overlap with `scan_queue` or `active_scans`, and normalize legacy queue `chronic` values when the new collection is absent:

```ts
test("accepts and canonically sorts repository-level unscannable targets", () => {
  const parsed = parseOperationsState({
    ...initialOperationsState(now),
    unscannable_targets: [unscannable(43), unscannable(42)],
  });

  expect(
    JSON.parse(serializeOperationsState(parsed)).unscannable_targets.map(
      ({ repository_id }: { repository_id: number }) => repository_id,
    ),
  ).toEqual([42, 43]);
});

test("normalizes pre-policy chronic flags before strict validation", () => {
  const legacy = {
    ...initialOperationsState(now),
    scan_queue: {
      next_ticket: 2,
      entries: [{ ...failedEntry(2), chronic: false }],
    },
  };
  delete (legacy as { unscannable_targets?: unknown }).unscannable_targets;

  expect(parseOperationsState(legacy).scan_queue.entries[0]?.chronic).toBe(
    true,
  );
});
```

- [ ] **Step 2: Run the state tests and confirm RED**

Run: `npm.cmd test -- tests/operations-state.test.ts`

Expected: FAIL because `unscannable_targets` and the new chronic compatibility behavior do not exist.

- [ ] **Step 3: Implement the schema and compatibility parser**

Add an unscannable schema with the terminal evidence needed by incidents:

```ts
export const UnscannableTargetSchema = z
  .strictObject({
    source_id: SourceIdSchema,
    repository_id: SafePositiveIntegerSchema,
    repository: RepositorySchema,
    target_sha: FullShaSchema,
    unscannable_at: z.iso.datetime(),
    consecutive_failures: SafePositiveIntegerSchema.refine(
      (value) => value >= 3,
    ),
    total_failures: SafePositiveIntegerSchema,
    last_failure: FailureDescriptorSchema.refine(
      ({ domain }) => domain === "target",
    ),
    last_failed_at: z.iso.datetime(),
    failure_history: z.array(ScanFailureHistoryEntrySchema).min(1).max(4),
  })
  .superRefine((entry, context) => {
    if (entry.source_id !== `github-${entry.repository_id}`)
      context.addIssue({
        code: "custom",
        path: ["source_id"],
        message: "Unscannable source ID must match repository ID.",
      });
    if (entry.total_failures < entry.consecutive_failures)
      context.addIssue({
        code: "custom",
        path: ["total_failures"],
        message: "Total failures cannot be below the terminal streak.",
      });
    const latest = entry.failure_history.at(-1);
    if (
      latest?.failed_at !== entry.last_failed_at ||
      latest?.error_fingerprint !== failureFingerprint(entry.last_failure)
    )
      context.addIssue({
        code: "custom",
        path: ["failure_history"],
        message: "Terminal history must end with the latest failure.",
      });
  });
```

Add `unscannable_targets: z.array(UnscannableTargetSchema).default([])` to schema version 3. Enforce unique repository IDs and no overlap with queued or active repository IDs. Change the queue `chronic` invariant to `consecutive_failures >= 2`.

Before strict parsing, detect old schema-version-3 values that do not own an `unscannable_targets` property and rewrite each queue entry's `chronic` property to `consecutive_failures >= 2`. New-format state remains strictly validated:

```ts
export function parseOperationsState(value: unknown) {
  const compatible = normalizeLegacyRetryPolicyState(value);
  return OperationsStateSchema.parse(compatible);
}
```

Initialize the collection in `initialOperationsState` and sort it by `repository_id` in `serializeOperationsState`.

- [ ] **Step 4: Run the state tests and confirm GREEN**

Run: `npm.cmd test -- tests/operations-state.test.ts`

Expected: PASS.

- [ ] **Step 5: Commit the canonical state unit**

```powershell
git add src/operations/state.ts tests/operations-state.test.ts
git commit -m "feat: track unscannable scan targets"
```

### Task 2: Bounded Target-Failure Transitions

**Files:**

- Modify: `src/operations/retry-schedule.ts`
- Modify: `src/queue/durable-queue.ts`
- Modify: `src/operations/retry.ts`
- Modify: `tests/durable-queue.test.ts`
- Modify: `tests/retry.test.ts`

**Interfaces:**

- Consumes: `OperationsState.unscannable_targets` and `UnscannableTarget` from Task 1.
- Produces: `targetRetryNotBefore(failedAt, consecutiveFailures): string | null`.
- Produces: `rotateFailedTarget(...)` result with `terminal`, `entry`, and optional `unscannable` evidence.
- Produces: `FailureTransition.notification` values `none | chronic | unscannable` and a truthful boolean `terminal`.

- [ ] **Step 1: Replace infinite-retry expectations with the approved timeline**

Write tests for failure one, failure two, and failure three:

```ts
test("allows one immediate retry, cools for seven days, then terminates", () => {
  let state = appendQueuedTarget(initialOperationsState(firstAt), target);

  const first = rotateFailedTarget(state, failureAt(firstAt));
  expect(first).toMatchObject({ terminal: false });
  expect(first.entry).toMatchObject({
    consecutive_failures: 1,
    not_before: null,
    chronic: false,
  });

  const second = rotateFailedTarget(first.state, failureAt(secondAt));
  expect(second).toMatchObject({ terminal: false, becameChronic: true });
  expect(second.entry).toMatchObject({
    consecutive_failures: 2,
    not_before: "2026-08-11T00:01:00.000Z",
    chronic: true,
  });

  const third = rotateFailedTarget(second.state, failureAt(finalAt));
  expect(third).toMatchObject({ terminal: true });
  expect(third.state.scan_queue.entries).toEqual([]);
  expect(third.state.unscannable_targets).toEqual([
    expect.objectContaining({ repository_id: 42, consecutive_failures: 3 }),
  ]);
});
```

Update retry-layer tests to expect notifications `none`, `chronic`, and `unscannable`, with `terminal` false, false, and true. Retain the shared/security hold tests unchanged to prove they do not consume target failures.

- [ ] **Step 2: Run the focused retry tests and confirm RED**

Run: `npm.cmd test -- tests/durable-queue.test.ts tests/retry.test.ts`

Expected: FAIL on the old 5/30/120/360-minute infinite target schedule and fifth-failure chronic behavior.

- [ ] **Step 3: Implement the bounded target schedule and terminal transition**

Keep `scanRetryAt` for automatic holds and add a target-specific schedule:

```ts
const TARGET_COOLDOWN_MS = 7 * 24 * 60 * 60 * 1_000;

export function targetRetryNotBefore(
  failedAt: string,
  consecutiveFailures: number,
) {
  if (consecutiveFailures === 1) return null;
  if (consecutiveFailures === 2)
    return new Date(Date.parse(failedAt) + TARGET_COOLDOWN_MS).toISOString();
  throw new Error("Terminal target failure has no retry deadline.");
}
```

In `rotateFailedTarget`, build the next failure snapshot once. For counts one and two, rotate it to the queue tail. For count three, remove all queued and active entries for the repository and append a tombstone with the bounded history. Return the terminal snapshot without retaining it in the queue. Refuse to append a target whose repository already has a tombstone.

In `recordFailure`, map the target transition to:

```ts
return {
  state: nextState,
  entry: transitioned.entry,
  notification: transitioned.terminal
    ? "unscannable"
    : transitioned.entry.chronic
      ? "chronic"
      : "none",
  terminal: transitioned.terminal,
};
```

Do not change the automatic-hold schedule or threshold.

- [ ] **Step 4: Run the focused retry tests and confirm GREEN**

Run: `npm.cmd test -- tests/durable-queue.test.ts tests/retry.test.ts`

Expected: PASS.

- [ ] **Step 5: Commit the bounded transition unit**

```powershell
git add src/operations/retry-schedule.ts src/queue/durable-queue.ts src/operations/retry.ts tests/durable-queue.test.ts tests/retry.test.ts
git commit -m "feat: bound target scan retries"
```

### Task 3: Reconciliation, SHA Churn, and Legacy Drain

**Files:**

- Modify: `src/queue/reconcile.ts`
- Modify: `src/queue/durable-queue.ts`
- Modify: `src/cli/targeted-scan.ts`
- Modify: `tests/queue-sync.test.ts`
- Modify: `tests/cli.test.ts`

**Interfaces:**

- Consumes: terminal tombstones and the queue transition state from Tasks 1 and 2.
- Produces: `normalizeTerminalQueueEntries(state, at)` inside queue reconciliation.
- Produces: SHA replacement that preserves the full consecutive failure episode.
- Produces: targeted wake results `{ accepted: false, coalesced: true, ticket: null }` for tombstoned repositories.

- [ ] **Step 1: Write failing reconciliation tests**

Add tests proving all automatic enrollment paths are blocked and legacy state drains:

```ts
test("converts legacy third failures to tombstones without reseeding", () => {
  const synchronized = syncScanQueue({
    manifest: manifest(selected),
    index: emptyIndex,
    state: legacyFailedState(selected, 3),
    now,
    scannerPolicyVersion: "3",
  });

  expect(synchronized.state.scan_queue.entries).toEqual([]);
  expect(synchronized.state.unscannable_targets).toEqual([
    expect.objectContaining({ repository_id: selected.repository_id }),
  ]);
  expect(synchronized.summary.terminalized).toBe(1);
});

test("does not re-enroll a tombstone for SHA, staff, policy, or coverage demand", () => {
  const synchronized = syncScanQueue({
    manifest: manifest(target(41, 1, "b")),
    index: emptyIndex,
    state: stateWithEveryDemandAndTombstone(41),
    now,
    scannerPolicyVersion: "3",
  });
  expect(synchronized.state.scan_queue.entries).toEqual([]);
  expect(synchronized.state.policy_campaigns[0]?.status).toBe("completed");
  expect(synchronized.state.coverage_campaigns[0]?.status).toBe("completed");
});
```

Add a SHA-churn test whose queue entry has two failures and assert that the new SHA retains `consecutive_failures`, `not_before`, `last_failure`, and `failure_history`. Add targeted matrix and queue-update tests that coalesce a tombstoned repository.

- [ ] **Step 2: Run queue and targeted tests and confirm RED**

Run: `npm.cmd test -- tests/queue-sync.test.ts tests/cli.test.ts`

Expected: FAIL because old reconciliation resets the streak and every demand path can reseed the target.

- [ ] **Step 3: Implement terminal normalization and tombstone filtering**

At reconciliation start, transform any queue entry with `consecutive_failures >= 3` into the same tombstone shape as a terminal runtime failure, using `last_failure`, `last_failed_at`, and a last-only compatibility history if needed. Remove its repository from active scans. Add `terminalized` to `QueueSyncSummary`.

Build a set from `unscannable_targets.repository_id` and use it to:

```ts
const eligibleTargets = manifest.repositories
  .filter(({ repository_id }) => !unscannableRepositoryIds.has(repository_id))
  .filter((target) => {
    const entry = existingEntryByRepositoryId.get(target.repository_id);
    const report = preferredReportByRepositoryId.get(target.repository_id);
    return (
      hasActivePolicyCampaign(
        target,
        campaignState,
        input.scannerPolicyVersion,
      ) ||
      hasActiveCoverageCampaign(
        target,
        campaignState,
        input.scannerPolicyVersion,
      ) ||
      (observationInitialized && entry?.staff_requested === true) ||
      entry?.catalog_change !== undefined ||
      detectedCatalogChange.has(target.repository_id) ||
      !hasExactCurrentReport({
        target,
        report,
        scannerPolicyVersion: input.scannerPolicyVersion,
        contextualReviewPolicyVersion: input.contextualReviewPolicyVersion,
      })
    );
  })
  .sort(targetOrder);
```

Filter tombstoned IDs from active policy campaign `repository_ids` and coverage campaign `remaining_repository_ids`, completing campaigns that become empty. When replacing a queued SHA, copy the current failure fields rather than calling `blankEntry` for the failure episode:

```ts
entries.push({
  ...entry,
  source_id: target.source_id,
  repository: target.repository,
  target_sha: target.target_sha,
  rescan_not_before: rescanNotBefore,
  catalog_change: catalogChange,
});
```

Apply the same preservation rule in `replaceQueuedTargetSha`.

In both targeted builders, check the tombstone after validating the manifest target and return a coalesced result without appending or selecting work.

- [ ] **Step 4: Run queue, CLI, backlog, claim, and artifact tests**

Run: `npm.cmd test -- tests/queue-sync.test.ts tests/cli.test.ts tests/backlog.test.ts tests/claim-scans.test.ts tests/artifact-batch.test.ts`

Expected: PASS, proving scan selection and publication cannot bypass the tombstone.

- [ ] **Step 5: Commit the reconciliation unit**

```powershell
git add src/queue/reconcile.ts src/queue/durable-queue.ts src/cli/targeted-scan.ts tests/queue-sync.test.ts tests/cli.test.ts
git commit -m "feat: drain terminal scan failures"
```

### Task 4: Protected Manual Add-Back

**Files:**

- Modify: `src/queue/durable-queue.ts`
- Modify: `src/cli/retry.ts`
- Modify: `.github/workflows/staff-operations.yml`
- Modify: `tests/durable-queue.test.ts`
- Modify: `tests/retry.test.ts`
- Modify: `tests/workflows.test.ts`

**Interfaces:**

- Produces: `addBackUnscannableTarget(state, repositoryId): OperationsState`.
- Produces: retry CLI input `{ operation: "add-back", repository_id: number }`.
- Consumes: protected `tavernkeeper-staff` environment and ordinary reconciliation dispatch.

- [ ] **Step 1: Write failing add-back tests**

```ts
test("add-back removes exactly one tombstone and updates state time", () => {
  const next = applyRetryOperation(
    stateWithTombstones(42, 43),
    { operation: "add-back", repository_id: 42 },
    now,
  );
  expect(
    next.unscannable_targets.map(({ repository_id }) => repository_id),
  ).toEqual([43]);
  expect(next.updated_at).toBe(now);
});

test("add-back rejects a repository that is not unscannable", () => {
  expect(() =>
    applyRetryOperation(
      initialOperationsState(now),
      {
        operation: "add-back",
        repository_id: 42,
      },
      now,
    ),
  ).toThrow(/not unscannable/iu);
});
```

In workflow tests, require `add-back` in the operation choices, repository-ID JSON construction, protected environment, and reconcile dispatch.

- [ ] **Step 2: Run add-back tests and confirm RED**

Run: `npm.cmd test -- tests/durable-queue.test.ts tests/retry.test.ts tests/workflows.test.ts`

Expected: FAIL because neither the operation nor workflow choice exists.

- [ ] **Step 3: Implement the add-back operation**

Add a queue helper that validates the ID, requires a matching tombstone, and filters only that tombstone. Extend `OperationSchema` and `applyRetryOperation`:

```ts
if (operation.operation === "add-back")
  return parseOperationsState({
    ...addBackUnscannableTarget(state, operation.repository_id),
    updated_at: now,
  });
```

Add `add-back` to `.github/workflows/staff-operations.yml`, describe the ID as applying to retry, revoke, or add-back, include it in the validated repository-ID branch, and allow the existing reconcile step to run after it.

- [ ] **Step 4: Run add-back tests and confirm GREEN**

Run: `npm.cmd test -- tests/durable-queue.test.ts tests/retry.test.ts tests/workflows.test.ts`

Expected: PASS.

- [ ] **Step 5: Commit the protected recovery unit**

```powershell
git add src/queue/durable-queue.ts src/cli/retry.ts .github/workflows/staff-operations.yml tests/durable-queue.test.ts tests/retry.test.ts tests/workflows.test.ts
git commit -m "feat: add protected scan add-back"
```

### Task 5: Cooling and Terminal Incident Reconciliation

**Files:**

- Modify: `src/cli/exhausted.ts`
- Modify: `.github/workflows/scan-and-publish.yml`
- Modify: `tests/incidents.test.ts`
- Modify: `tests/workflows.test.ts`

**Interfaces:**

- Produces: `operationalIncidents(...).chronic_failures` for queued cooling targets at failure two.
- Produces: `operationalIncidents(...).unscannable_targets` with stable target incident keys.
- Consumes: exact target incident keys and the existing `scanner-operations` issue inventory.

- [ ] **Step 1: Write failing incident export and workflow tests**

```ts
test("exports cooling and terminal target incidents separately", () => {
  const incidents = operationalIncidents(stateWithCoolingAndTerminalTargets());
  expect(incidents.chronic_failures).toEqual([
    expect.objectContaining({ consecutive_failures: 2 }),
  ]);
  expect(incidents.unscannable_targets).toEqual([
    expect.objectContaining({
      target_incident_key: targetIncidentKey(43, terminalSha),
      repository_id: 43,
    }),
  ]);
});
```

Workflow assertions must require the `scanner-unscannable` label, terminal input iteration, a manual add-back close comment, and combined cooling/terminal keys protecting tombstones from the generic recovery close path. Assert that the terminal branch does not call `gh issue create`.

- [ ] **Step 2: Run incident tests and confirm RED**

Run: `npm.cmd test -- tests/incidents.test.ts tests/workflows.test.ts`

Expected: FAIL because terminal tombstones are not exported or reconciled.

- [ ] **Step 3: Implement incident export and exact lifecycle handling**

Map tombstones to incident records with `targetIncidentKey(repository_id, target_sha)`. In the workflow:

```bash
cooling_target_keys="$(jq -r '.chronic_failures[].target_incident_key' <<< "$incidents")"
terminal_target_keys="$(jq -r '.unscannable_targets[].target_incident_key' <<< "$incidents")"
active_target_keys="${cooling_target_keys}"$'\n'"${terminal_target_keys}"
gh label create scanner-unscannable --color 5319E7 --description "Removed from automatic TavernKeeper scans" --force
```

Change cooling issue text from unlimited retries to one remaining attempt after the seven-day deadline. For each terminal tombstone, resolve an existing issue by exact key, falling back once to repository ID plus target SHA for legacy bodies. If an issue exists, add `scanner-unscannable`, comment that automatic scans stopped and protected `add-back` is required, and close it if open. Do nothing when no issue exists. Keep the generic recovery close loop, but compare against the combined key set.

- [ ] **Step 4: Run incident and workflow tests and confirm GREEN**

Run: `npm.cmd test -- tests/incidents.test.ts tests/workflows.test.ts`

Expected: PASS.

- [ ] **Step 5: Commit the incident lifecycle unit**

```powershell
git add src/cli/exhausted.ts .github/workflows/scan-and-publish.yml tests/incidents.test.ts tests/workflows.test.ts
git commit -m "feat: close terminal scan incidents"
```

### Task 6: Integrated Verification and Pull Request Delivery

**Files:**

- No repository changes are expected; any scoped correction repeats its owning task's focused RED/GREEN cycle before this gate is rerun.

**Interfaces:**

- Consumes: all prior tasks.
- Produces: a green PR #222, merged to `main`, plus live reconciliation evidence.

- [ ] **Step 1: Run formatting on only the touched implementation files**

Run: `npx.cmd prettier --write docs/superpowers/specs/2026-08-26-terminal-unscannable-retry-policy-design.md docs/superpowers/plans/2026-08-26-terminal-unscannable-retry-policy.md src/operations/state.ts src/operations/retry-schedule.ts src/operations/retry.ts src/queue/durable-queue.ts src/queue/reconcile.ts src/cli/targeted-scan.ts src/cli/retry.ts src/cli/exhausted.ts tests/operations-state.test.ts tests/durable-queue.test.ts tests/retry.test.ts tests/queue-sync.test.ts tests/cli.test.ts tests/incidents.test.ts tests/workflows.test.ts .github/workflows/staff-operations.yml .github/workflows/scan-and-publish.yml`

Expected: only listed files are formatted; unrelated files remain unchanged.

- [ ] **Step 2: Run focused policy verification**

Run: `npm.cmd test -- tests/operations-state.test.ts tests/durable-queue.test.ts tests/retry.test.ts tests/queue-sync.test.ts tests/cli.test.ts tests/incidents.test.ts tests/workflows.test.ts tests/backlog.test.ts tests/claim-scans.test.ts tests/artifact-batch.test.ts`

Expected: PASS.

- [ ] **Step 3: Run the complete repository gate**

Run: `npm.cmd run check`

Expected: formatting, TypeScript, all Vitest files, and workflow-policy checks pass. If the known JavaScript normalizer timeout recurs once, rerun its focused file and then rerun the complete gate; do not dismiss a repeat failure.

- [ ] **Step 4: Inspect scope and perform a fresh diff review**

Run:

```powershell
git status --short
git diff --check origin/main...HEAD
git diff --stat origin/main...HEAD
git log --oneline origin/main..HEAD
```

Expected: only the cooldown policy, terminal retry policy, tests, workflows, spec, and plan are present; no user or generated artifacts are included.

- [ ] **Step 5: Push and verify PR checks**

Run:

```powershell
git push origin codex/weekly-scan-cooldown
gh pr checks 222 --watch
gh pr view 222 --json mergeStateStatus,reviewDecision,statusCheckRollup,headRefOid,url
```

Expected: all required checks pass and the head SHA matches the local branch.

- [ ] **Step 6: Merge the authorized PR and verify `main`**

Use ordinary merge first. If CODEOWNER review remains the only blocker, use the user's explicit authorization for `gh pr merge 222 --merge --admin`. Then verify the PR reports `MERGED` and `main` contains the exact merge commit.

- [ ] **Step 7: Reconcile live operations state and drain issues individually**

Dispatch `reconcile.yml` on `main`, watch it to completion, and verify `operations/state.json` contains tombstones with no overlapping queue or active entries. Inspect every remaining open issue and close only those whose canonical incident state proves recovery or terminal removal; leave unrelated safety findings open. Confirm no unscannable repository is selected by a subsequent queue claim.
