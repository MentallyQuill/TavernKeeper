# Catalog-First Failure Quarantine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Keep failed exact target SHAs fail-closed while completing primary catalog coverage before bounded, eligible retries.

**Architecture:** Extend operations-state V2 compatibly with explicit automatic/manual retry mode and bounded failure history. Split planning into primary and retry lanes, add typed target-local diagnostics at known scanner/evidence/model boundaries, and key target incidents by exact target identity while retaining shared/security behavior.

**Tech Stack:** TypeScript 6, Node.js 24, Zod 4, Vitest 4, GitHub Actions, PowerShell.

## Global Constraints

- Failed targets remain completely unpublished.
- Primary catalog work always precedes target retry work.
- Deterministic target failures require a new SHA or explicit targeted scan.
- Automatic target retry delays remain 5 minutes, 30 minutes, and 2 hours, measured from the latest failure.
- Four failed queued attempts exhaust one exact target SHA.
- Shared failures do not consume target-local attempt budgets.
- Unknown generic failures remain security holds.
- Keep operations-state schema version 2 readable without a destructive migration.
- Do not alter Technical Report V5, scanner policy, batch size five, or concurrency two.
- Preserve the user-owned untracked `F:\git\TavernKeeper\TavernKeeper\` directory.

---

### Task 1: Add typed diagnostics and retry eligibility

**Files:**

- Modify: `src/operations/failure.ts`
- Modify: `src/scanners/types.ts`
- Modify: `src/scanners/opengrep.ts`
- Modify: `src/context/evidence-context.ts`
- Test: `tests/failure.test.ts`
- Test: `tests/opengrep.test.ts`
- Test: `tests/evidence-context.test.ts`

**Interfaces:**

- Produces `TargetRetryModeSchema` and `retryModeForFailure(failure)`.
- Adds safe diagnostics `parser_syntax`, `rule_timeout`, and `evidence_non_text`.
- Adds failure component `evidence-context` and code `EVIDENCE_CONTEXT_UNSUPPORTED`.
- `ScannerError` accepts an optional safe scanner diagnostic.

- [ ] **Step 1: Write RED failure-mode tests**

Add assertions equivalent to:

```ts
expect(
  retryModeForFailure({
    code: "SCANNER_FAILED",
    domain: "target",
    component: "opengrep",
    diagnostic: "parser_syntax",
  }),
).toBe("manual");
expect(
  retryModeForFailure({
    code: "SCANNER_TIMEOUT",
    domain: "target",
    component: "opengrep",
  }),
).toBe("automatic");
expect(
  retryModeForFailure({
    code: "MODEL_INVALID_RESPONSE",
    domain: "target",
    component: "contextual-model",
    diagnostic: "assessment_technical_explanation",
  }),
).toBe("manual");
```

Also prove an unknown plain `Error` still becomes
`{ code: "CLI_FAILED", domain: "security", component: "orchestrator" }`.

- [ ] **Step 2: Write RED OpenGrep diagnostic tests**

Add fixtures with exit code 0 and diagnostics shaped like the live failures:

```ts
{ code: 3, level: "warn", type: "Syntax error" }
{ code: 2, level: "warn", type: "Timeout" }
```

Assert syntax throws `ScannerError` with `diagnostic === "parser_syntax"`,
timeout throws with `diagnostic === "rule_timeout"`, and a mixed report chooses
`parser_syntax`.

- [ ] **Step 3: Write RED non-text evidence test**

Construct one binary inventory file and one current scanner finding for it.
Assert `buildEvidenceContextGroups()` rejects with an object classified as:

```ts
{
  code: "EVIDENCE_CONTEXT_UNSUPPORTED",
  domain: "target",
  component: "evidence-context",
  diagnostic: "evidence_non_text",
}
```

- [ ] **Step 4: Run focused tests and confirm RED**

Run:

```powershell
npm.cmd test -- tests/failure.test.ts tests/opengrep.test.ts tests/evidence-context.test.ts
```

Expected: failures because the new diagnostics, retry classifier, and typed
evidence error do not exist.

- [ ] **Step 5: Implement bounded classification**

In `failure.ts`, add:

```ts
export const TargetRetryModeSchema = z.enum(["automatic", "manual"]);
export type TargetRetryMode = z.infer<typeof TargetRetryModeSchema>;

export function retryModeForFailure(
  failureInput: FailureDescriptor,
): TargetRetryMode {
  const failure = FailureDescriptorSchema.parse(failureInput);
  if (failure.domain !== "target") {
    throw new Error("Retry mode requires a target failure.");
  }
  if (failure.code === "SCANNER_TIMEOUT") return "automatic";
  if (["CHECKOUT_FAILED", "HISTORY_FAILED"].includes(failure.code)) {
    return "automatic";
  }
  return "manual";
}
```

Extend the bounded enums and target-code set for the three diagnostics,
`evidence-context`, and `EVIDENCE_CONTEXT_UNSUPPORTED`.

- [ ] **Step 6: Implement scanner and evidence errors**

Add an optional diagnostic to `ScannerError`. In OpenGrep, reduce non-tolerated
diagnostics to a safe priority: syntax before timeout before generic failure.
Throw no raw diagnostic object.

Add an `EvidenceContextError` carrying only the four safe classifier fields.
Throw it when `readVerifiedText()` receives `file.kind !== "text"`. Retain the
existing generic errors for hash mismatch, missing inventory entries, and
unexpected conditions.

- [ ] **Step 7: Run focused tests and confirm GREEN**

```powershell
npm.cmd test -- tests/failure.test.ts tests/opengrep.test.ts tests/evidence-context.test.ts
npm.cmd run typecheck
```

Expected: all focused tests and typecheck pass.

- [ ] **Step 8: Commit Task 1**

```powershell
git add src/operations/failure.ts src/scanners/types.ts src/scanners/opengrep.ts src/context/evidence-context.ts tests/failure.test.ts tests/opengrep.test.ts tests/evidence-context.test.ts
git commit -m "fix(scan): type target-local failures"
```

---

### Task 2: Persist retry mode and bounded failure history

**Files:**

- Modify: `src/operations/state.ts`
- Modify: `src/operations/retry.ts`
- Modify: `src/operations/retry-schedule.ts`
- Test: `tests/operations-state.test.ts`
- Test: `tests/retry.test.ts`
- Test: `tests/state-migration.test.ts`

**Interfaces:**

- `TargetRetryEntry` gains optional legacy-compatible `retry_mode` and
  `failure_history` fields.
- New writes always populate both fields.
- `targetRetryAt(lastFailedAt, attempt)` schedules from the latest failure.

- [ ] **Step 1: Write RED state-schema tests**

Prove an old V2 entry without extension fields still parses. Prove a new manual
entry may be nonexhausted with `next_retry_at: null`. Prove an automatic entry
must have the exact scheduled time from `last_failed_at`.

Use this history shape:

```ts
failure_history: [
  {
    failed_at: "2026-08-04T00:00:00.000Z",
    failure,
    error_fingerprint: failureFingerprint(failure),
  },
],
```

Reject histories longer than four, out of chronological order, or with a
fingerprint that does not match its descriptor.

- [ ] **Step 2: Write RED transition tests**

Cover:

- first deterministic failure produces `retry_mode: "manual"`, attempt 1,
  null wake, and one history row;
- an explicit second failed scan appends a different descriptor without
  resetting attempts;
- first transient failure produces `retry_mode: "automatic"` and a five-minute
  wake measured from `last_failed_at`;
- a second transient failure at a much later time produces a 30-minute wake
  measured from that second failure;
- the fourth failure exhausts either mode; and
- shared failures retain their shared probe behavior and do not use target
  history semantics.

- [ ] **Step 3: Run state tests and confirm RED**

```powershell
npm.cmd test -- tests/operations-state.test.ts tests/retry.test.ts tests/state-migration.test.ts
```

- [ ] **Step 4: Implement compatible state extensions**

Add strict schemas for history rows and optional extension fields. Treat absent
`retry_mode` as `retryModeForFailure(entry.failure)` at read sites. Retain
schema version 2 and V1-to-V2 migration output compatibility.

For target failures, build the next entry as:

```ts
const retryMode = retryModeForFailure(input.failure);
const failureHistory = [
  ...(input.existing?.failure_history ?? []),
  {
    failed_at: input.at,
    failure: input.failure,
    error_fingerprint: input.fingerprint,
  },
].slice(-4);
```

Automatic nonexhausted entries call `targetRetryAt(input.at, attempt)`; manual
and exhausted entries store null.

- [ ] **Step 5: Run state tests and confirm GREEN**

```powershell
npm.cmd test -- tests/operations-state.test.ts tests/retry.test.ts tests/state-migration.test.ts
npm.cmd run typecheck
```

- [ ] **Step 6: Commit Task 2**

```powershell
git add src/operations/state.ts src/operations/retry.ts src/operations/retry-schedule.ts tests/operations-state.test.ts tests/retry.test.ts tests/state-migration.test.ts
git commit -m "fix(queue): persist quarantine eligibility"
```

---

### Task 3: Make primary catalog work precede retries

**Files:**

- Modify: `src/queue/backlog.ts`
- Modify: `src/cli/reconcile.ts`
- Modify: `.github/workflows/reconcile.yml`
- Modify: `.github/workflows/retry.yml`
- Test: `tests/backlog.test.ts`
- Test: `tests/cli.test.ts`
- Test: `tests/workflows.test.ts`

**Interfaces:**

- `BatchPlan` adds `primaryRemaining`, `automaticRetries`,
  `manualQuarantines`, and `exhaustedTargets`.
- Planner selects target retries only when no primary candidates remain.

- [ ] **Step 1: Write RED planner tests**

Add cases asserting:

```ts
expect(plan.targets.map(({ reason }) => reason)).toEqual(["new", "changed"]);
expect(plan.primaryRemaining).toBeGreaterThan(0);
expect(plan.automaticRetries).toBe(1);
```

when a due automatic retry exists beside primary work. Add separate cases that
prove:

- due automatic retries are selected after primary becomes empty;
- manual and exhausted targets are counted but never dispatched;
- a new SHA for a manually quarantined repository is primary changed work;
- a delayed-only automatic retry exposes `nextWakeAt`; and
- shared recovery probes still override both lanes.

- [ ] **Step 2: Run planner tests and confirm RED**

```powershell
npm.cmd test -- tests/backlog.test.ts tests/cli.test.ts tests/workflows.test.ts
```

- [ ] **Step 3: Split primary and retry planning**

Replace retry-first sorting with two arrays. Keep existing popularity/lane
comparators for primary work. Sort retries by
`[next_retry_at,last_failed_at,repository_id,target_sha]` only inside the retry
phase.

Return no automatic retries while `primary.length > 0`, even if all retry wake
times are overdue. Continue to count quarantines in `totalRemaining`.

- [ ] **Step 4: Extend reconcile output and summaries**

Emit snake-case JSON fields:

```ts
{
  primary_remaining,
  automatic_retries,
  manual_quarantines,
  exhausted_targets,
}
```

Retain existing fields for workflow compatibility. Add the new counts to job
summaries without using them as a weaker continuation gate.

- [ ] **Step 5: Run planner/workflow tests and confirm GREEN**

```powershell
npm.cmd test -- tests/backlog.test.ts tests/cli.test.ts tests/workflows.test.ts
npm.cmd run workflows:check
npm.cmd run typecheck
```

- [ ] **Step 6: Commit Task 3**

```powershell
git add src/queue/backlog.ts src/cli/reconcile.ts .github/workflows/reconcile.yml .github/workflows/retry.yml tests/backlog.test.ts tests/cli.test.ts tests/workflows.test.ts
git commit -m "fix(queue): finish catalog before retries"
```

---

### Task 4: Make contextual-review retries corrective

**Files:**

- Modify: `src/model/contextual-prompt.ts`
- Modify: `src/model/contextual-review.ts`
- Modify: `src/model/openai-compatible-client.ts`
- Test: `tests/contextual-prompt.test.ts`
- Test: `tests/contextual-review.test.ts`
- Test: `tests/contextual-review-contract.test.ts`

**Interfaces:**

- `buildContextualReviewPrompt(group, repair?)` accepts a trusted bounded repair
  descriptor.
- Immediate retry occurs only when the request changes.

- [ ] **Step 1: Write RED repair tests**

Use a provider mock that first returns an invalid
`assessment_technical_explanation`, then a valid response. Assert the second
request contains:

```json
{
  "diagnostic": "assessment_technical_explanation"
}
```

in trusted system instructions and does not contain rejected prose.

Add a mock returning the same invalid field twice. Assert only two provider
calls occur even when `maxImmediateAttempts` is three. Preserve the existing
test that valid context expansion changes evidence and may use another call.

- [ ] **Step 2: Run model tests and confirm RED**

```powershell
npm.cmd test -- tests/contextual-prompt.test.ts tests/contextual-review.test.ts tests/contextual-review-contract.test.ts
```

- [ ] **Step 3: Implement bounded repair prompts**

Define:

```ts
interface ContextualReviewRepair {
  diagnostic: ModelResponseDiagnostic;
}
```

Append a trusted instruction stating which response field violated the schema.
Track the prior serialized repair descriptor. If the next caught retryable
error produces the same descriptor, throw it immediately. Never add completion
content or raw Zod messages to the prompt.

- [ ] **Step 4: Run model tests and confirm GREEN**

```powershell
npm.cmd test -- tests/contextual-prompt.test.ts tests/contextual-review.test.ts tests/contextual-review-contract.test.ts
npm.cmd run typecheck
```

- [ ] **Step 5: Commit Task 4**

```powershell
git add src/model/contextual-prompt.ts src/model/contextual-review.ts src/model/openai-compatible-client.ts tests/contextual-prompt.test.ts tests/contextual-review.test.ts tests/contextual-review-contract.test.ts
git commit -m "fix(model): make review retries corrective"
```

---

### Task 5: Key target incidents by exact target identity

**Files:**

- Create: `src/operations/incidents.ts`
- Modify: `src/cli/exhausted.ts`
- Modify: `.github/workflows/scan-and-publish.yml`
- Test: `tests/incidents.test.ts`
- Test: `tests/workflows.test.ts`

**Interfaces:**

- `targetIncidentKey(repositoryId, targetSha)` returns SHA-256 of the approved
  tuple.
- Exhaustion output includes `target_incident_key` and `failure_history`.

- [ ] **Step 1: Write RED incident identity tests**

Assert the same repository/SHA produces one key across different failure
fingerprints, while another repository or SHA produces another key.

- [ ] **Step 2: Run incident tests and confirm RED**

```powershell
npm.cmd test -- tests/incidents.test.ts tests/workflows.test.ts
```

- [ ] **Step 3: Implement incident output and workflow dedupe**

Emit:

```ts
{
  target_incident_key: targetIncidentKey(repository_id, target_sha),
  repository_id,
  target_sha,
  failure,
  failure_history,
}
```

Search issues first for `Target incident key: <key>`, then for both legacy
`Repository ID` and `Target commit` fields. Reuse the oldest match. Do not use a
class fingerprint alone for target issue dedupe. Keep shared-hold issue logic
fingerprint-based.

- [ ] **Step 4: Run incident/workflow tests and confirm GREEN**

```powershell
npm.cmd test -- tests/incidents.test.ts tests/workflows.test.ts
npm.cmd run workflows:check
```

- [ ] **Step 5: Commit Task 5**

```powershell
git add src/operations/incidents.ts src/cli/exhausted.ts .github/workflows/scan-and-publish.yml tests/incidents.test.ts tests/workflows.test.ts
git commit -m "fix(ops): dedupe exact-target incidents"
```

---

### Task 6: Document, verify, and prepare safe recovery

**Files:**

- Modify: `docs/architecture.md`
- Modify: `docs/operations.md`
- Modify: `README.md`

**Interfaces:**

- Documents catalog-first ordering, automatic/manual quarantine, exact-target
  issues, and the security-hold recovery sequence.

- [ ] **Step 1: Update operator documentation**

Document the exact planner order, retry modes, latest-failure backoff, manual
targeted retry, new-SHA behavior, four-attempt exhaustion, and the requirement
to deploy before resuming the active SillyBunny security hold.

- [ ] **Step 2: Run complete verification**

```powershell
npm.cmd run check
npm.cmd run test:e2e
npm.cmd run build
npm.cmd run scanners:verify
npm.cmd run scanners:smoke
git diff --check
```

Expected: every command exits 0.

- [ ] **Step 3: Run invariant searches**

```powershell
rg -n 'reason === "retry".*return -1|targetRetryAt\(initialFailedAt|fingerprint in:body' src .github/workflows tests docs README.md
```

Expected: no retry-first comparator, initial-failure retry scheduling, or
fingerprint-only target issue search remains. Intentional shared fingerprint
searches may remain.

- [ ] **Step 4: Review branch scope**

```powershell
git status --short
git diff main...HEAD --stat
git log --oneline main..HEAD
```

Expected: only planned files plus the committed design/plans; the pre-existing
untracked `TavernKeeper/` directory remains untouched.

- [ ] **Step 5: Commit Task 6**

```powershell
git add README.md docs/architecture.md docs/operations.md
git commit -m "docs: explain catalog-first quarantine"
```
