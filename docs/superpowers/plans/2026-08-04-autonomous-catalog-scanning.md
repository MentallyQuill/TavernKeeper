# Autonomous Catalog Scanning Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make TavernKeeper scan the complete Tavernary catalog in explicit popularity order while isolating target failures, automatically recovering shared transient failures, and retaining hard security holds.

**Architecture:** Introduce a sanitized three-domain failure descriptor, operations-state schema V2, and a planner that distinguishes runnable, delayed, held, and exhausted work. The serialized publisher remains authoritative for state changes; continuation follows publisher/deployment results rather than matrix conclusions. Tavernary publishes a backwards-compatible V3 target manifest with a complete popularity rank, while TavernKeeper accepts V2 and V3 during rollout.

**Tech Stack:** TypeScript 6, Node.js 24, Zod 4, Vitest 4, GitHub Actions, GitHub CLI, JSON Schema Draft 7, GitHub Pages.

## Global Constraints

- Target repositories remain hostile data and must never have dependencies, scripts, builds, tests, hooks, Actions, containers, or executables run.
- Technical Report V5, scanner policy 3, contextual-review policy 1, and Tavernary synthesis policy remain unchanged.
- Publication remains fail-closed: no partial candidate, skipped required scanner, missing contextual assessment, or inferred-safe report may publish.
- Automatic batches remain bounded to five repositories with two concurrent scan jobs.
- Exact repository ID, full SHA, encrypted outcome transport, immutable history, protected Publisher-App writes, and exact-SHA Pages deployment remain mandatory.
- Target-local exhaustion must not stop unrelated catalog work.
- Shared transient failures probe forever with capped backoff and never become terminal solely from retry count.
- Credential, configuration, authenticity, integrity, and compromise failures create a security hold and require staff repair plus explicit resume.
- TavernKeeper must accept V2 manifests until Tavernary V3 is deployed.
- Preserve the user-owned untracked `F:\git\TavernKeeper\TavernKeeper\` directory and unrelated worktrees.

---

### Task 1: Add the sanitized failure-domain contract

**Files:**

- Create: `src/operations/failure.ts`
- Modify: `src/cli/io.ts`
- Modify: `src/cli/transition.ts`
- Modify: `src/cli/transition-result.ts`
- Modify: `src/orchestrator/scan-handler.ts`
- Modify: `.github/workflows/scan-and-publish.yml`
- Test: `tests/failure.test.ts`
- Test: `tests/cli-io.test.ts`
- Test: `tests/scan-atomicity.test.ts`

**Interfaces:**

- Produces `FailureDomainSchema`, `FailureComponentSchema`, `FailureDiagnosticSchema`, `FailureDescriptorSchema`, `classifyFailure()`, and `failureFingerprint()` from `src/operations/failure.ts`.
- `classifyFailure(input)` consumes `{ code, scope, component?, diagnostic? }` and returns `{ code, domain, component, diagnostic? }`.
- Scan transition schema V2 carries `failure: FailureDescriptor` instead of loose `code` and `scope` fields; completed transitions also use schema version 2.

- [ ] **Step 1: Write classification and fingerprint tests**

Add `tests/failure.test.ts` with literal expectations that catch the binary-scope defect:

```ts
import { describe, expect, test } from "vitest";
import {
  classifyFailure,
  failureFingerprint,
} from "../src/operations/failure.js";

describe("operational failure domains", () => {
  test.each([
    ["SCANNER_FAILED", "opengrep", "target"],
    ["SCANNER_TIMEOUT", "gitleaks", "target"],
    ["MODEL_INVALID_RESPONSE", "contextual-model", "target"],
    ["MODEL_CONTEXT_INCOMPLETE", "contextual-model", "target"],
    ["MODEL_PROVIDER", "contextual-model", "shared"],
    ["MODEL_QUOTA", "contextual-model", "shared"],
    ["SCANNER_UNAVAILABLE", "opengrep", "shared"],
    ["MODEL_AUTHENTICATION", "contextual-model", "security"],
    ["MODEL_CONFIGURATION", "contextual-model", "security"],
  ] as const)("classifies %s from %s as %s", (code, component, domain) => {
    expect(classifyFailure({ code, scope: "system", component })).toMatchObject(
      {
        code,
        component,
        domain,
      },
    );
  });

  test("unknown system failures fail safe as security holds", () => {
    expect(classifyFailure({ code: "CLI_FAILED", scope: "system" })).toEqual({
      code: "CLI_FAILED",
      domain: "security",
      component: "orchestrator",
    });
  });

  test("fingerprints distinguish scanner components and diagnostics", () => {
    const opengrep = classifyFailure({
      code: "SCANNER_FAILED",
      scope: "system",
      component: "opengrep",
    });
    const gitleaks = classifyFailure({
      code: "SCANNER_FAILED",
      scope: "system",
      component: "gitleaks",
    });
    expect(failureFingerprint(opengrep)).not.toBe(failureFingerprint(gitleaks));
  });
});
```

- [ ] **Step 2: Run the tests and confirm RED**

Run:

```powershell
npm.cmd test -- tests/failure.test.ts
```

Expected: FAIL because `src/operations/failure.ts` does not exist.

- [ ] **Step 3: Implement the bounded descriptor and explicit classification**

Create `src/operations/failure.ts` with strict enums and these rules:

```ts
import { createHash } from "node:crypto";
import { z } from "zod";

export const FailureDomainSchema = z.enum(["target", "shared", "security"]);
export const FailureComponentSchema = z.enum([
  "acquisition",
  "inventory",
  "history",
  "gitleaks",
  "opengrep",
  "osv-scanner",
  "zizmor",
  "malcontent",
  "contextual-model",
  "finalization",
  "artifact-transport",
  "publication",
  "target-manifest",
  "github",
  "pages",
  "orchestrator",
]);
export const FailureDiagnosticSchema = z.enum([
  "assessment_candidate_id",
  "assessment_evidence_ids",
  "assessment_schema",
  "output_limit",
  "response_content",
  "response_envelope",
  "response_json",
  "response_size",
  "response_usage",
  "review_schema",
]);
export const FailureDescriptorSchema = z.strictObject({
  code: z.string().regex(/^[A-Z][A-Z0-9_]{0,79}$/u),
  domain: FailureDomainSchema,
  component: FailureComponentSchema,
  diagnostic: FailureDiagnosticSchema.optional(),
});
export type FailureDescriptor = z.infer<typeof FailureDescriptorSchema>;

export function failureFingerprint(value: FailureDescriptor) {
  const parsed = FailureDescriptorSchema.parse(value);
  return createHash("sha256")
    .update(
      JSON.stringify([
        parsed.domain,
        parsed.component,
        parsed.code,
        parsed.diagnostic ?? null,
      ]),
    )
    .digest("hex");
}
```

Implement `classifyFailure()` with explicit code sets. Repository-scoped input always maps to `target`; scanner failed/timeout/output/malformed codes map to `target`; scanner unavailable maps to `shared`; model provider/quota maps to `shared`; model configuration/authentication/header mismatch and unknown system codes map to `security`.

- [ ] **Step 4: Prove safe metadata survives CLI and encrypted transitions**

Add failing tests to `tests/cli-io.test.ts` and `tests/scan-atomicity.test.ts` asserting that an OpenGrep failure writes and parses:

```json
{
  "code": "SCANNER_FAILED",
  "domain": "target",
  "component": "opengrep"
}
```

Modify `safeCliErrorRecord()` to call `classifyFailure()`, write the complete descriptor to `phase-error.json`, and keep stderr body-free. Update `ScanTransitionSchema`, `transition-result.ts`, and the bootstrap outcome in `scan-and-publish.yml` to schema version 2.

Make scanner installation `continue-on-error` and write a sanitized `{ code: "SCANNER_UNAVAILABLE", domain: "shared", component: "orchestrator" }` phase error when pinned installation or verification fails after `npm ci`. Checkout or dependency failures that prevent TavernKeeper CLIs from running retain the already-encrypted `SCAN_BOOTSTRAP_FAILED` shared outcome.

- [ ] **Step 5: Run focused tests and confirm GREEN**

Run:

```powershell
npm.cmd test -- tests/failure.test.ts tests/cli-io.test.ts tests/scan-atomicity.test.ts
npm.cmd run typecheck
```

Expected: all focused tests pass and TypeScript exits 0.

- [ ] **Step 6: Commit Task 1**

```powershell
git add src/operations/failure.ts src/cli/io.ts src/cli/transition.ts src/cli/transition-result.ts src/orchestrator/scan-handler.ts .github/workflows/scan-and-publish.yml tests/failure.test.ts tests/cli-io.test.ts tests/scan-atomicity.test.ts
git commit -m "feat(ops): classify failure domains"
```

---

### Task 2: Replace the singular breaker with operations-state V2

**Files:**

- Modify: `src/operations/state.ts`
- Modify: `src/operations/retry.ts`
- Modify: `src/operations/retry-schedule.ts`
- Create: `src/operations/migrate-state.ts`
- Create: `src/cli/migrate-state.ts`
- Modify: `package.json`
- Test: `tests/operations-state.test.ts`
- Test: `tests/retry.test.ts`
- Create: `tests/state-migration.test.ts`

**Interfaces:**

- Produces `OperationsStateV2`, `TargetRetryEntry`, `SharedRecoveryHold`, `parseOperationsState()`, and `migrateOperationsState()`.
- `recordFailure(state, { target, failure, at })` records target, shared, or security behavior.
- `recordSuccess(state, target, at)` removes the target retry and clears the matching shared hold on the first successful probe.

- [ ] **Step 1: Write RED tests for isolated exhaustion, endless shared recovery, and security pause**

Extend `tests/retry.test.ts` with three real state-transition tests:

```ts
test("exhausting one target never creates a shared hold", () => {
  let state = runningState();
  for (const at of [
    "2026-08-04T00:00:00.000Z",
    "2026-08-04T00:05:00.000Z",
    "2026-08-04T00:30:00.000Z",
    "2026-08-04T02:00:00.000Z",
  ])
    state = recordFailure(state, {
      target,
      failure: {
        code: "SCANNER_FAILED",
        domain: "target",
        component: "opengrep",
      },
      at,
    }).state;
  expect(state.target_retries[0]).toMatchObject({ exhausted: true });
  expect(state.shared_holds).toEqual([]);
  expect(state.pause).toBeNull();
});

test("shared failures keep probing after notification threshold", () => {
  let state = runningState();
  for (let index = 0; index < 7; index += 1)
    state = recordFailure(state, {
      target,
      failure: {
        code: "MODEL_PROVIDER",
        domain: "shared",
        component: "contextual-model",
      },
      at: new Date(Date.UTC(2026, 7, 4, index)).toISOString(),
    }).state;
  expect(state.shared_holds[0]).toMatchObject({
    consecutive_failures: 7,
    notified: true,
  });
  expect(state.shared_holds[0]?.next_probe_at).not.toBeNull();
  expect(state.pause).toBeNull();
});

test("security failures persist a staff-visible security pause", () => {
  const failed = recordFailure(runningState(), {
    target,
    failure: {
      code: "MODEL_AUTHENTICATION",
      domain: "security",
      component: "contextual-model",
    },
    at: "2026-08-04T00:00:00.000Z",
  });
  expect(failed.state.pause).toMatchObject({
    kind: "system",
    reason_code: "SECURITY_HOLD",
  });
});
```

- [ ] **Step 2: Run the retry tests and confirm RED**

Run:

```powershell
npm.cmd test -- tests/retry.test.ts tests/operations-state.test.ts
```

Expected: FAIL because V1 has `retries` and `circuit_breaker`, not `target_retries` and `shared_holds`.

- [ ] **Step 3: Implement strict V2 state and schedules**

Change `OperationsStateSchema` to schema version 2 with these persisted collections:

```ts
target_retries: z.array(z.strictObject({
  source_id: SourceIdSchema,
  repository_id: z.number().int().positive(),
  repository: RepositorySchema,
  target_sha: FullShaSchema,
  failure: FailureDescriptorSchema,
  error_fingerprint: FingerprintSchema,
  initial_failed_at: z.iso.datetime(),
  last_failed_at: z.iso.datetime(),
  attempt: z.number().int().min(1).max(4),
  next_retry_at: z.iso.datetime().nullable(),
  exhausted: z.boolean(),
})),
shared_holds: z.array(z.strictObject({
  error_fingerprint: FingerprintSchema,
  failure: FailureDescriptorSchema.refine(({ domain }) => domain === "shared"),
  first_failed_at: z.iso.datetime(),
  last_failed_at: z.iso.datetime(),
  consecutive_failures: z.number().int().positive(),
  next_probe_at: z.iso.datetime(),
  notified: z.boolean(),
})),
```

Use target retry delays `[5, 30, 120]` minutes from the initial failure. Use shared delays `[5, 15, 30, 60, 180]` minutes from the latest failure, capped at 180 minutes for every later failure. A target's fourth failure sets `attempt: 4`, `next_retry_at: null`, and `exhausted: true`. Shared holds never become terminal.

`recordSuccess()` removes the exact target retry and clears the shared hold matching that retry's fingerprint even when other target retries have the same fingerprint.

When a target's failure fingerprint changes, prune the prior shared hold only when no remaining target retry references it. This prevents an orphaned shared hold from blocking the queue without any eligible probe.

- [ ] **Step 4: Write RED migration tests with a literal V1 fixture**

Create `tests/state-migration.test.ts`. Use a literal V1 object containing coverage start, one exhausted repository reply failure, one `MODEL_PROVIDER` system retry, one `SCANNER_FAILED` system retry, and the legacy singular breaker. Assert V2 output:

- preserves `coverage_started_at`, active scans, and campaigns;
- maps `MODEL_PROVIDER` to shared/contextual-model;
- maps ambiguous `SCANNER_FAILED` to target/orchestrator;
- keeps exhausted entries exhausted;
- removes the singular breaker; and
- emits migration counts `{ target: 2, shared: 1, security: 0 }`.

- [ ] **Step 5: Implement explicit migration CLI**

Create `migrateOperationsState(value, at)` returning:

```ts
{
  state: OperationsStateV2;
  summary: {
    target: number;
    shared: number;
    security: number;
  }
}
```

Create `src/cli/migrate-state.ts` to read `operations/state.json`, reject schema V2 unless `--check` is used, atomically write V2, and print only the numeric summary. Add:

```json
"state:migrate": "tsx src/cli/migrate-state.ts"
```

to `package.json`.

- [ ] **Step 6: Run V2 state tests and confirm GREEN**

Run:

```powershell
npm.cmd test -- tests/retry.test.ts tests/operations-state.test.ts tests/state-migration.test.ts
npm.cmd run typecheck
```

Expected: all focused tests pass.

- [ ] **Step 7: Commit Task 2**

```powershell
git add package.json src/operations/state.ts src/operations/retry.ts src/operations/retry-schedule.ts src/operations/migrate-state.ts src/cli/migrate-state.ts tests/operations-state.test.ts tests/retry.test.ts tests/state-migration.test.ts
git commit -m "feat(ops): add resilient recovery state"
```

---

### Task 3: Plan runnable work and exact popularity ordering

**Files:**

- Modify: `src/contracts/targets.ts`
- Create: `schemas/tavernary-targets.v3.schema.json`
- Modify: `src/queue/backlog.ts`
- Modify: `src/cli/reconcile.ts`
- Modify: `scripts/generate-contract-schemas.ts`
- Test: `tests/contracts.test.ts`
- Test: `tests/backlog.test.ts`
- Test: `tests/cli.test.ts`

**Interfaces:**

- Produces V3 target metadata `catalog_priority.popularity_rank: number`.
- `planBatch()` returns `{ targets, totalRemaining, runnableRemaining, delayedRetries, sharedHolds, nextWakeAt, blocked }`.
- V2 inputs retain their existing lane fallback; V3 initial coverage uses exact rank.

- [ ] **Step 1: Write RED contract and ranking tests**

Add a V3 fixture to `tests/contracts.test.ts` with ranks 1 and 2 and prove zero, duplicate properties, and missing rank are rejected.

Add `tests/backlog.test.ts` cases asserting:

```ts
expect(
  planBatch(
    manifestV3([
      targetV3(300, { rank: 3 }),
      targetV3(100, { rank: 1 }),
      targetV3(200, { rank: 2 }),
    ]),
    emptyIndex,
    runningStateV2(),
    now,
    "3",
  ).targets.map(({ target }) => target.repository_id),
).toEqual([100, 200, 300]);
```

Also prove:

- an exhausted exact SHA is not immediately reselected as `new`;
- due target retries precede new work;
- a non-due shared hold emits no targets and exposes `nextWakeAt`;
- due shared holds admit one matching probe per fingerprint, at most two;
- delayed-only work has `runnableRemaining: 0`; and
- V2 still uses Top-30/new/old fallback.

- [ ] **Step 2: Run planner tests and confirm RED**

Run:

```powershell
npm.cmd test -- tests/contracts.test.ts tests/backlog.test.ts tests/cli.test.ts
```

Expected: FAIL because V3 and rich planner output do not exist.

- [ ] **Step 3: Implement V3 parsing and rich planning**

Add `TargetV3Schema` and `TargetManifestV3Schema`. Parse target manifests as V1, V2, or V3. Generate the strict V3 JSON Schema from the Zod source.

In `planBatch()`:

1. Build retry/exhausted maps before report coverage checks.
2. Skip an exhausted retry for the exact current SHA.
3. If `pause !== null`, return no targets.
4. If shared holds exist, select only due matching target retries, one per failure fingerprint, with two total probes.
5. Otherwise sort due target retries first and V3 new/changed work by rank ascending.
6. Compute the earliest future retry/probe time without treating delayed work as runnable.

- [ ] **Step 4: Update reconciliation JSON contract**

Change `buildReconcileMatrix()` output to:

```ts
{
  include: ScanRequest[];
  total_remaining: number;
  runnable_remaining: number;
  delayed_retries: number;
  shared_holds: number;
  next_wake_at: string | null;
  blocked: boolean;
}
```

Keep scan requests self-contained and include no popularity score beyond the manifest metadata already required by the request schema.

- [ ] **Step 5: Run planner/contract tests and confirm GREEN**

Run:

```powershell
npm.cmd test -- tests/contracts.test.ts tests/backlog.test.ts tests/cli.test.ts
npm.cmd run contracts:generate
npm.cmd run typecheck
```

Expected: tests and typecheck pass; generated V3 schema is stable.

- [ ] **Step 6: Commit Task 3**

```powershell
git add src/contracts/targets.ts schemas/tavernary-targets.v3.schema.json src/queue/backlog.ts src/cli/reconcile.ts scripts/generate-contract-schemas.ts tests/contracts.test.ts tests/backlog.test.ts tests/cli.test.ts
git commit -m "feat(queue): plan ranked resilient batches"
```

---

### Task 4: Make mixed-batch continuation publisher-authoritative

**Files:**

- Modify: `src/publish/artifact-batch.ts`
- Modify: `src/publish/publisher.ts`
- Modify: `src/cli/publish.ts`
- Modify: `src/cli/exhausted.ts`
- Modify: `.github/workflows/scan-and-publish.yml`
- Modify: `.github/workflows/reconcile.yml`
- Modify: `.github/workflows/retry.yml`
- Modify: `.github/workflows/staff-operations.yml`
- Modify: `scripts/check-workflow-policy.mjs`
- Test: `tests/artifact-batch.test.ts`
- Test: `tests/publisher.test.ts`
- Test: `tests/workflows.test.ts`

**Interfaces:**

- `publishArtifactBatch()` returns `{ status, reports, target_failures, shared_holds, security_holds, continuation_blocked, terminal_failures }`.
- Workflow continuation uses `continuation_blocked`, deployment success, and `inputs.total_remaining`; `inputs.runnable_remaining` is retained for workflow summaries and it never checks matrix success.

- [ ] **Step 1: Write RED mixed-batch and workflow behavior tests**

Extend `tests/artifact-batch.test.ts` to prove:

- one completed report plus one target failure returns `continuation_blocked: false`;
- one completed report plus one shared failure returns `continuation_blocked: true` and records a shared hold;
- any security failure returns `continuation_blocked: true` and records a security pause;
- a later successful probe clears its shared hold; and
- completed candidates remain published in every mixed case.

Extend `tests/workflows.test.ts` to parse workflows and assert behavior rather than source snippets:

- matrix `fail-fast` is false;
- publisher uses `if: always()`;
- deploy uses publisher success;
- continue uses `always()`, publisher/deploy results, and `continuation_blocked`, not `needs.scan.result` or `system_failure`;
- retry cron is `*/5 * * * *`;
- reconcile outputs rich planner fields; and
- state migration is available only in the staff-protected workflow.

- [ ] **Step 2: Run batch/workflow tests and confirm RED**

Run:

```powershell
npm.cmd test -- tests/artifact-batch.test.ts tests/publisher.test.ts tests/workflows.test.ts
```

Expected: FAIL on old `system_failure` output and hourly retry schedule.

- [ ] **Step 3: Implement publisher-authoritative outcomes**

Pass each V2 transition's complete failure descriptor to `recordFailure()`. Count target/shared/security outcomes separately. Preserve complete outcome-set authentication and publish completed reports before returning summary metadata.

Update `publish.ts` to print only:

```json
{
  "status": "partial",
  "reports": 1,
  "target_failures": 1,
  "shared_holds": 0,
  "security_holds": 0,
  "continuation_blocked": false,
  "terminal_failures": 0
}
```

with values derived from the real batch.

- [ ] **Step 4: Update workflows and operational issues**

Change reusable scan inputs from `remaining` to `total_remaining` and `runnable_remaining`. Continue when:

```yaml
if: ${{ always() && needs.publish.result == 'success' && needs.deploy.result == 'success' && needs.publish.outputs.continuation_blocked != 'true' && inputs.total_remaining != '0' }}
```

An immediate follow-up reconcile may find only delayed work and then exits without invoking `scan-and-publish`, so no continuation loop forms.

Set retry cron to `*/5 * * * *`. Use `exhausted.ts` output to create target-exhaustion issues and shared-hold notifications by complete fingerprint. Close a matching open shared-recovery issue after the hold disappears. Keep incident bodies secret-free.

Add a protected `migrate` operation to `staff-operations.yml` that runs `npm run --silent state:migrate`, commits only `operations/state.json`, and does not dispatch scanning until a separate resume operation.

- [ ] **Step 5: Run batch/workflow tests and confirm GREEN**

Run:

```powershell
npm.cmd test -- tests/artifact-batch.test.ts tests/publisher.test.ts tests/workflows.test.ts
npm.cmd run workflows:check
npm.cmd run typecheck
```

Expected: all checks pass.

- [ ] **Step 6: Commit Task 4**

```powershell
git add src/publish/artifact-batch.ts src/publish/publisher.ts src/cli/publish.ts src/cli/exhausted.ts .github/workflows/scan-and-publish.yml .github/workflows/reconcile.yml .github/workflows/retry.yml .github/workflows/staff-operations.yml scripts/check-workflow-policy.mjs tests/artifact-batch.test.ts tests/publisher.test.ts tests/workflows.test.ts
git commit -m "fix(ci): continue isolated scan failures"
```

---

### Task 5: Document operations and verify TavernKeeper completely

**Files:**

- Modify: `README.md`
- Modify: `docs/architecture.md`
- Modify: `docs/operations.md`

**Interfaces:**

- Documents the V2 state migration, three failure domains, five-minute recovery, V2/V3 manifest compatibility, and exact rollout sequence.

- [ ] **Step 1: Update operator documentation**

Document the exact distinction:

- target-local: three delayed retries, exhaust exact SHA, continue catalog;
- shared transient: capped probes forever, notify without terminal stop;
- security hold: fail closed, repair/check/resume;
- publisher/deployment drives continuation after mixed batches;
- initial V3 coverage is strict popularity rank;
- V2 fallback remains temporary compatibility behavior.

- [ ] **Step 2: Run TavernKeeper's complete local gates**

Run:

```powershell
npm.cmd run check
npm.cmd run test:e2e
npm.cmd run build
npm.cmd run scanners:verify
npm.cmd run scanners:smoke
git diff --check
```

Expected: every command exits 0. Scanner smoke runs only TavernKeeper-owned benign fixtures.

- [ ] **Step 3: Search for stale V1/breaker contracts**

Run:

```powershell
rg -n "circuit_breaker|system_failure|schema_version: z.literal\(1\)|hourly|17 \* \* \* \*" src tests .github/workflows docs README.md
```

Expected: only intentional V1 migration fixtures/history references remain; workflow continuation contains no `system_failure` gate; retry workflow contains no hourly cron.

- [ ] **Step 4: Commit Task 5**

```powershell
git add README.md docs/architecture.md docs/operations.md
git commit -m "docs: explain autonomous scan recovery"
```

---

### Task 6: Publish exact popularity ranks from Tavernary

**Files in `F:\git\Tavernary`:**

- Modify: `scripts/security/tavernkeeper-targets.mjs`
- Modify: `scripts/security/tavernkeeper-targets.d.mts`
- Modify: `scripts/catalog/build.mjs`
- Modify: `scripts/verify-static-export.mjs`
- Modify: `config/tavernkeeper-contract.json`
- Create: `data/schemas/tavernkeeper-targets.v3.schema.json`
- Create: `tests/fixtures/tavernkeeper/targets.v3.valid.json`
- Modify: `tests/unit/tavernkeeper-targets.test.ts`
- Modify: `tests/unit/static-export-verification.test.ts`

**Interfaces:**

- Produces manifest schema version 3 with `catalog_priority: { top_30, first_cataloged_at, popularity_rank }`.
- `popularityProjectRanks(projects)` returns `Map<projectId, positiveRank>` using the existing aggregate/name/ID ordering.
- A shared source receives the minimum rank among supported published project cards.

- [ ] **Step 1: Create an isolated Tavernary worktree from current remote main**

Use branch `codex/tavernkeeper-popularity-rank-v3`. Preserve all existing Tavernary worktrees and dirty files.

- [ ] **Step 2: Write RED manifest-rank tests**

Add tests with scored, unscored, tied, unsupported preset, and shared-source cards. Hand-derive these expectations:

```ts
expect([...popularityProjectRanks(projects).entries()]).toEqual([
  ["highest", 1],
  ["tied-alpha", 2],
  ["tied-beta", 3],
  ["unscored", 4],
]);
expect(manifest.repositories[0]?.catalog_priority).toEqual({
  top_30: true,
  first_cataloged_at: "2026-07-02T00:00:00.000Z",
  popularity_rank: 2,
});
```

Validate the V3 fixture against Draft 7 and prove rank 0, missing rank, and an incorrect `top_30`/rank relation are rejected by build-time validation.

- [ ] **Step 3: Run focused tests and confirm RED**

Run:

```powershell
npm.cmd test -- tests/unit/tavernkeeper-targets.test.ts tests/unit/static-export-verification.test.ts
```

Expected: FAIL because V3 rank generation does not exist.

- [ ] **Step 4: Implement deterministic V3 generation**

Refactor the existing popularity comparator into one reusable ordering function. Assign 1-based ordinal ranks to all published catalog projects. While building supported source metadata, retain the minimum rank among supported cards. Emit V3 and assert `top_30 === (popularity_rank <= 30)`.

Keep V1/V2 readers/tests intact; only the production export moves to V3.

- [ ] **Step 5: Run Tavernary verification and confirm GREEN**

Run:

```powershell
npm.cmd test -- tests/unit/tavernkeeper-targets.test.ts tests/unit/static-export-verification.test.ts
npm.cmd run catalog:validate
npm.cmd run catalog:build
npm.cmd run check
```

Expected: all commands exit 0 and the generated manifest contains a unique deterministic rank for every eligible repository.

- [ ] **Step 6: Commit Tavernary V3**

```powershell
git add scripts/security/tavernkeeper-targets.mjs scripts/security/tavernkeeper-targets.d.mts scripts/catalog/build.mjs scripts/verify-static-export.mjs config/tavernkeeper-contract.json data/schemas/tavernkeeper-targets.v3.schema.json tests/fixtures/tavernkeeper/targets.v3.valid.json tests/unit/tavernkeeper-targets.test.ts tests/unit/static-export-verification.test.ts
git commit -m "feat(security): rank scan targets by popularity"
```

---

### Task 7: Review, publish, migrate, and prove live recovery

**Files:**

- Review all branch diffs in both repositories.
- Production mutation is performed only through protected GitHub workflows and merged commits.

**Interfaces:**

- Produces merged TavernKeeper and Tavernary main SHAs, migrated operations state V2, live V3 target manifest, and resumed automatic backlog.

- [ ] **Step 1: Run final TavernKeeper verification immediately before publication**

Run `npm.cmd run check`, `npm.cmd run test:e2e`, `npm.cmd run build`, `npm.cmd run scanners:verify`, `npm.cmd run scanners:smoke`, `git diff --check`, and inspect `git diff main...HEAD` plus `git status --short`.

- [ ] **Step 2: Run final Tavernary verification immediately before publication**

Run `npm.cmd run check` and inspect `git diff main...HEAD`, generated V3 manifest samples, and `git status --short`.

- [ ] **Step 3: Publish TavernKeeper through protected review**

Push `codex/autonomous-catalog-scanning`, open a ready PR, wait for all required checks, review unresolved threads, merge only after green checks, and record the exact merge SHA. Do not direct-push protected main.

- [ ] **Step 4: Pause and migrate production state**

Dispatch `staff-operations.yml` with `operation=pause` and reason `AUTOMATION_STATE_MIGRATION`; approve the expected `tavernkeeper-staff` environment. After the TavernKeeper merge/deployment, dispatch `operation=migrate`, verify the resulting commit changes only `operations/state.json`, preserves `coverage_started_at`, and contains schema version 2.

- [ ] **Step 5: Publish Tavernary V3 through protected review**

Push `codex/tavernkeeper-popularity-rank-v3`, open a ready PR, wait for required checks, merge, deploy the exact main SHA, and verify `https://tavernary.org/security/tavernkeeper-targets.json` is schema V3 with complete positive ranks.

- [ ] **Step 6: Verify compatibility checks and resume**

Run TavernKeeper provider compatibility and scanner-toolchain verification workflows. Resume through `staff-operations.yml`; verify the first batch's repository ranks are ascending and no exhausted target is selected.

- [ ] **Step 7: Prove target-local continuation live**

Observe one of the migrated legacy `SCANNER_FAILED` target retries in a mixed batch. Verify successful siblings publish/deploy, `continuation_blocked=false`, and the next popularity-ranked reconcile dispatch starts automatically. Do not inject a synthetic production failure.

- [ ] **Step 8: Prove the shared recovery path without altering credentials**

Dispatch the merged `retry.yml` after the migrated production state converts the existing due legacy `MODEL_PROVIDER` retries into a shared hold. Verify it admits one matching real target as the probe, a successful scan clears the hold, the shared-recovery issue closes, and reconciliation resumes without staff resume. Do not inject a synthetic production failure and do not alter provider credentials.

- [ ] **Step 9: Capture final evidence**

Record both merge SHAs, PR URLs, workflow run URLs, Pages/deployment SHAs, state schema/coverage timestamp, V3 manifest generation time, published-report count, remaining/runnable/delayed counts, and the first resumed ranks. Confirm no security hold, no active shared hold, and no unexpected dirty or untracked files were created.
