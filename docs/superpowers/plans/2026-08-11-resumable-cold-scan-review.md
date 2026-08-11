# Resumable Cold Scan Review Implementation Plan

> Execute test-first in the isolated `codex/resumable-cold-scans` worktree.
> Preserve complete-or-nothing publication and all policy-5 per-wave limits.

**Goal:** Make deterministic preparation a one-time cost for an exact target
while contextual review and finalization resume from authenticated encrypted
checkpoints across workflow runs.

**Architecture:** Add review protocol v2 as an execution layer separate from
policy-5 assessment semantics. A protocol-v2 planner creates one bounded wave
at a time; a versioned checkpoint contains the exact prepared session and
validated progress. Queue state references the newest encrypted artifact, and
workflow transitions distinguish progress from failure and completion.

**Stack:** TypeScript, Zod, Vitest, Node crypto, GitHub Actions YAML, GitHub CLI.

---

## Task 1: Define protocol-v2 wave contracts

**Files:**

- Modify: `src/model/contextual-review-budget.ts`
- Modify: `src/model/contextual-review.ts`
- Test: `tests/contextual-review-budget.test.ts`
- Test: `tests/contextual-review.test.ts`

1. Add failing tests for a 24-group target producing a first wave of at most 12
   fresh groups, stable remaining order, and a fresh wave-local ledger when
   resumed with cumulative progress.
2. Add failing tests proving cached groups do not consume fresh-wave capacity
   and a single indivisible group that cannot fit an empty wave is classified as
   structural.
3. Introduce `review_protocol_version: 2`, explicit wave identity, wave-local
   usage, and cumulative audit usage in contextual progress.
4. Replace whole-target planning with `planContextualReviewWave`, returning the
   selected groups, pending count, wave estimate, and completion state.
5. Run `npm.cmd test -- tests/contextual-review-budget.test.ts
   tests/contextual-review.test.ts`.

## Task 2: Make review stop safely at a wave boundary

**Files:**

- Modify: `src/model/contextual-review.ts`
- Modify: `src/orchestrator/session.ts`
- Modify: `src/operations/failure.ts`
- Test: `tests/contextual-review.test.ts`
- Test: `tests/scan-session.test.ts`
- Test: `tests/failure.test.ts`

1. Add failing tests that accept and checkpoint one bounded wave, return
   `review_pending` with unresolved groups, and never construct a partial
   report.
2. Add failing tests that a restored `reviewed` checkpoint performs report
   finalization without a provider call.
3. Add a typed `REVIEW_WAVE_PENDING` progress outcome separate from sanitized
   failure descriptors.
4. Update `reviewPreparedSession` to persist progress after every accepted
   group, stop normally at the wave boundary, and write a reviewed marker before
   final report construction.
5. Preserve `REPORT_FINALIZATION_FAILED` with a stable sanitized fingerprint.
6. Run focused model/session/failure tests.

## Task 3: Add authenticated checkpoint packaging

**Files:**

- Create: `src/contracts/review-checkpoint.ts`
- Create: `src/cli/review-checkpoint.ts`
- Modify: `src/publish/encrypted-transport.ts`
- Modify: `package.json`
- Test: `tests/review-checkpoint.test.ts`
- Test: `tests/encrypted-transport.test.ts`

1. Add failing round-trip tests for prepared, reviewing, and reviewed phases,
   including request identity, session/evidence digests, file digests, progress,
   creation/expiry times, and protocol version.
2. Add failing tests for wrong key, ciphertext mutation, manifest mutation,
   request/SHA/policy/model mismatch, expired checkpoint, unexpected files, and
   replay-invalid progress.
3. Generalize the AES-GCM helper to accept authenticated context while keeping
   the existing outcome transport compatible.
4. Implement checkpoint pack/restore/inspect commands. Pack validates the
   prepared session and progress before encryption; restore authenticates and
   revalidates before writing an ephemeral session.
5. Enforce bounded manifest/payload sizes and safe temporary-root names.
6. Run checkpoint and encrypted-transport tests.

## Task 4: Add queue checkpoint state and progress transitions

**Files:**

- Modify: `src/operations/state.ts`
- Modify: `src/operations/migrate-state.ts`
- Modify: `src/cli/transition.ts`
- Modify: `src/cli/transition-result.ts`
- Modify: `src/operations/retry.ts`
- Modify: `src/queue/durable-queue.ts`
- Test: `tests/operations-state.test.ts`
- Test: `tests/state-migration.test.ts`
- Test: `tests/transition.test.ts`
- Test: `tests/retry.test.ts`
- Test: `tests/durable-queue.test.ts`

1. Add failing tests for operations schema v4 and migration from schema v3 with
   no checkpoint.
2. Define a strict checkpoint reference containing run/artifact/name/digest,
   phase, exact target identity, protocol version, and expiry.
3. Add a transition-v3 `progress` variant carrying only a validated checkpoint
   reference and timestamp.
4. Implement `recordProgress`: atomically replace the reference, clear the
   failure streak, remove the active lease, preserve ticket priority, and make
   the entry immediately runnable.
5. Clear checkpoint references when target identity changes or publication
   succeeds. Preserve them across transient failures for the same identity.
6. Add structural failure fingerprint behavior for repeated identical
   finalization failures without changing global security holds.
7. Run focused state/transition/queue tests.

## Task 5: Carry checkpoints through reconciliation requests

**Files:**

- Modify: `src/cli/staff-request.ts`
- Modify: `src/cli/reconcile.ts`
- Modify: `src/queue/backlog.ts`
- Test: `tests/cli.test.ts`
- Test: `tests/backlog.test.ts`
- Test: `tests/claim-scans.test.ts`

1. Add failing tests that a due entry with an exact checkpoint emits its
   checkpoint reference in the self-contained scan request.
2. Add failing tests that mismatched/expired references are omitted and force a
   new cold preparation.
3. Extend the request schema with an optional strict checkpoint reference.
4. Bind request construction to the exact queued target and policy identity.
5. Run focused reconciliation tests.

## Task 6: Correct deterministic triage under unknown scope

**Files:**

- Modify: `src/model/review-triage.ts`
- Test: `tests/review-triage.test.ts`

1. Add a failing fixture with an unknown-scope group containing exact OSV
   candidates and ordinary unknown candidates.
2. Prove exact OSV candidates remain deterministic, unknown candidates remain
   contextual, and hard dangerous-correlation escalation still moves the whole
   group into contextual review.
3. Narrow the group-level condition accordingly without changing candidate
   coverage or counts.
4. Run `npm.cmd test -- tests/review-triage.test.ts`.

## Task 7: Publish protocol-v2 review accounting

**Files:**

- Modify: `src/contracts/reports-v5.ts`
- Modify: `src/report/contextual-report.ts`
- Modify: `src/contracts/generated/report-v5.schema.json`
- Modify: `scripts/generate-contract-schemas.ts`
- Test: `tests/contextual-report.test.ts`
- Test: `tests/report-contract.test.ts`

1. Add failing tests accepting existing protocol-1 reports unchanged and a
   protocol-v2 report whose total fresh cases exceed 12 while each wave remains
   within every cap.
2. Add failing tests for incorrect wave sums, an over-budget wave, duplicate
   wave IDs, and inconsistent cumulative usage.
3. Add optional protocol-v2 accounting to the report contract, keeping legacy
   fields valid for protocol 1.
4. Generate the JSON Schema and run focused report-contract tests.

## Task 8: Wire durable checkpoints into GitHub Actions

**Files:**

- Modify: `.github/workflows/scan-and-publish.yml`
- Modify: `.github/workflows/reconcile.yml`
- Modify: `scripts/check-workflow-policy.mjs`
- Test: `tests/workflows.test.ts`
- Test: `tests/two-lane-workflows.test.ts`
- Test: `tests/provider-credential-contract.test.ts`

1. Add failing workflow tests for cold and resume branches.
2. On cold start, prepare once, seal an encrypted checkpoint, and upload it with
   90-day retention before model review.
3. On resume, download the exact prior run/artifact via GitHub CLI, verify its
   digest, restore it, and skip checkout/scanners.
4. After a partial wave or reviewed marker, seal/upload the successor and emit a
   progress transition. Keep the previous state reference authoritative until
   publisher validation commits the successor.
5. On reviewed resume, skip provider setup/check and run finalization only.
6. Keep plaintext prepared artifacts at one-day retention and remove plaintext
   session/progress files before outcome upload.
7. Extend workflow-policy checks for permissions, exact artifact binding,
   encrypted-only durable retention, no fork execution, and protected secrets.
8. Run workflow tests and `npm.cmd run workflows:check`.

## Task 9: End-to-end interruption and migration coverage

**Files:**

- Modify: `tests/e2e/scan-fixtures.test.ts`
- Modify: `tests/artifact-batch.test.ts`
- Modify: `operations/state.json`
- Test: `tests/e2e/scan-fixtures.test.ts`
- Test: `tests/artifact-batch.test.ts`

1. Add fixtures that interrupt after preparation, after wave one, and before
   finalization; resume each and prove scanner invocation count is one.
2. Prove publication occurs once and only with complete exact evidence.
3. Migrate committed operations state to schema v4 without altering the frozen
   campaign IDs, tickets, cooldowns, holds, or unrelated history.
4. Run end-to-end and artifact-batch tests.

## Task 10: Verify, review, publish, and resume the campaign

1. Run `npm.cmd run format` only on changed files, then `git diff --check`.
2. Run `npm.cmd run typecheck`, all focused tests, `npm.cmd test`,
   `npm.cmd run workflows:check`, `npm.cmd run build`, and hostile-fixture E2E
   tests. Re-run the known JavaScript-normalizer timeout separately if it appears
   only under full-suite load.
3. Review the complete diff for checkpoint identity, secret exposure, artifact
   authority, queue idempotence, and protocol-1 compatibility.
4. Commit with a security/data-migration rationale, push the branch, open a PR,
   monitor checks, merge, and verify deployment.
5. Dispatch reconciliation for the existing frozen campaign. Verify all 13
   original repository IDs reach exact preferred reports at scanner policy 5,
   contextual policy 5, prompt v7, and assessment schema v2.
6. Verify deployed VectHare landing/detail advisory agreement and deactivate the
   heartbeat only after terminal success or an exact diagnosed structural
   blocker.
