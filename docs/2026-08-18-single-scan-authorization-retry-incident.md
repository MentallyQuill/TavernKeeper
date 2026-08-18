# Single-scan authorization retry incident

- **Incident date:** 2026-08-18
- **Incident window:** 04:09–05:02 UTC
- **Affected target:** `Sillyanonymous/SillyTavern-CharacterLibrary` (`repository_id: 1139430137`)
- **Affected target SHA:** `70ff25474f77516ffc81ebd22fa8a2e37a9b7b4b`
- **Control objective:** Run one explicitly authorized scan without releasing the ordinary backlog
- **Incident status:** Contained under full maintenance
- **Remediation status:** Implemented and verified in the accompanying branch; not yet merged or deployed at this report snapshot

## Executive summary

TavernKeeper was placed behind `POLICY_V5_CANARY_GATE` so one staff-selected target could run while ordinary queued repositories remained blocked. The gate met the narrow concurrency and backlog-isolation requirement: it selected only a staff-marked repository, selected at most one target per reconciliation, and never released ordinary work.

It did **not** meet the intended one-attempt authorization lifetime.

The targeted request set `staff_requested: true` on CharacterLibrary's durable queue entry. When the authorized attempt failed during deterministic preparation, TavernKeeper rotated the failed entry to a new ticket and applied retry backoff, but preserved `staff_requested: true`. Reconciliation then scheduled a delayed wake for the new `not_before` time. When that time arrived, the still-active canary gate treated the same durable staff flag as continuing authorization and claimed CharacterLibrary again without a second manual request.

The second attempt failed in the same pre-model preparation phase. Contextual review was skipped, no provider request occurred, no model tokens were spent, and no report was published. Ordinary repositories remained blocked. Nevertheless, an explicit one-attempt operational boundary was exceeded.

This was not caused by contributor PR #180. That PR changed report contracts and contextual-review retry diagnostics; it did not modify queue selection, retry rotation, delayed wakes, targeted authorization, or staff operations.

## Impact assessment

| Dimension                          | Assessment                            | Evidence                                                                                                                   |
| ---------------------------------- | ------------------------------------- | -------------------------------------------------------------------------------------------------------------------------- |
| Authorization/control              | **Moderate**                          | One manual target authorization resulted in two scan attempts.                                                             |
| Model/API cost                     | **None from the unintended retry**    | The contextual-assessment step was skipped after preparation failed.                                                       |
| GitHub Actions cost                | **Low but non-zero**                  | The retry ran claim, preparation, failure packaging, and publication-state jobs for about two runner-minutes in aggregate. |
| Security/privacy                   | **No observed impact**                | No provider call, report payload, credential disclosure, or target-side mutation occurred.                                 |
| Backlog isolation                  | **Preserved**                         | The policy gate continued to exclude every non-staff queue entry.                                                          |
| Recurrence risk before containment | **Certain at the next eligible wake** | The queue entry retained `staff_requested: true` and received a future `not_before`.                                       |

This report interprets “single scan” conservatively as one execution attempt. If the objective were measured only as successful model-backed reports, the unintended retry produced none; that narrower accounting does not erase the control violation.

## Timeline

All times are UTC.

| Time     | Event                                                                                                                                                                                                                                                                                 |
| -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 04:02:15 | Staff operation changed the emergency-stop reason from full maintenance to `POLICY_V5_CANARY_GATE` (commit `6dfbe54b`).                                                                                                                                                               |
| 04:09:46 | [Targeted enqueue run 32098110123](https://github.com/MentallyQuill/TavernKeeper/actions/runs/32098110123) accepted CharacterLibrary and persisted `staff_requested: true` (commit `eb9db469`).                                                                                       |
| 04:11:14 | [Authorized scan run 32098205167](https://github.com/MentallyQuill/TavernKeeper/actions/runs/32098205167) began and claimed only CharacterLibrary.                                                                                                                                    |
| 04:12:44 | Exact-target preparation ended with sanitized failure `CLI_FAILED / target / orchestrator`.                                                                                                                                                                                           |
| 04:13:09 | The scan transition recorded the target failure. Contextual review and report finalization were skipped.                                                                                                                                                                              |
| 04:13:32 | Publication committed the failed state (commit `35fe66bf`). CharacterLibrary remained queued, now with `consecutive_failures: 2`, `staff_requested: true`, and `not_before: 2026-08-18T04:43:09.003Z`.                                                                                |
| 04:14:03 | [Reconciliation run 32098358622](https://github.com/MentallyQuill/TavernKeeper/actions/runs/32098358622) claimed nothing immediately and scheduled a delayed wake for exactly 04:43:09.003.                                                                                           |
| 04:33:21 | A newer same-concurrency [delayed wake 32099577030](https://github.com/MentallyQuill/TavernKeeper/actions/runs/32099577030) replaced the earlier wake while preserving the same deadline.                                                                                             |
| 04:43:09 | The delayed wake dispatched reconciliation automatically.                                                                                                                                                                                                                             |
| 04:43:11 | [Unintended retry run 32100161412](https://github.com/MentallyQuill/TavernKeeper/actions/runs/32100161412) began. The canary planner found the same staff-marked target due and claimed it (commit `17a113c4`).                                                                       |
| 04:44:35 | Preparation failed again with the same sanitized descriptor.                                                                                                                                                                                                                          |
| 04:44:54 | Contextual assessment was skipped; therefore no model/provider call occurred.                                                                                                                                                                                                         |
| 04:44:55 | Failure rotation persisted `consecutive_failures: 3`, `total_failures: 16`, `staff_requested: true`, and `not_before: 2026-08-18T06:44:55.132Z`.                                                                                                                                      |
| 04:45:21 | Failure-state publication committed as `a2bdf1a2`; report deployment was skipped.                                                                                                                                                                                                     |
| 04:45:30 | [Post-failure reconciliation 32100304046](https://github.com/MentallyQuill/TavernKeeper/actions/runs/32100304046) claimed nothing and scheduled [delayed wake 32100326199](https://github.com/MentallyQuill/TavernKeeper/actions/runs/32100326199) for the two-hour backoff deadline. |
| 04:59:19 | The separately approved Recursion replacement was claimed as the sole active target (commit `2872b28b`).                                                                                                                                                                              |
| 05:01:55 | Recursion completed and published successfully (commit `cdb1a1ec`).                                                                                                                                                                                                                   |
| 05:02:38 | Full `MODEL_COST_MAINTENANCE` pause was committed by [staff operation 32101189263](https://github.com/MentallyQuill/TavernKeeper/actions/runs/32101189263) (commit `615d4b2a`). Persisted state showed zero active scans.                                                             |

## Technical root cause

### 1. A targeted request grants durable staff status

`buildTargetedQueueUpdate` promotes an existing queue entry by calling `appendQueuedTarget(..., { staffRequested: true })` and reports the request as accepted. The stored representation is only a boolean; it has no request ID, attempt allowance, consumption timestamp, or expiry.

Relevant code:

- [`src/cli/targeted-scan.ts`](../src/cli/targeted-scan.ts), targeted enqueue at lines 149–168.
- [`src/queue/durable-queue.ts`](../src/queue/durable-queue.ts), durable staff promotion at lines 77–138.

### 2. Failure rotation deliberately preserves all existing entry metadata

`rotateFailedTarget` constructs the replacement entry with `...current`, then changes the ticket, failure counts, failure record, and `not_before`. Because `staff_requested` is part of `current`, it survives unchanged.

Relevant code:

- [`src/queue/durable-queue.ts`](../src/queue/durable-queue.ts), failure rotation at lines 195–255.
- [`src/operations/retry-schedule.ts`](../src/operations/retry-schedule.ts), scan backoff sequence `5, 30, 120, 360` minutes at lines 1–31.

CharacterLibrary already had one consecutive failure before the manual request. The authorized failure therefore moved it to failure count two and a 30-minute delay. The unintended retry moved it to failure count three and a 120-minute delay.

### 3. The canary gate interprets staff status as reusable eligibility

Under `POLICY_V5_CANARY_GATE`, `planBatch` filters the queue to entries where `staff_requested === true`. It then applies `not_before`, calculates `nextWakeAt`, and selects one runnable target. The `slice(0, 1)` cap constrains concurrent breadth; it does not constrain lifetime attempts.

Relevant code:

- [`src/queue/backlog.ts`](../src/queue/backlog.ts), canary filtering and wake calculation at lines 154–175.
- [`src/queue/backlog.ts`](../src/queue/backlog.ts), due selection and one-target cap at lines 253–292.
- [`tests/backlog.test.ts`](../tests/backlog.test.ts), the existing canary test confirms one staff target and ordinary-work isolation at lines 682–722.

### 4. Reconciliation turns future eligibility into an automatic retry

When no target is due but a staff-marked entry has a future `not_before`, reconciliation dispatches `delayed-wake.yml` with `next_wake_at`. The delayed workflow sleeps until that timestamp and dispatches reconciliation again. Failed publication also continues the backlog whenever queue entries remain.

Relevant code:

- [`.github/workflows/reconcile.yml`](../.github/workflows/reconcile.yml), delayed-wake scheduling at lines 126–132.
- [`.github/workflows/delayed-wake.yml`](../.github/workflows/delayed-wake.yml), bounded wait and automatic reconciliation at lines 1–46.
- [`.github/workflows/scan-and-publish.yml`](../.github/workflows/scan-and-publish.yml), post-publication continuation at lines 583–593.

### Root-cause statement

The confirmed root cause is an **authorization-lifetime mismatch**: `staff_requested` was designed and tested as durable queue provenance and retry priority, but it was reused as the canary gate's authorization predicate for an operation whose approved lifetime was one attempt. There is no state transition that consumes or revokes that authorization after a claim or failure.

This was deterministic behavior, not a race. The delayed wake executed exactly at the persisted retry deadline.

## Contributing operational failure

The code behavior alone did not require the gate to remain open. After the first failure, live state exposed all necessary warning signs:

- `staff_requested: true` was still present;
- `not_before` was set to 04:43:09;
- reconciliation emitted `next_wake_at` and created a delayed-wake run;
- immediate follow-up reconciliations claimed nothing only because the target was cooling down.

The operator, Codex, treated “zero active scans” and “no second repository claimed immediately” as sufficient safety proof. That was incomplete. The correct operational response was to restore full `MODEL_COST_MAINTENANCE` immediately after the first authorized attempt transitioned to failure, before waiting for or requesting a replacement target.

In other words, the existing controls behaved as implemented, while the operational procedure applied a one-shot meaning they did not possess.

## Non-causes

### Contributor PR #180

PR #180 changed only:

- `schemas/scan-report.v5.schema.json`
- `src/contracts/reports-v5.ts`
- `src/model/contextual-review.ts`
- `src/model/openai-compatible-client.ts`
- contextual-review and contract tests

It did not touch any file in the claim, queue, targeted-scan, retry-schedule, delayed-wake, or staff-operation path. The reusable canary predicate predates the PR; it entered through commit `b79f7597` on 2026-08-09. Failure rotation preserving current entry metadata predates it through commit `22f8d18b` on 2026-08-04.

### GLM and provider configuration

The unintended retry never reached contextual review. The model selection, API key, provider response format, and PR #180's `retry_reason` field had no role in this incident.

### Broad backlog release

The canary gate did not admit ordinary queue entries. Only the previously authorized CharacterLibrary target retried. The incident is an excess-attempt problem, not a catalog-wide unpause.

## Current containment and residual risk

As of state commit `615d4b2a` at 05:02:38 UTC:

- emergency stop: `MODEL_COST_MAINTENANCE`;
- active scans: `0`;
- CharacterLibrary remains queued with `staff_requested: true`;
- CharacterLibrary has `consecutive_failures: 3`, `total_failures: 16`;
- next target eligibility: `2026-08-18T06:44:55.132Z`;
- a delayed-wake run remains capable of dispatching reconciliation at that time.

The full maintenance stop makes that reconciliation a no-op, so the immediate cost boundary is contained. This is not a permanent repair. If the emergency-stop reason is changed back to the matching policy canary gate after the deadline, CharacterLibrary can become eligible again without a fresh targeted request.

The remediation accompanying this report atomically consumes
`staff_requested` when a target receives a scan lease and adds a protected,
idempotent `revoke` operation. Its regression coverage exercises the complete
claim, target-failure rotation, and canary-replan sequence. Deployment and
live revocation remain separate operational steps; this historical state
snapshot must not be read as proof that either has occurred.

## Recommended corrective actions

### Before any future canary

1. Keep `MODEL_COST_MAINTENANCE` active.
2. Revoke or clear CharacterLibrary's durable staff authorization before reusing a policy canary gate.
3. Cancel or explicitly account for the outstanding delayed wake so a future no-op reconciliation is not mistaken for a new authorization.
4. Require a pre-canary state check that lists every `staff_requested` entry and its `not_before`, rather than checking only active scans.

### Future hardening beyond the accompanying remediation

The accompanying repair deliberately retains the existing boolean queue
schema and makes that authorization one-shot at claim time. A richer grant
record remains optional future hardening rather than part of the implemented
incident fix.

Replace the boolean authorization predicate with an explicit one-shot grant, for example:

- `staff_request_id`;
- `authorized_attempts_remaining`, defaulting to `1`;
- `authorized_at` and `expires_at`;
- optional `retry_on_failure`, defaulting to `false` for targeted canaries.

Consume the attempt atomically when the target is claimed. A failed transition may remain in the durable queue for ordinary future recovery, but it must no longer satisfy a staff-only canary gate unless a new explicit request reauthorizes it.

Add a supported staff operation to revoke a targeted grant without deleting failure history or the underlying durable queue entry.

### Required regression coverage

1. A targeted request creates exactly one authorized attempt.
2. Claiming that attempt consumes the authorization.
3. Failure rotation retains failure history and backoff but not canary eligibility.
4. A matching canary gate produces no target and no delayed wake after the authorized attempt is consumed.
5. An explicit staff retry creates a new, auditable authorization.
6. Ordinary backlog entries remain blocked throughout.
7. Workflow summaries expose remaining authorized attempts, pending staff entries, and the next wake reason.

The accompanying remediation covers the one-shot claim/failure/canary
invariants above. Item 7 and the richer grant schema remain future
observability and auditability improvements.

## Verification performed for this report

- Inspected current `operations/state.json` from protected `main`.
- Inspected job-level Actions state and logs for both CharacterLibrary attempts, the intervening delayed wake, post-failure reconciliation, Recursion, and the final maintenance pause.
- Traced targeted enqueue, failure rotation, canary selection, retry scheduling, delayed wake, and publication continuation in current source.
- Compared PR #180's exact changed-file set with the affected control path.
- Ran focused queue tests: `tests/backlog.test.ts` and `tests/durable-queue.test.ts`; 30 tests passed.

The focused tests listed above describe the deployed behavior at incident
time. The accompanying remediation adds the previously missing one-shot
authorization invariant and regression coverage; it is not deployed merely
because it appears in this report branch.
