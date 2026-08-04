# Catalog-First Failure Quarantine Design

## Status

Approved in conversation on 2026-08-04. Written-spec review is pending.

This design is a focused amendment to
`2026-08-04-autonomous-catalog-scanning-design.md`. It preserves the V2
failure domains, protected publisher, exact-SHA acquisition, five-target
batches, two-job concurrency, and fail-closed report publication. It replaces
the retry-first target ordering that allowed repeatedly failing repositories to
consume the next catalog batch.

## Problem

Production evidence exposed five related defects:

1. Due target retries sort ahead of ordinary catalog work. A deterministic
   failure can therefore re-enter the next batch while most of the catalog is
   still unscanned.
2. Target retries are scheduled from the initial failure time. When a catalog
   pass lasts longer than the retry delays, a newly recorded retry can already
   be overdue and immediately runnable.
3. Deterministic and transient target failures share one automatic retry
   policy. Parser incompatibilities and repeated model-contract violations are
   retried even though neither the repository SHA nor the failing input changed.
4. Target state retains only the latest failure descriptor. Aventuras changed
   failure shape across attempts, while NemoPresetExt repeated the same invalid
   model field, but the terminal record cannot distinguish those histories.
5. Target exhaustion issues deduplicate only by a class fingerprint. Schema
   migration created duplicate issues for Marinara-Engine and NemoPresetExt,
   while the shared generic OpenGrep fingerprint can hide failures from other
   repositories.

The active security hold adds a sixth defect. An untyped error thrown while
building textual evidence from a scanner finding becomes `CLI_FAILED` in the
security domain. Strong reproduction evidence indicates that a malcontent
finding on a binary or archive path reached the text-only evidence builder.
The generic-error security default is correct, but the known target-local
boundary failed to type its own error.

## Goals

- Complete one primary attempt across the current catalog before automatic
  target retries consume scan slots.
- Keep every failed exact target unpublished and quarantined.
- Automatically retry only failures that can plausibly recover without a new
  SHA, code change, policy change, or operator decision.
- Bound every exact target SHA to four queued scan attempts.
- Preserve a safe, bounded descriptor history for each target.
- Make immediate model retries corrective rather than identical.
- Type the binary-evidence incompatibility at its source without weakening the
  unknown-error security default.
- Give every exact target one stable operational incident, independent of
  failure-class fingerprint changes.
- Resume the existing catalog without resetting reports, history, coverage
  start, or retry counts.

## Non-goals

- Publishing partial or degraded reports.
- Ignoring OpenGrep diagnostics merely to make a target pass.
- Reducing scanner coverage, model review coverage, or validation strictness.
- Replacing the V2 target/shared/security failure-domain architecture.
- Changing batch size, scan concurrency, Technical Report V5, scanner policy,
  or contextual-review policy.
- Treating an unknown generic exception as target-local.
- Automatically clearing the current security hold before the corrected code
  is deployed and the affected target is revalidated.

## Approved invariants

1. A failed target is completely unpublished and quarantined.
2. Unrelated primary catalog targets continue.
3. Quarantined targets cannot preempt primary catalog work.
4. Deterministic target failures require a new SHA or explicit operator retry.
5. Potentially transient target failures become automatically eligible only
   after primary catalog work is empty and their backoff has expired.
6. One target receives at most one slot in a retry round.
7. Four failed queued attempts exhaust an exact target SHA.
8. A shared provider outage does not consume a target-local attempt budget.
9. Genuine security failures remain global, fail-closed holds.

## Considered approaches

### 1. Catalog-first quarantine with typed retry eligibility — selected

Derive a primary lane from current manifest/index coverage and a quarantine
lane from exact-SHA retry state. Admit automatic retries only when the primary
lane is empty. Persist whether a failure is automatic or manual and retain the
existing bounded attempt count.

This directly prevents starvation while changing only the planner and retry
state around the existing scan and publisher pipeline.

### 2. One automatic retry for every failure

This would be cheaper than the current system, but deterministic targets would
still consume a second slot before the catalog is complete unless queue
ordering also changed. It also abandons genuinely transient targets too soon.

### 3. Keep timed retries interleaved with primary work

This retains the current architecture but recreates the reported failure mode.
Popularity rank cannot protect catalog progress while every due retry has a
higher global priority.

## Failure and retry contract

The sanitized `FailureDescriptor` remains the transport and class identity:

```ts
interface FailureDescriptor {
  code: string;
  domain: "target" | "shared" | "security";
  component: FailureComponent;
  diagnostic?: SafeFailureDiagnostic;
}
```

Target retry state gains two backward-compatible fields:

```ts
type TargetRetryMode = "automatic" | "manual";

interface TargetFailureHistoryEntry {
  failed_at: string;
  failure: FailureDescriptor;
  error_fingerprint: string;
}

interface TargetRetryEntryV2Extension {
  retry_mode?: TargetRetryMode;
  failure_history?: TargetFailureHistoryEntry[];
}
```

Older V2 entries without these fields remain readable. Their retry mode is
derived through the same explicit classifier used for new failures. Every new
failure persists the selected mode and appends a safe history entry. History is
bounded to the four queued attempts for the exact SHA; it never stores source
text, raw model output, provider bodies, filesystem paths, or raw exceptions.

For a manual, nonexhausted quarantine, `next_retry_at` is null. For an
automatic, nonexhausted quarantine, `next_retry_at` is calculated from
`last_failed_at`, not `initial_failed_at`. The delays remain 5 minutes,
30 minutes, and 2 hours. The fourth failed queued attempt sets `exhausted=true`
and `next_retry_at=null` regardless of mode.

An explicit targeted scan is the operator retry mechanism. If it fails, it
increments the same exact-SHA attempt sequence. A new repository SHA has no
matching retry identity and enters the primary lane as changed work.

## Retry classification

Retry eligibility is a bounded decision made from the safe descriptor, not a
raw message.

Deterministic/manual examples include:

- OpenGrep parser syntax diagnostics for a committed file;
- a scanner failure whose safe descriptor identifies target-specific malformed
  output;
- contextual-model invalid-response or evidence-validation failure after
  corrective immediate attempts;
- contextual review that remains incomplete after bounded context expansion;
- unsupported non-text evidence construction; and
- exact-SHA inventory, package, or finalization contract failures.

Potentially transient/automatic examples include:

- a scanner runtime timeout;
- a bounded repository acquisition or history transport failure; and
- another explicitly allowlisted target-local condition that can change
  without changing target content.

Shared provider, quota, installation, and service failures retain the shared
probe path. Credential, configuration, authenticity, integrity, and genuinely
unknown errors retain the security path.

OpenGrep adds bounded diagnostics for parser syntax and rule timeout. If one
run contains both, deterministic parser failure wins because the complete scan
cannot succeed until that parser incompatibility changes. The scanner still
publishes no partial findings.

## Catalog-pass planning

The planner constructs two independent candidate sets:

1. **Primary candidates:** current manifest targets that need a new, changed,
   or policy report and have no matching exact-SHA quarantine.
2. **Retry candidates:** matching exact-SHA target retry entries that are not
   exhausted, are automatic, and are due.

Planning follows this order:

1. A security pause emits no work.
2. A shared hold admits only its bounded recovery probes, as today.
3. If any primary candidate exists, select up to five primary candidates by
   the existing V3 popularity order or V2 compatibility order. Target retries
   are not considered.
4. Only when the primary set is empty may the planner select up to five due
   automatic retry candidates, oldest eligible first.
5. Manual and exhausted quarantines remain visible in totals and operations
   output but are never automatically dispatched.

No persistent catalog epoch is required. The current manifest, preferred
report index, active scans, and exact-SHA quarantine identities completely
define whether primary work remains. Duplicate wake-ups remain idempotent.

The planner exposes separate primary, automatic-retry, manual-quarantine, and
exhausted counts in its JSON and workflow summary. A delayed-only retry backlog
exposes `next_wake_at` and does not create a continuation loop.

## Corrective model attempts

Contextual review may still make up to three immediate model calls inside one
queued scan attempt, but every repeated call must change the request.

Validation produces a bounded repair descriptor containing only the safe
diagnostic code and schema location category. The next prompt includes that
descriptor as trusted corrective instructions. It does not include rejected
model prose. If the next repair descriptor would be identical to the one
already supplied, the reviewer stops early and returns the typed target-local
failure instead of issuing another identical request.

Context expansion remains separate: a valid `needs_more_context` response may
expand the immutable evidence group and retry because the evidence changed.
Provider outages remain shared failures and do not enter the target repair
loop.

## Evidence-context boundary

Evidence construction introduces a typed, sanitized error for a current
scanner finding that cannot be represented as verified text. The descriptor is
target-local, uses a dedicated evidence-context component, and records only an
allowlisted diagnostic such as `evidence_non_text`; it does not persist the
path or scanner output.

This change is made at `readVerifiedText()` or its immediate evidence-group
caller. The top-level classifier continues mapping an arbitrary `Error` to
`CLI_FAILED` in the security domain. Other unexpected evidence-construction
errors therefore still stop the system.

## Operational incident identity

Target incidents are keyed by the exact target identity:

```text
target incident key = SHA-256(["target", repository_id, target_sha])
```

Failure fingerprints remain inside the issue body and history, but they do not
create multiple issues for one exact target. Shared recovery incidents continue
to use their class fingerprint because they intentionally represent one shared
outage.

Before creating a target incident, the workflow searches for the exact target
incident key and then performs a compatibility search for the repository ID
and SHA used by pre-amendment issues. It reuses the oldest matching issue.
One rollout reconciliation closes the known duplicate pairs with a reference to
their canonical issue. A successful retry or newer target SHA closes the
canonical target incident; issue closure never implies that an unpublished
report was accepted.

## Data flow

1. Reconcile reads the trusted manifest, deployed report index, and V2 state.
2. The planner separates primary candidates from quarantines.
3. Matrix jobs remain unchanged in authority: each produces one authenticated,
   encrypted completed or failed outcome.
4. Known scanner, model, and evidence boundaries emit typed safe descriptors.
5. The publisher publishes every complete report and records every failed exact
   target with retry mode and bounded history.
6. Continuation dispatches another primary batch while primary work remains.
7. After primary work is empty, the scheduled wake or continuation admits due
   automatic retries.
8. Manual and exhausted quarantines remain fail-closed until a new SHA or
   explicit operator action.

## Verification

TDD coverage must prove:

- due retries never precede primary work;
- a changed SHA enters primary work even when an older SHA is quarantined;
- manual quarantines never enter automatic batches;
- automatic retries use backoff from the latest failure;
- one retry failure cannot immediately reselect the same target;
- four queued failures exhaust the exact SHA;
- shared failures do not increment a target-local attempt sequence;
- safe failure history preserves changing descriptors and repeated descriptors;
- OpenGrep syntax and timeout diagnostics choose the documented retry mode;
- mixed syntax plus timeout is deterministic/manual;
- non-text evidence raises the typed target-local error while unrelated generic
  errors remain security failures;
- model repair changes the second request and identical repair feedback stops a
  redundant third call;
- exact-target incident identity prevents migration duplicates and cross-target
  fingerprint collisions; and
- workflow summaries distinguish primary, automatic, manual, and exhausted
  work.

The complete TavernKeeper check, E2E suite, build, workflow-policy check,
scanner verification, scanner smoke, and diff checks remain required.

## Rollout and recovery

1. Keep the current production security hold in place during implementation.
2. Merge the backward-compatible state and planner changes without resetting
   reports, histories, coverage start, or attempts.
3. Run focused exact-SHA local reproductions for Marinara-Engine, Lumiverse,
   NemoPresetExt, Aventuras, and SillyBunny to verify their safe classification.
4. Run provider and scanner compatibility workflows.
5. Explicitly resume the existing security hold only after the new evidence
   boundary is deployed.
6. Run a targeted SillyBunny scan. If it produces the expected non-text
   evidence descriptor, it becomes a manual target quarantine and unrelated
   catalog work continues. If it still produces an unknown generic error, the
   security hold remains and the system does not claim recovery.
7. Verify that the next reconciliation selects popularity-ordered primary
   targets and not overdue Marinara/Lumiverse retries.
8. Verify a transient target retry becomes eligible only after primary work is
   empty and its latest-failure backoff expires.
9. Reconcile the two known migration-created issue pairs after the canonical
   target incident behavior is live.

This rollout changes scheduling and diagnostics only. It requires no report
history reset and no degraded-publication compatibility window.
