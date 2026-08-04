# Autonomous Catalog Scanning Design

## Status

Approved for implementation on 2026-08-04. This design replaces the current
catalog-wide coupling between target-local failures and the global circuit
breaker, preserves fail-closed report publication, and makes ordinary recovery
automatic.

## Problem

TavernKeeper has begun full-catalog coverage and can retain successful reports
from mixed batches, but it does not yet advance autonomously through failure.
The current implementation has four coupled defects:

1. Failures are classified only as `repository` or `system`. Scanner adapters
   use `system` for many failures caused by one repository's contents, so an
   incompatible target can stop unrelated catalog work.
2. The retry fingerprint is only `scope + code`. Every system
   `SCANNER_FAILED`, regardless of scanner component or cause, shares one
   global breaker identity.
3. The breaker clears only after every retry with that broad fingerprint is
   removed. One successful recovery therefore cannot prove the shared service
   healthy and release the queue.
4. A mixed batch deliberately suppresses continuation whenever any system
   failure occurs. The hourly retry cron is then the only wake-up, and a third
   failed retry makes the breaker terminal.

The live target manifest also exposes only `top_30: boolean`. TavernKeeper can
prioritize the Top 30 as a group, but it cannot scan the complete catalog in an
exact most-popular-first order.

## Goals

- Scan every eligible Tavernary GitHub source without one incompatible target
  stalling unrelated targets.
- Use an explicit all-catalog popularity rank for initial coverage.
- Publish every complete report from a mixed batch and continue immediately
  after target-local failures.
- Recover automatically from shared transient outages with bounded probes and
  capped backoff.
- Preserve a hard stop for credential, configuration, authenticity, and
  integrity failures that automation cannot safely repair.
- Keep publication fail-closed: no partial, degraded, inferred-safe, or
  unreviewed report may be published.
- Keep batches at five repositories and scan concurrency at two.
- Preserve exact-SHA acquisition, immutable report history, sanitized
  artifacts, and protected Publisher-App writes.

## Non-goals

- Changing Technical Report V5, scanner policy 3, contextual-review policy 1,
  or Tavernary's final risk synthesis.
- Automatically changing secrets, provider configuration, scanner pins, or
  security policy.
- Executing target dependencies, scripts, builds, tests, Actions, containers,
  or binaries.
- Hiding, removing, or recoloring a catalog listing because its scan failed.

## Considered approaches

### 1. Domain-aware isolation and recovery — selected

Classify failures as target-local, shared-transient, or security-hold; carry a
safe component/cause identity through the encrypted transition; retry each
class differently; and let the publisher decide whether continuation is safe.
This is the smallest design that is both autonomous and fail-safe.

### 2. Remove the global breaker

Treat every failure as target-local and keep scanning. This maximizes progress
but can create a catalog-wide retry storm during a provider outage or broken
scanner deployment, consume quota, and flood operational issues. It is not
robust enough.

### 3. Keep the breaker and shorten its timer

Run the current retry workflow more often and clear the breaker more
aggressively. This improves latency but retains the incorrect failure coupling
and can release the queue based on an unrelated success. It treats symptoms,
not the classification defect.

## Failure contract

Every failed phase emits a sanitized failure descriptor:

```ts
type FailureDomain = "target" | "shared" | "security";

interface FailureDescriptor {
  code: string;
  domain: FailureDomain;
  component: string;
  diagnostic?: string;
}
```

`component` is a bounded enum maintained by TavernKeeper. It distinguishes at
least acquisition, inventory, history, each pinned scanner, contextual model,
report finalization, artifact transport, publication, target manifest, and
GitHub/Pages operations. `diagnostic` is optional and must come from an
allowlist; no source text, provider body, credentials, or raw exception is
persisted.

The fingerprint is the SHA-256 of
`[domain, component, code, diagnostic ?? null]`. Repository ID and target SHA
remain separate retry identity fields rather than being folded into the
failure-class fingerprint.

### Target-local failures

Target-local failures are caused by, or bounded to, one exact repository SHA.
They never create a global hold. Examples include:

- unsafe or oversized repository structure;
- checkout, inventory, or history limitations for one target;
- scanner parse errors, target-driven nonzero exits, timeouts, output ceilings,
  or malformed target-specific output;
- model invalid-response, evidence, context, or output-limit failures for one
  review package; and
- exact-HEAD or report-binding failures limited to one acquired target.

They retry independently at 5 minutes, 30 minutes, and 2 hours. A fourth
failure exhausts that exact SHA, creates or updates one deduplicated staff
issue, and leaves the rest of the catalog runnable. A newer target SHA creates
a fresh sequence.

### Shared transient failures

Shared failures indicate a dependency that affects more than one target but
may recover without a code or secret change. Examples include provider quota,
provider network/DNS/5xx failure, GitHub/API availability, Pages availability,
or a scanner tool that cannot be installed or launched on the trusted runner.

A shared failure creates a nonterminal recovery hold keyed by its complete
failure fingerprint. New catalog targets pause, but completed reports still
publish and deploy. The scheduler admits one due target as a recovery probe for
each held key, bounded by the normal two-job concurrency. Probe delays are 5,
15, 30, and 60 minutes, then three hours capped indefinitely. Four consecutive
failures create or refresh one staff issue, but probes continue automatically.

The first successful probe for a held key clears that shared hold immediately.
Other targets that previously failed with the same key keep their independent
retry entries; they no longer keep the global queue blocked. Successful
publication/deployment then dispatches reconciliation immediately.

### Security holds

Security failures require an external configuration or trust decision and must
not be retried as ordinary work. Examples include invalid or rejected provider
credentials, an invalid endpoint boundary, artifact authentication failure,
outcome/target mismatch, invalid encryption configuration, Publisher-App
authorization failure, or evidence of credential compromise.

A security failure creates a staff pause and one deduplicated high-priority
issue. Scheduled reconciliation remains idempotent but dispatches no scans.
Staff must repair the external condition, run the relevant compatibility or
integrity check, and explicitly resume. This is a security hold, not a
transient circuit breaker, and is the only normal path that requires human
recovery.

Failures that prevent TavernKeeper from authenticating or committing the state
change cannot truthfully claim a persisted pause. Those workflows fail closed,
emit a secret-free Actions annotation, and create the incident with the
repository-local issue token when available. The absence of a committed
publisher result prevents continuation, so the queue remains stopped even when
the state file could not be updated.

## Operations state

Operations state moves to schema version 2. It stores:

- independent target retry sequences with failure domain and component;
- zero or more shared recovery holds, each with its failure key, consecutive
  failure count, first/last failure times, next probe time, and notification
  state;
- the existing staff/system pause, active scans, coverage start, and policy
  campaigns; and
- no raw error messages or target content.

Parsing supports a deliberate one-time migration from schema version 1. Legacy
provider quota/network codes become shared-transient; legacy authentication or
configuration codes become security holds; ambiguous legacy scanner,
scan-phase, and CLI failures become target-local retries and are surfaced in a
migration summary. Exhausted legacy repository failures remain exhausted but
do not block the queue. The singular legacy circuit breaker is removed unless
it maps to a security hold.

The migration is performed by an explicit CLI and protected staff workflow,
not opportunistically during report publication. It preserves
`coverage_started_at`, reports, histories, and policy campaigns.

## Workflow and data flow

1. Reconciliation fetches the trusted Tavernary target manifest, deployed
   report index, and operations state.
2. If a security pause exists, it emits no work. If shared holds exist, it
   emits only due recovery probes. Otherwise it selects up to five runnable
   targets.
3. Every matrix job attempts to produce one authenticated encrypted outcome.
   Phase errors retain their sanitized failure descriptor, including component
   and domain.
4. The serialized publisher authenticates the complete expected outcome set,
   publishes every completed report, records every failure, and commits one
   atomic reports/state change.
5. Pages deploys the exact committed source SHA.
6. The continuation job depends on publisher and deployment results, not the
   matrix conclusion. It dispatches reconciliation when the publisher reports
   runnable backlog and no shared/security hold.
7. A five-minute recovery schedule wakes delayed retries and shared probes.
   The existing six-hour reconciliation remains a missed-wakeup repair path.

The planner reports separate values for total uncovered targets, immediately
runnable targets, delayed target retries, active shared holds, and the earliest
next wake. `remaining` alone no longer controls continuation, preventing both
false stops and empty dispatch loops.

## Popularity ordering

Tavernary publishes target manifest version 3 with
`catalog_priority.popularity_rank`, a positive integer for every eligible
source. Tavernary derives a deterministic rank from the existing
`community.aggregate` ordering used for the Top 30; projects without a score
follow scored projects using the existing name/ID tie-break. A repository
shared by multiple supported cards receives the best (lowest) project rank.
`top_30` remains during the compatibility window and must equal
`popularity_rank <= 30`.

TavernKeeper accepts V2 and V3 during rollout. V3 initial coverage sorts
uncovered current-policy targets by:

1. due shared recovery probe;
2. due target retry;
3. `popularity_rank` ascending;
4. `first_cataloged_at` ascending; and
5. repository ID ascending.

During initial coverage, age boosts do not reorder unscanned targets ahead of
more-popular targets. Exhausted target-local failures count as attempted for
coverage progress but remain visible to staff. After initial coverage,
new/changed targets use the same popularity rank, with due retries first.

If only a V2 manifest is available, TavernKeeper retains the current Top-30,
new-submission, and old-project fallback. It never invents an exact rank from
repository ID or catalog date.

## Reliability and observability

- Operational issues deduplicate by complete failure fingerprint and domain.
- Shared-recovery issues remain open while probes fail and close automatically
  after recovery; target-exhaustion issues remain informational until the
  target advances or staff resolves them.
- Workflow summaries show reports published, target failures, shared holds,
  security holds, runnable backlog, delayed backlog, and next wake time.
- State commits and continuation dispatches remain serialized by the global
  concurrency group.
- Reconciliation and publication are idempotent against duplicate wake-ups.
- No retry path may lower scanner coverage, skip contextual assessments, swap
  models, infer low risk, or publish incomplete output.

## Verification

TDD coverage must prove:

- failure classification for every scanner/model/acquisition code;
- component-aware fingerprints do not couple unrelated failures;
- target exhaustion never blocks unrelated catalog work;
- shared holds admit bounded probes, back off, notify, and never become
  terminal solely from elapsed attempts;
- one successful probe clears only its shared hold and immediately makes the
  backlog runnable;
- security failures pause and require explicit resume;
- mixed batches publish successes and continue after target failures;
- continuation runs despite failed matrix jobs when publication/deployment
  succeed and the planner says work is runnable;
- delayed-only backlogs do not create dispatch loops;
- schema-v1 state migrates deterministically without losing coverage start;
- V3 manifests rank the complete catalog and TavernKeeper respects that rank;
  and
- V2 fallback ordering remains compatible during rollout.

Release verification includes TavernKeeper's complete check, E2E gate, build,
workflow-policy check, scanner verification/smoke, exact diff review, and
protected-branch CI. Tavernary's V3 manifest change receives its complete
content/unit/build verification. Live proof must show a mixed batch with one
target-local failure still publishing and continuing, then a controlled shared
transient failure recovering through a scheduled probe and automatically
resuming the popularity-ordered backlog.

## Rollout

1. Pause ordinary production scanning through the protected staff workflow.
2. Merge TavernKeeper state/failure/workflow compatibility while it still
   accepts V2 manifests.
3. Run the explicit operations-state migration and verify the preserved
   coverage timestamp and report index.
4. Merge and deploy Tavernary manifest V3 with explicit popularity ranks.
5. Verify TavernKeeper parses the live V3 manifest and plans the next batch in
   rank order.
6. Run provider and scanner-toolchain compatibility checks.
7. Resume scanning and verify target-local continuation plus shared recovery.
8. Leave the five-minute recovery cron and six-hour reconciliation active.

This orchestration change does not alter scanner eligibility or report output,
so no report-history reset is required.
