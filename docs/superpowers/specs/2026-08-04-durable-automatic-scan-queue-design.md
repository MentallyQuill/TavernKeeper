# Durable Automatic Scan Queue Design

**Status:** Approved on 2026-08-04  
**Scope:** TavernKeeper scanning and publication, Tavernary report import, and the automation between them  
**Supersedes:** The permanent/manual automatic-hold, retry-exhaustion, retry-first, and deployment-gating portions of `2026-08-04-autonomous-catalog-scanning-design.md`

## Directive

Every common catalog-processing path must recover automatically. A project failure may delay that project, but it must never pause the catalog, require a staff resume, disappear from retry consideration, or repeatedly jump ahead of healthy work.

After a bounded failure streak, the project is moved behind the queue that exists at that moment. Later arrivals are appended after it. This guarantees that the failed project will be retried after the finite set of projects already ahead of it, even while the catalog grows.

## Current Failure Modes

The existing system violates that directive in four ways:

1. Unknown orchestrator failures are classified as security failures and create a system-wide `SECURITY_HOLD`.
2. Target retries are selected ahead of fresh catalog work and become terminal after four failures.
3. Reconciliation waits for Pages to match the latest committed report index before it dispatches more scans.
4. Tavernary imports reports in one transaction, so one synthesis failure prevents every later report from being imported.

These are liveness failures, not merely retry-timing problems. The redesign removes terminal and staff-gated recovery states from common operation. Shared and security boundary failures use a finite, automatically probed circuit so a known-broken common dependency is not hammered by the full catalog.

## Goals

- Persist the exact order of every eligible scan target.
- Prevent both healthy-work starvation and failed-project starvation.
- Retry failed projects forever without letting a hot failure monopolize capacity.
- Keep report integrity fail-closed: incomplete or degraded scans never become published reports.
- Let scanning continue while Pages deployment or Tavernary import is delayed.
- Let Tavernary import healthy reports while another report repeatedly fails synthesis.
- Migrate the current held and exhausted state automatically.
- Keep the solution proportional to the steady-state load of roughly 5–10 projects per day.

## Non-goals

- A general-purpose queue service, database, broker, daemon, or distributed scheduler.
- Infinite parallelism or an attempt to make external outages disappear.
- Publishing partial security reports.
- Removing an explicit human emergency stop. An operator-set stop remains available, but no common failure may create one.

## Considered Designs

### Selected: persisted monotonic tickets

Each target receives an increasing integer ticket. The scheduler chooses the lowest eligible ticket. A failed target moves once to the current tail by receiving `next_ticket`, then `next_ticket` is incremented.

This is the smallest design that makes arrival ordering durable and its starvation behavior provable.

### Rejected: frozen queue epochs

Epochs would freeze the initial backlog and admit later projects only after the epoch drains. This also prevents overtaking, but introduces epoch rollover, partially drained epochs, and special handling for a permanently failing member.

### Rejected: weighted priority or aging

A score combining popularity, age, and failures could usually behave well, but would not give a simple no-overtaking guarantee. It would also require tuning for a workload that will become small after the initial backlog.

## TavernKeeper State

`operations/state.json` advances to schema version 3 and owns a compact scan ledger:

```json
{
  "schema_version": 3,
  "emergency_stop": null,
  "automatic_holds": [],
  "scan_queue": {
    "next_ticket": 306,
    "entries": [
      {
        "repository_id": 123456,
        "repository": "owner/name",
        "target_sha": "0123456789abcdef",
        "ticket": 1,
        "consecutive_failures": 0,
        "total_failures": 0,
        "not_before": null,
        "last_failure": null,
        "chronic": false
      }
    ]
  },
  "active_scans": [],
  "policy_campaigns": []
}
```

The manifest and report index remain authoritative for eligibility and coverage. The queue stores ordering and retry state, not duplicate catalog metadata.

`repository_id` is the stable identity. `repository` is retained for readable diagnostics. `target_sha` makes each request immutable. Tickets and `next_ticket` must be positive safe integers and unique within the queue.

## Queue Synchronization

Before choosing a batch, a protected synchronization step reconciles the current manifest and report index into state and commits a changed state before dispatch:

1. Remove entries whose exact target is already covered or no longer eligible.
2. If an existing repository now points at a different SHA, update that entry in place, preserve its ticket, and clear its failure streak and cooldown.
3. Append missing eligible targets in current catalog popularity order, assigning consecutive tickets.
4. Preserve every existing ticket not affected by the rules above.

The first schema-3 synchronization seeds the whole current backlog in one operation. Existing target retries and exhausted targets are reconciled into this ledger rather than discarded. Legacy shared and system holds become finite automatic recovery circuits whose next probes are scheduled without staff action. An explicit operator emergency stop is preserved.

Synchronizing the full ledger before dispatch is important: it records the membership of the _current_ tail. If synchronization or its protected push temporarily fails, the scheduled reconciler retries it; it never writes a terminal pause.

## Scheduling and Retry Semantics

The scheduler selects up to five due entries by ascending ticket and retains the existing maximum parallelism of two.

- An entry is due when `not_before` is absent or has passed.
- A cooling entry is skipped without changing its ticket.
- Once its cooldown expires, its old ticket makes it precede every later ticket.
- Success removes the exact queue entry after its complete report is published.
- Failure increments the counters, assigns the entry the current `next_ticket`, increments `next_ticket`, records a sanitized diagnostic, and assigns a capped cooldown based on the most recent failure.
- The fifth consecutive failure marks the entry `chronic` and raises or updates a diagnostic incident. It remains queued and continues rotating forever.
- A newer target SHA clears the consecutive streak and cooldown because it is a different immutable scan target. Historical `total_failures` may remain for operations telemetry.

### Starvation argument

When target A fails and is assigned ticket T, only a finite number of queued entries have tickets below T. Every project discovered later receives a ticket greater than T. Each entry ahead of A either succeeds and leaves or fails and moves behind A. Therefore the number of entries ahead of A strictly decreases as they are attempted. Once A is due, later arrivals cannot overtake it.

This property does not require high steady-state volume. With 5–10 daily projects, the same small JSON ledger remains sufficient.

## Failure Boundaries

Failure classification determines whether recovery is target-local or whether a shared trusted boundary needs one bounded probe before normal batching resumes.

- Every target, shared-component, security-provider, and unknown scan failure fails the current immutable report and rotates that target to the current queue tail.
- Target-local failures do not affect peer scheduling.
- Shared and security failures open or refresh a fingerprinted automatic circuit. While it cools, ordinary batches are withheld; at 5 minutes, 30 minutes, 2 hours, and then every 6 hours, the scheduler admits exactly one lowest-ticket due target as a recovery probe.
- A matching successful probe clears only that circuit and the next reconciliation immediately resumes normal ticket order. A failed probe rotates its target, refreshes the relevant circuit, and schedules itself automatically. A fifth failure is chronic diagnostic state, never terminal state.
- No common exception writes an emergency stop.
- Credentials, integrity, or provider failures remain fail-closed for the affected report and open or update an incident.
- Workflow-level failures before a target result is available are retried by the scheduled reconciler and GitHub Actions. They do not mutate durable state into a blocked state.
- Only an explicit operator action may set `emergency_stop`. Resuming it is likewise explicit because it represents intentional operational control, not ordinary recovery.

Diagnostics must preserve a sanitized phase and underlying error category. Generic or unrecognized system failures default to the shared circuit, not the security domain. Only explicitly classified authentication, configuration, identity, response-origin, and policy-integrity failures use the security domain.

## Independent Automation Loops

The pipeline is divided into three independently progressing loops:

1. **Scan loop:** synchronize queue, dispatch a bounded batch, publish complete reports, record outcomes, and immediately schedule the next reconciliation when work remains.
2. **Pages loop:** reconcile the latest committed report index with Pages and retry deployment independently until it matches.
3. **Tavernary loop:** discover deployed reports, import each report independently, persist successes and retry state, and retry pending imports independently.

Scanning never waits for Pages digest parity. Publishing a report commit may request a deployment, but scheduling the next scan does not depend on deployment success. Tavernary receives a successful-deploy wake-up as an optimization and retains its scheduled reconciliation as the durable recovery path.

## Tavernary Import Ledger

Tavernary gains a small persisted import ledger beside its synthesized security snapshot:

```json
{
  "schema_version": 1,
  "next_ticket": 42,
  "entries": [
    {
      "report_id": "owner/name@sha",
      "ticket": 12,
      "attempts": 2,
      "not_before": "2026-08-04T12:00:00.000Z",
      "last_failure": "SYNTHESIS_INVALID"
    }
  ]
}
```

Each run reconciles newly deployed report IDs into the ledger, then processes due entries in ticket order. A report is handled inside its own error boundary:

- Success updates the security snapshot and removes the ledger entry.
- Failure moves only that report to the current tail, applies a capped cooldown, and allows later due reports to continue in the same run.
- Five failures make an incident chronic but never terminal.
- New reports receive tickets after all currently assigned imports, including previously failed imports.
- A failed replacement report leaves the previous successful assessment preferred until the replacement succeeds. A brand-new repository remains without an assessment rather than receiving partial data.

Snapshot and ledger changes are committed together after the run. The import workflow schedules another import when due work remains and triggers site deployment independently; deployment failure cannot roll back or block the next import attempt.

## Workflow Changes

### TavernKeeper

- Add a protected queue-synchronization job before planning.
- Remove the pre-scan Pages parity gate.
- Remove retry-first derived sorting, permanent/manual shared-security holds, exhaustion, and `continuation_blocked`; replace them with the finite automatic circuit and single-probe path.
- Make continuation depend only on whether eligible queue work remains or a future cooldown is scheduled.
- Dispatch Pages reconciliation and the next scan reconciliation independently after publication.
- Keep one global scan concurrency group so state writers remain serialized.

### Tavernary

- Replace the all-or-nothing importer loop with per-report outcomes and a persisted ticket ledger.
- Commit partial successes and retry movement even when another report fails.
- Continue scheduled imports and optionally dispatch a near-term continuation when pending due work remains.
- Separate import success from Pages deployment success.

## Verification

### TavernKeeper unit and workflow tests

- Stable initial seeding and uniqueness of tickets.
- Existing entries cannot be overtaken by later manifest arrivals.
- A failure moves exactly once to the current tail.
- A fifth and later failure remains eligible and rotates again.
- Cooldown skips without repositioning; expiry restores ticket priority.
- SHA replacement preserves ticket and resets the streak.
- Schema-2 target retries migrate into queue entries; shared and system holds migrate into finite, immediately reconsidered automatic circuits.
- Unknown failures create a shared automatic circuit with a finite next probe, never an emergency stop.
- Cooling circuits admit no ordinary batch, due circuits admit exactly one fingerprinted probe, and only a matching success clears the circuit.
- A mixed batch publishes successes and queues failures without blocking continuation.
- Scan continuation is independent of Pages deployment.

### Tavernary unit and workflow tests

- One synthesis failure does not prevent later reports from succeeding.
- Partial successes and retry movement persist together.
- A failed report keeps its place ahead of later arrivals after moving to the then-current tail.
- Five failures remain retryable.
- A failed replacement preserves the previous preferred assessment.
- Import continuation is independent of site deployment.

### Integration and live proof

1. Merge TavernKeeper through its protected checks.
2. Observe schema-3 synchronization materialize the full eligible backlog and convert legacy shared/security state into due automatic probes.
3. Confirm the lowest-ticket targets advance while the repeatedly failing target remains in the ledger behind the captured tail.
4. Confirm a report commit can be followed by another scan even if Pages reconciliation is pending or failing.
5. Merge Tavernary through its protected checks and verify a known failing synthesis no longer blocks later report imports.
6. Verify exact deployed commits and hydrated catalog behavior after the independent deployment loops converge.

## Operational Invariants

1. No common project, provider, CLI, synthesis, publication, or deployment failure can create a permanent or staff-gated stop; every shared/security circuit has a finite automatic probe time.
2. Every eligible target is either covered, active, queued with a durable ticket, or temporarily cooling until a finite timestamp.
3. Every failed target remains in the same current queue and later arrivals cannot overtake its requeued ticket.
4. No incomplete or degraded security report is published.
5. Scan, deployment, and import progress are observable and independently recoverable.
