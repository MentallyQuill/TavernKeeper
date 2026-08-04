# Partial Batch Publication Design

## Context

TavernKeeper scans a bounded matrix of five independent repositories. Each
matrix job produces one authenticated encrypted outcome containing either a
complete Technical Report V5 candidate or a classified failure transition.
The serialized publisher already prevalidates all supplied reports and rolls
back every report, history, state, and preferred-index write if publication
itself fails.

The current publisher adds an unnecessary batch-wide rule: when any outcome
contains a system-scoped failure, it passes an empty candidate list to the
publisher. GitHub Actions also uses fail-fast matrix execution. As a result,
one repository can cancel unfinished peers and discard valid reports that
other repositories completed. Those successful repositories are selected and
scanned again, increasing provider calls, scanner work, latency, and the chance
that another unrelated failure blocks the same reports.

## Goal

Complete every started five-repository matrix independently, atomically
publish every schema-valid completed report from the batch, and record only
unsuccessful repositories in the existing retry state. A system-scoped failure
still engages TavernKeeper's existing circuit breaker for subsequent batches.

## Non-goals

- Do not change scanner selection, scanner policy, contextual-review prompts,
  accepted assessment vocabulary, report construction, report schema, risk
  synthesis, retry delays, catalog priority, or batch size.
- Do not publish an incomplete or degraded report for any repository.
- Do not clear or reset Wandlight, Recursion, or any other scan history. This
  change affects batch orchestration and retention only, not test behavior or
  report output.
- Do not weaken publisher authentication, immutable paths, prevalidation, or
  rollback guarantees.
- Do not remove the system circuit breaker or automatically bypass terminal
  failures.

## Design

### Independent matrix completion

The scan matrix sets `fail-fast: false` while retaining `max-parallel: 2` and
the five-target batch ceiling. A failed system transition still makes that
repository's matrix job fail, but GitHub Actions allows every other selected
repository to finish. Each job continues to upload exactly one encrypted
outcome, including bootstrap failures and classified phase failures.

### Candidate retention

The publish command processes decrypted outcomes by artifact directory so each
candidate remains paired with its transition. It records every failure through
the existing `recordFailure` path. For a completed transition, it requires and
validates that outcome's candidate before passing the report to
`publishCandidates`, regardless of whether another transition has system
scope. A failure transition must not carry a candidate.

Candidate acceptance remains all-or-nothing at the report level. A candidate
must have a completed transition produced by its scan job and must pass the
existing V5 sanitizer, schema, evidence, immutable-path, history, and index
validation. A failed repository supplies no candidate and therefore cannot
produce a report.

The publisher retains its transaction boundary across the successful subset:
all valid successes in that subset publish together, or a publication failure
rolls back the entire subset and its state/index updates.

### Result classification

The publish command reports one of three operational statuses:

- `published`: one or more reports published and no failure transition was
  present;
- `partial`: one or more reports published and at least one failure transition
  was recorded;
- `deferred`: no reports published and one or more failure transitions were
  recorded.

The command also returns explicit `has_failures` and `system_failure` booleans
for workflow routing. These values describe the batch, not any public project
assessment.

### Deployment and continuation

The publish job captures the command result and exposes `reports` and
`system_failure` as job outputs. A successful publish job may deploy even when
one or more matrix jobs failed, because its reports and operations state have
already passed serialized publication. The deploy condition therefore uses an
explicit `always()` guard and requires a successful publish job. This preserves
the existing exact-source-SHA deployment contract even when a no-report batch
changes only retry state and the generated index timestamp.

When a mixed batch contains a system failure, deployment publishes the valid
successes and updated retry/circuit state, but the `continue` job does not
dispatch another ordinary backlog batch. Existing retry and circuit behavior
remains authoritative. When failures are repository-scoped only, or when all
repositories succeed, normal continuation remains allowed.

If a batch publishes no report, TavernKeeper still commits and deploys any
changed retry/circuit state and generated index timestamp. When those failures
are repository-scoped only, normal backlog continuation remains allowed after
the exact source commit is live. A system failure suppresses continuation.

### Safety properties

- A repository never receives a report unless its own deterministic scan,
  contextual review, finalization, and exact-HEAD checks completed.
- A failure in one repository cannot turn another repository's candidate into
  a degraded report or change its contents.
- Authenticated encrypted transport remains mandatory for every outcome.
- The serialized publisher still prevalidates the full successful subset and
  rolls back partial filesystem writes.
- System failures still engage the existing circuit breaker and retain their
  existing retry schedule and terminal escalation.
- The preferred index and Tavernary importer see only committed, deployed V5
  reports.

## Testing

Unit and workflow-policy tests cover these cases:

1. Two valid candidates plus one system failure publish both reports, record
   the failed target, engage the circuit breaker, and return `partial`.
2. A system failure with no candidate publishes zero reports and returns
   `deferred`.
3. Repository-scoped failures alongside successes publish the successes,
   record retries, and return `partial` without engaging a new system breaker.
4. An invalid candidate in the successful subset still causes publisher
   prevalidation to reject the whole subset before immutable writes.
5. The workflow matrix has fail-fast disabled and preserves max parallelism of
   two.
6. The deploy job runs after any successful serialized publisher, including a
   mixed batch whose scan matrix result is failure.
7. The continuation job is suppressed when `system_failure` is true and is
   retained for all-success or repository-only-failure batches.

The full CI suite must remain green, including workflow pinning and policy
checks.

## Production rollout

Merge the verified change through the normal protected-main path. Allow the
next bounded production batch to run without manual target retries. Confirm
that a deliberately encountered mixed outcome, if one occurs naturally,
commits and deploys its successful reports, retains retry entries only for
unsuccessful targets, leaves the system circuit engaged when appropriate, and
does not reselect the newly published repositories.

No Wandlight or Recursion reset is part of this rollout because neither the
test nor report output changes.
