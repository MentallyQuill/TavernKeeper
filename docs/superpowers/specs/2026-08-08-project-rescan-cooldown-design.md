# Project Rescan Cooldown Design

## Goal

Limit automatic rescans caused by upstream project commits to at most one
completed scan per repository in any rolling 48-hour interval. This reduces
scanner and contextual-review churn from projects that push several times per
day.

## Scope

The cooldown applies only when TavernKeeper already has a completed preferred
report for a repository and the Tavernary manifest advances that repository to
a different SHA. It does not delay:

- a repository's first scan;
- an explicit staff-requested scan;
- a versioned policy-rescan campaign; or
- the existing retry schedule after a failed scan attempt.

The interval begins at the latest preferred report's `completed_at` timestamp.
The changed target becomes runnable at exactly `completed_at + 48 hours`.
Additional pushes during that interval update the queued target to the newest
manifest SHA without extending the original eligibility time.

## Queue Design

Add an optional `rescan_not_before` timestamp to a durable queue entry. It is
separate from `not_before`, which remains the failure-retry cooldown. Queue
synchronization derives the timestamp from the preferred report when it seeds
or replaces an automatic changed-SHA target. Existing queue tickets remain in
place so the cooldown does not sacrifice fairness.

Staff requests and active policy campaigns omit or clear
`rescan_not_before`. Failure rotation continues to use `not_before`; a retry is
not reclassified as an automatic changed-SHA rescan.

Batch planning computes an entry's effective eligibility from its applicable
cooldowns. The automatic rescan timestamp is ignored for staff requests and
active policy campaigns. Delayed counts and `next_wake_at` include the rescan
cooldown, allowing the existing reconciliation workflows to wake accurately.

## Compatibility and Validation

`rescan_not_before` is optional, so committed schema-3 state remains valid and
does not require migration. When present, it must be a valid ISO timestamp.
Queue synchronization remains deterministic and byte-stable when its inputs do
not change.

## Tests

Focused queue tests will prove that:

- an automatic changed-SHA target is delayed before 48 hours;
- it becomes runnable at exactly 48 hours;
- repeated SHA changes retain the original report-based deadline;
- first scans remain immediately runnable;
- staff and policy rescans bypass the automatic cooldown; and
- failure retry timing retains its existing behavior.

The full repository check will cover formatting, types, all unit tests, and
workflow policy validation before publication.
