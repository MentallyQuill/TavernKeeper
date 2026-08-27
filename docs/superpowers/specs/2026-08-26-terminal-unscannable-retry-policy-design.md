# Terminal Unscannable Retry Policy

## Problem

TavernKeeper currently retries target-local scan failures forever. The retry
delays grow, but every repository remains eligible for more expensive scans and
can keep an incident open indefinitely. Restoring provider credentials exposed
a large backlog of these target-local failures.

Provider-wide, shared-infrastructure, and security failures already have a
different safety mechanism: they create automatic holds. This design leaves
that behavior intact and changes only failures classified in the `target`
domain.

## Approved Policy

Each repository gets one immediate retry for a target-local failure:

1. The first target-local failure returns the repository to the queue without a
   delay. This is the one automatic retry.
2. If that retry also fails, TavernKeeper records two consecutive failed
   attempts and defers the repository for seven days.
3. When the cooldown expires, TavernKeeper makes one final automatic attempt.
4. If the final attempt fails, TavernKeeper removes the repository from the
   active scan queue and marks the repository `unscannable`.
5. An unscannable repository cannot be enrolled again by catalog reconciliation,
   a new commit, policy changes, staff priority, or coverage campaigns. A staff
   member must explicitly add it back before automatic scanning can resume.

Only target-local failures consume this attempt budget. Provider, shared-system,
and security failures continue to use automatic holds and do not mark a target
unscannable.

## Canonical State

`operations/state.json` remains the authority. Operations state gains a
top-level `unscannable_targets` collection. Each tombstone records:

- repository source identity and owner/name;
- the target commit that exhausted the attempt budget;
- when the target was marked unscannable;
- consecutive and lifetime failure counts;
- the last sanitized failure classification and message; and
- the bounded failure history already used by queue entries.

The tombstone is keyed by repository source identity rather than commit SHA.
This prevents a new commit from silently resetting the expensive failure cycle.
The field defaults to an empty collection so existing schema-version-3 state
can be read without an unrelated state migration.

Active policy and coverage campaigns must also drop tombstoned repository IDs
from their remaining work. Otherwise an intentionally removed repository would
leave a campaign permanently active even though it can no longer be selected.

While a repository is still in its retry/cooldown cycle, reconciliation must
also preserve its consecutive failure state when the catalog SHA changes. A
push must not evade the attempt budget. The queued target SHA may advance to
the current catalog SHA, but the repository-level failure episode continues.

When legacy state first migrates or reconciles under this policy, attempts one
and two receive the new immediate/seven-day deadlines, while any queued target
that already has three or more consecutive target failures is converted to an
unscannable tombstone. This bounds the existing backlog without paying for
another scan solely because the old policy permitted unlimited retries.

## Queue Transitions

Target failure transitions are deterministic:

| Consecutive failure | Queue result                                          | Incident state      |
| ------------------- | ----------------------------------------------------- | ------------------- |
| 1                   | Move to queue tail with `not_before: null`            | No chronic incident |
| 2                   | Move to queue tail with `not_before` seven days later | Cooling down        |
| 3                   | Remove from queue and active scans; write tombstone   | Unscannable         |

Successful publication removes the queue entry as it does today. A successful
scan after the cooldown therefore ends the failure episode without creating a
tombstone.

The existing `chronic` queue marker becomes true at the second consecutive
failure so operations and issue reconciliation can expose the week-long
cooldown. Tombstoned repositories are reported separately and are not kept as
fake queue entries.

## Manual Add-Back

The protected staff-operations workflow gains an `add-back` operation that
requires the repository source ID. It atomically removes only that repository's
unscannable tombstone, seeds a staff-requested queue entry, and then dispatches
normal reconciliation. The explicit staff request remains eligible even when
an exact current report already exists, and reconciliation advances it to the
catalog's current commit if necessary. Lifetime failure totals remain on the
queue entry while the new consecutive-failure episode starts at zero.

The existing staff `retry` action remains for repositories that are still in
the queue. It cannot bypass an unscannable tombstone. This keeps manual recovery
explicit and auditable.

## Incident Reconciliation and Backlog Drain

The exhausted-state export includes both cooling targets and unscannable
tombstones. GitHub issue reconciliation handles each repository incident by its
stable target key:

- after the second failure, create or update its scanner incident with the
  seven-day cooldown and remaining final attempt;
- after terminal failure or legacy normalization, update any matching incident
  to say the repository was removed from automatic scans and requires protected
  manual add-back, apply a `scanner-unscannable` label, and close it without
  creating new closed-only issues for legacy targets that never had one;
- after successful recovery, close a still-open cooling incident with the
  existing recovery explanation; and
- leave unrelated safety and scanner-review issues to their existing
  reconciliation paths.

This makes the issue pool a view of canonical operations state, not the
blocklist itself. The backlog drain is therefore reproducible and does not rely
on bulk-closing issues.

The same secret-free incident command runs after both committed queue claims
and committed scan publications. A legacy-only drain therefore still updates
issues when it produces tombstones but no child scans. Terminal updates are
resumable: an issue is considered complete only when it is both labeled
`scanner-unscannable` and closed.

## Rollout and Safety

The change follows the merged weekly-cooldown pull request with one focused
terminal-policy pull request. On merge, the next reconciliation run normalizes
legacy chronic queue entries, seeds unscannable tombstones, and reconciles their
issues. No live state file is rewritten by hand.

The rollout must prove:

- first failure receives exactly one immediate retry;
- second failure receives exactly a seven-day cooldown;
- third failure is terminal and cannot be automatically re-enrolled;
- SHA churn preserves an in-progress failure episode;
- protected add-back clears only the requested tombstone and permits a fresh
  queue entry;
- provider/shared/security failures remain holds and consume no target budget;
- existing chronic targets normalize without an additional scan;
- issue reconciliation distinguishes cooling, unscannable, recovered, and
  unrelated incidents; and
- the full repository check and workflow-policy validation pass.

## Alternatives Rejected

Keeping an `unscannable` flag on a queue entry was rejected because a terminal
target must actually be absent from scan selection. Using GitHub issues as a
blocklist was rejected because issues are mutable presentation state and are
not the canonical operations ledger. Continuing exponential retries was
rejected because it leaves the cost unbounded.

## Non-Goals

This change does not alter retries inside an individual model request, add
cross-workflow model checkpoints, change provider-hold recovery, or classify
new failure domains. Those can be evaluated independently without weakening
the repository-level cost ceiling defined here.
