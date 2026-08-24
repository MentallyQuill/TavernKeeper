# Durable Report Freshness Recovery Design

## Status

Approved for implementation and live recovery on 2026-08-23.

## Goal

Make TavernKeeper converge every current Tavernary target to one preferred report
for the exact current target SHA, scanner policy, and contextual-review policy.
Preserve the existing two-slot scheduler, retry backoff, immutable report history,
security boundaries, and model-cost limits.

This design replaces the earlier new-and-updated-only eligibility rule. Priority
becomes protected staff and policy work first, then newly submitted projects,
newly updated projects, frozen coverage work, and finally every other target that
lacks the exact current report tuple.

## Root Cause

Report identity was split across incompatible scopes:

- reconciliation and targeted scans calculated `report_version` and
  `supersedes_report_id` only from reports with the same target SHA and scanner
  policy; but
- publication selected a preferred report by the highest report version across
  the whole repository.

Changing a target or policy therefore restarted generation at version 1 while an
older repository report remained preferred at version 3. Scheduled reconciliation
continued to see the current tuple as missing and generated more immutable version
1 reports. The live Aventuras history contains more than one thousand examples of
that loop.

Queue admission compounded the problem. Backlog classification understood the
exact SHA/scanner/context tuple, but queue synchronization admitted only explicit
campaigns, staff work, catalog changes, and target-SHA mismatches. Missing reports
and same-SHA policy drift could disappear from the durable queue instead of
converging.

## Selected Architecture

### Repository-global report lineage

Report versions and supersession form one monotonic chain per provider and
repository ID. A request always derives its lineage from the current preferred
repository report, regardless of target SHA or policy:

- no preferred report: version 1 and no predecessor;
- preferred version `N`: version `N + 1`, superseding that preferred report ID.

Reconciliation and targeted scans use one shared pure lineage helper. Historical
target SHAs remain bounded metadata and do not participate in version selection.

The publisher enforces the same invariant before creating an immutable path. It
rejects a first report that is not version 1, or a later report that does not
advance exactly one version and supersede the current preferred report. A stale
concurrent result therefore fails closed instead of adding another invisible
report or regressing the preferred index.

### Exact-tuple continuous eligibility

A manifest target is current only when its preferred report matches all three:

1. current target SHA;
2. current scanner policy version; and
3. current contextual-review policy version.

Queue synchronization admits every target without that exact tuple. Catalog
observation still supplies durable `new` and `updated` provenance, so those lanes
retain their higher priority. An unchanged legacy or policy-stale target enters
the ordinary tail without pretending to be a new submission. Existing reason
contracts remain unchanged; ordinary freshness work uses the existing `changed`
request reason.

Successful publication updates the preferred index and removes that queue entry.
The next reconciliation sees the exact tuple and does not re-add it. Retries,
staff flags, policy campaigns, catalog provenance, tickets, and active leases
remain durable.

### Bounded recovery

The current emergency stop remains in place while the code is merged. Recovery
uses the existing policy-canary gate:

1. convert the stop to `POLICY_V5_CANARY_GATE`;
2. place one known looped repository at staff priority;
3. run reconciliation and allow only that staff canary through;
4. verify its report advances the repository-global version, supersedes the
   former preferred report, becomes preferred, and does not re-enter the queue;
5. clear the stop and let the existing two global slots drain the exact-tuple
   backlog in priority order.

The existing chronic-incident reconciler closes issues whose exact target is no
longer a chronic queued failure and keeps genuine target-local failures open.
Recovery does not weaken symlink rejection, scanner requirements, contextual
review coverage, token/call budgets, or sanitized diagnostics merely to make an
issue disappear.

## Approaches Rejected

### Prefer the newest completion time

This would make the latest policy report visible, but an older concurrent scan
could later win by wall-clock order. It would not repair the broken lineage
contract and would make replay behavior nondeterministic.

### Prefer the current policy regardless of version

Teaching the publisher about a mutable "current" policy would couple immutable
publication to deployment configuration and still leave target-SHA races. Policy
changes would be special cases instead of ordinary lineage advances.

### Search every history during reconciliation

History could reconstruct the maximum repository version, but the preferred
index is already the authoritative one-entry-per-repository projection. Reading
hundreds of history files on every scheduled wake would add cost and another
source of truth. Publisher validation prevents future divergence at the boundary.

### Drop or weaken target failures

`UNSAFE_LINK`, scanner failures, preparation failures, and model-budget failures
are not one interchangeable platform error. They remain fail-closed and continue
through bounded retry and incident handling. Only independently reproduced
platform defects warrant code or policy changes.

## Verification

Regression tests prove repository-global lineage across target and policy changes,
publisher rejection before immutable writes, exact-tuple admission for missing
reports and both policy dimensions, exact-current pruning, and preserved lane
ordering. Release verification runs the focused tests, full repository check,
build, E2E suite, workflow policy, diff review, hosted CI, the stopped live
canary, report/index/history inspection, and bounded resume observation.
