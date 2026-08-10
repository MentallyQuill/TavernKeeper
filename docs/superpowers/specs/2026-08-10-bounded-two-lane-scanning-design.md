# Bounded Two-Lane Catalog Scanning Design

## Goal

Return TavernKeeper to bounded automatic catalog scanning while keeping policy-v4
reports current where they matter most. Automatic eligibility is limited to new
submissions, newly updated projects, and one freshly selected, immutable 20+20
coverage cohort. At most two repositories are scanned at once, and every
repository publishes independently as soon as its own scan finishes.

The cutover must remove the catalog-wide version backlog without losing valid
new/updated work, explicit staff requests, or retry history for work that remains
eligible. It must not change the scanner suite, contextual-review policy, or the
strict review-cache identity rules.

## Approaches Considered

### Two-target batches

Restoring `max-parallel: 2` and shrinking batches to two is the smallest workflow
change. A fast scan would still wait for the slow scan before either result could
publish, and the free model slot would remain idle until the pair completed.

### Matrix scans with detached publisher workflows

Each matrix leg could dispatch another workflow that downloads its encrypted
artifact and publishes it. That meets the publication requirement but introduces
cross-run artifact lookup, dispatch authentication, and orphan cleanup that the
current trusted handoff does not need.

### Durable claims with single-target reusable workflows

This is the selected approach. Reconciliation atomically claims available queue
entries up to a global capacity of two. Each claim invokes the existing reusable
pipeline with one request, so its prepare, model review, publication, and Pages
deployment are independent. Completion clears one durable claim and immediately
dispatches reconciliation to refill the open slot.

## Eligibility and Priority

Reconciliation uses Tavernary's current target manifest, TavernKeeper's preferred
report index, the catalog observation cursor, and the committed campaign state.
An exact current target is automatically eligible only when at least one of these
conditions holds:

1. it is an explicit staff request;
2. it belongs to an active policy campaign;
3. it is a new catalog submission since the observation cursor;
4. its catalog SHA changed since the observation cursor; or
5. it remains in the active one-time coverage campaign.

An ordinary missing policy-version tuple is no longer sufficient. Reconciliation
removes version-only entries left by the catalog-wide catch-up, including their
ineligible retry state. It retains failure history, deadlines, and tickets for
entries that remain eligible.

Runnable ordering is staff/policy control first, then new submissions, updated
projects, and coverage work. Target-local failures keep the existing retry
rotation and cooldown behavior within their eligibility class. Shared provider
holds and the explicit staff emergency stop remain authoritative.

## Fresh One-Time 20+20 Campaign

The cutover creates a new fixed campaign identity so the earlier completed or
retired campaign cannot suppress this requested recalculation. Selection requires
manifest schema 3 and takes:

- the 20 lowest published popularity ranks; and
- the 20 most recently created qualifying stable GitHub Releases.

Drafts, prereleases, and repositories without a qualifying release do not enter
the release half. The union is deduplicated and frozen at no more than 40
repositories. The two component lists, union, creation time, and remaining list
are committed for audit. Selection is atomic: a release `404` is an ordinary
absence, while authentication, rate-limit, transport, oversized-response, or
malformed-response failures abort without changing state.

Coverage work observes the existing 48-hour automatic rescan deadline. A current
report completed after campaign creation completes that member; the campaign
becomes permanently completed when its remaining list is empty. It is never
recalculated by schedules or ordinary reconciliation.

## Durable Two-Slot Claims

The existing `active_scans` state becomes the scheduling lease ledger. During a
single deterministic state transition, reconciliation:

1. synchronizes eligibility and the catalog observation;
2. expires claims older than two hours;
3. computes `capacity = 2 - active_scans.length`;
4. selects at most that many due targets in priority order; and
5. records each selected exact target with its start time and claim identifier.

The claim state is committed before any reusable scan workflow starts. Concurrent
reconcilers use optimistic fetch/reapply/push retries, so a losing writer replans
against the winning state instead of dispatching duplicates. Preparation and scan
jobs receive explicit timeouts below the two-hour lease lifetime. A five-minute
scheduled reconciler already supplies bounded stale-lease recovery after a
canceled or infrastructure-failed workflow.

The two-slot limit is derived only from committed active claims. It therefore
applies across overlapping workflow runs, manual triggers, schedules, and
continuations rather than merely within one Actions matrix.

## Per-Target Publication

`scan-and-publish.yml` accepts exactly one validated request. Its preparation and
review stages continue to pass only bounded prepared evidence and encrypted
sanitized outcomes across the secret boundary. No publisher credential is added
to a model job.

The publisher decrypts one outcome, applies its report/queue transition, and
pushes immediately. On a non-fast-forward race it fetches current `main`, restores
the original encrypted outcome, reapplies the deterministic publication
transition, and retries. Thus parallel completions cannot overwrite reports,
queue updates, staff stops, or campaign progress.

Every successful report commit invokes Pages deployment immediately. Success or
recorded target failure clears that target's claim; if eligible queued work
remains, that child dispatches reconciliation without waiting for the other child.
A publication-boundary failure leaves the claim for bounded lease recovery and
raises the existing sanitized operational incident.

## Scanner and Review Guarantees

Every claimed target still runs the complete deterministic suite: repository
preparation, OpenGrep, dependency advisories, secrets checks, package/script
inspection, JS-X-Ray, webcrack, and the current contextual aggregation path. This
change neither replaces scanners with X-Ray nor suppresses their findings.

Review-cache reuse remains limited to content-identical low-risk,
`not_demonstrated` groups with matching candidate IDs, evidence, tool versions,
policy, prompt, schema, provider endpoint, and model. All deterministic scanners
rerun on every target. Material, demonstrated, changed, malformed, or stale cache
entries require fresh model review.

## Cutover

The catalog-wide drain is first placed under a staff emergency stop and its old
in-flight workflows are canceled. After the implementation merges:

1. run stopped reconciliation and prove version-only backlog entries are removed;
2. execute the protected one-time coverage selector and inspect its two component
   lists and deduplicated union;
3. verify no claims exist while the stop is active;
4. resume through the protected staff operation; and
5. verify exactly two single-target pipelines start, then verify the first
   completed target commits and deploys before its peer finishes.

## Verification

Tests cover campaign contracts and selection, bounded eligibility, priority,
catalog-wide backlog pruning, cooldowns, claim capacity, overlapping reconcile
races, stale-claim recovery, per-target workflow shape, secret separation,
publication push replay, continuation, and full scanner preservation. The final
gate is `npm.cmd run check`, `npm.cmd run build`, and the hostile-fixture E2E suite,
followed by hosted CI and live Actions/report-index verification.
