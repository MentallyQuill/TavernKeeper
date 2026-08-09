# One-Time Popular and Latest-Release Coverage Design

## Goal

Add one bounded scan cohort to the new/updated-only automation: the union of
the current 20 most popular Tavernary repositories and the 20 repositories
with the most recent qualifying GitHub Releases. The cohort is created once,
is deduplicated to at most 40 repositories, and never becomes a recurring
catalog eligibility rule.

Every selected repository remains subject to the rolling 48-hour completed
scan limit. The catalog-wide emergency stop stays active while the cohort is
created and inspected.

## Approaches considered

### Reuse the policy-rescan campaign

This is the smallest code change, but policy campaigns deliberately bypass
the automatic rescan deadline and currently select the whole catalog. Reusing
that authority would violate both the bounded scope and the 48-hour rule.

### Issue protected staff requests for every selected repository

This uses existing queue transitions, but staff requests also bypass the
automatic rescan deadline and do not provide one durable cohort identity.

### Add a cooldown-aware coverage campaign

This is the selected approach. A distinct campaign records the selected
repositories, provides durable one-time eligibility, completes from reports
published after the campaign was created, and never grants staff or policy
cooldown bypass.

## Selection

The one-time campaign has a fixed identifier so dispatching its protected
workflow again is idempotent and cannot create another cohort.

The popularity half requires Tavernary target manifest V3 and selects the 20
lowest `catalog_priority.popularity_rank` values. The latest-release half
queries GitHub's latest-release endpoint for every manifest repository using
the workflow's ordinary read token. A qualifying result is GitHub's latest
published release, which excludes drafts and prereleases. Repositories with
no qualifying release do not enter this half. Results sort by `created_at`
descending, then repository ID ascending, and the first 20 are selected.

The two repository-ID lists, their sorted union, and a mutable sorted
`remaining_repository_ids` subset are committed in the campaign state.
Overlap reduces the final count below 40. Selection is atomic:
a `404` means that repository has no qualifying release, while authentication,
rate-limit, transport, malformed-response, or other GitHub API failures abort
without changing state. Release lookups use bounded concurrency.

## State and queue behavior

Schema-3 state gains an optional/default-empty `coverage_campaigns` array. A
campaign contains its fixed ID, scanner policy version, creation timestamp,
status, the sorted popular IDs, the sorted latest-release IDs, their sorted
union, and the remaining subset. Schema validation proves the component lists
are unique, contain no more than 20 entries each, exactly produce the union,
and contain every remaining ID.

An active campaign makes only its selected current manifest targets eligible.
Reconciliation adds ordinary queue tickets without `staff_requested` or
`catalog_change`. If a preferred report exists, the entry receives
`rescan_not_before = completed_at + 48 hours` even when that report covers the
same SHA. With no report, the target is immediately runnable. Target failure
backoff remains authoritative through the existing retry path.

A selected repository is complete when the preferred index contains a report
for its current manifest SHA and campaign scanner policy version whose
`completed_at` is at or after the campaign `created_at`. Reconciliation removes
completed or no-longer-manifest members from `remaining_repository_ids` while
preserving the original selection lists for audit. The campaign becomes
`completed` when no selected repository remains. A completed campaign never
becomes active again and the fixed identifier prevents a second campaign from
being created.

Batch planning reports campaign targets with reason `coverage`. Coverage work
does not receive staff priority and does not bypass either rescan or failure
deadlines.

## Protected GitHub workflow

A manual, environment-protected GitHub Actions workflow performs the one-time
selection. It checks out trusted `main`, installs locked dependencies, queries
only Tavernary's public manifest, the committed report index, and GitHub's API,
then writes and commits the campaign through the existing publisher-app path.
It dispatches reconciliation only after the state push succeeds.

The workflow has no schedule and its fixed campaign ID makes repeated manual
dispatches no-ops. No external server, database, queue, or credential store is
introduced.

## Cutover sequence

1. Merge the incremental-only queue and one-time coverage implementation.
2. While `CATALOG_WIDE_RESCAN_BLOCKED` remains active, run reconciliation to
   establish and verify the catalog observation baseline.
3. Run the protected one-time coverage workflow while still stopped.
4. Verify the committed component lists, deduplicated union, campaign ID,
   per-entry deadlines, and absence of ordinary legacy entries.
5. Re-run stopped reconciliation and require a stable queue and zero planned
   targets.
6. Resume through the protected staff operation and inspect the first plan;
   it may contain only authentic catalog deltas, retained retries, and due
   members of this fixed coverage campaign.

## Tests

Contract tests reject oversized, duplicate, unsorted, or inconsistent
campaign lists. Reconciliation tests cover no-report immediacy, same-SHA and
changed-SHA 48-hour deadlines, completion, removal, retries, and the absence
of cooldown bypass. Selection tests cover popularity ordering, release-date
ordering, overlap, fewer than 20 releases, idempotency, `404`, and atomic
failure. Workflow-policy tests prove environment protection, least privilege,
pinned actions, trusted-main checkout, publisher-only state writes, and no
schedule trigger.
