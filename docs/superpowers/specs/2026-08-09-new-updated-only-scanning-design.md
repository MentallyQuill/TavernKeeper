# New and Updated Projects Only Scanning Design

## Goal

TavernKeeper automatically scans only:

1. a GitHub repository newly added to Tavernary after the incremental baseline;
2. a previously observed GitHub repository whose target SHA changes; or
3. one repository or policy campaign deliberately requested through a protected staff workflow.

Ordinary legacy catalog entries without a report are baseline state, not pending work. Automatic changed-SHA scans remain limited to one completed scan per repository in a rolling 48-hour interval.

## Root cause

Queue synchronization currently considers a target eligible whenever the report index does not contain the current target SHA under the current scanner policy. That definition conflates three different states:

- a new submission;
- an updated repository; and
- a legacy catalog repository that has never been scanned.

Resuming the queue therefore seeded every remaining legacy repository. The 48-hour guard only applies when a prior report exists, so it cannot bound the initial legacy sweep.

## Selected architecture

Operations state gains a persisted catalog observation containing the current repository ID and target SHA for every manifest entry. The observation is initialized from the current manifest while scanning is stopped. Initialization establishes a hard baseline: it creates no automatic first-scan work and discards every pre-baseline queue entry unless the target is independently eligible as a changed-SHA repository or belongs to an active explicit policy campaign. A pre-baseline staff flag is not retained; an operator can issue a fresh single-project request after cutover if it is still wanted.

Every later synchronization compares the live manifest with the persisted observation:

- an absent repository ID is a new project;
- a known repository ID with a different SHA is an updated project;
- an unchanged repository is not automatic work;
- a repository removed from the manifest is removed from the observation and queue because it is no longer an authoritative scan target;
- a same-SHA scanner-policy change is not automatic work.

An automatically queued new or updated target carries durable `catalog_change` provenance. This distinguishes legitimate incremental work from the 359 unmarked legacy queue entries and allows new/updated work to survive subsequent synchronizations and target-local retries. Staff requests created after baseline initialization and active policy campaigns retain their existing explicit provenance.

The catalog observation and queue update are serialized in the same `operations/state.json` commit, so an observation cannot advance without its corresponding queue entry.

## Eligibility and timing

Automatic work is eligible only when at least one condition is true:

- the target has durable `catalog_change` provenance;
- the preferred report targets a different SHA;
- the target belongs to an active protected policy campaign; or
- the queue entry is an explicit protected staff request created after baseline initialization.

New projects have no prior completed report and run immediately. Updated projects with a prior report receive `rescan_not_before = completed_at + 48 hours`. Further SHA changes replace the queued target without moving that deadline. Target-local failure retry timing remains separate and retains the existing bounded backoff.

## Targeted and staff paths

Tavernary's protected targeted workflow remains an explicit operator path and may request one repository. It does not create catalog-wide eligibility. Protected staff policy campaigns remain possible but are never created by ordinary synchronization.

The emergency stop remains active throughout implementation and migration. After deployment, one stopped reconciliation initializes the catalog observation and prunes unmarked legacy work. The system resumes only after live state proves that no legacy backlog remains and any retained automatic entries correspond to new IDs or changed SHAs.

## Failure handling

- Invalid, duplicate, or unsorted catalog observations fail schema validation.
- Observation initialization or comparison failure leaves the emergency stop and committed state unchanged.
- A changed target whose previous report timestamp is invalid fails closed during synchronization.
- A retry retains its catalog-change provenance, target identity, ticket rotation, and failure history.
- Provider or scanner failures remain target-local and cannot recreate catalog-wide eligibility.

## Testing

Regression tests must prove:

- first incremental synchronization snapshots the manifest and removes unmarked legacy queue entries without seeding them;
- baseline initialization also removes pre-baseline staff entries while retaining independently changed-SHA work;
- a repository added after the snapshot is queued once;
- an unreported legacy repository is queued when its observed SHA changes;
- an unchanged repository without a report remains unqueued;
- same-SHA scanner-policy drift remains unqueued without an explicit campaign;
- changed-SHA work with a prior report retains the 48-hour boundary;
- repeated SHA changes preserve the original cooldown and ticket;
- retries preserve catalog-change provenance;
- staff requests and policy campaigns remain explicit exceptions;
- serialization is deterministic and schema validation rejects ambiguous observation state.

The release gate includes the full repository check, hosted CI, a stopped live migration, exact state inspection, one no-op stopped reconcile, and then a controlled resume. Live proof must show no legacy backlog dispatch and no more than the expected new/updated targets selected.
