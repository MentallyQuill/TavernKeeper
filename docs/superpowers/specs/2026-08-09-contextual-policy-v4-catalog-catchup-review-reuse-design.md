# Contextual Policy V4, Catalog Catch-up, and Review Reuse Design

**Date:** 2026-08-09

## Goal

Calibrate TavernKeeper to the actual SillyTavern community threat model, scan
every catalog project whose preferred report is not current, and stop paying a
contextual-review model to repeat a low-risk judgment when the meaningful
review evidence has not changed.

The release has three independently testable parts:

1. contextual-review policy 4 defines the user-harm threshold;
2. ordinary reconciliation schedules every out-of-version catalog target in
   new, updated, then remaining-catalog order; and
3. a content-addressed review cache reuses only validated low-risk evidence
   units under the exact current policy and reviewer identity.

The first catalog pass under contextual policy 4 is deliberately cold. It
creates the only baseline eligible for later reuse.

## Contextual threat model

TavernKeeper reviews community extensions, frontends, and presets used with a
single-user roleplay client/server. It is not applying a high-assurance or
national-security risk threshold.

Recoverable degradation confined to the user's own current client or session
is low impact. This includes a slow response, elevated local CPU or memory,
a frozen tab or window, a crash, a restart, and loss of unsaved generated
content. Deliberately triggering one of those effects does not by itself make
the project yellow.

Yellow requires high-confidence, demonstrated, plausibly exploitable harm of
the sort a user should actually treat as a security caution. Qualifying harm
includes credential theft, private-content exfiltration, destructive or
persistent loss/corruption of meaningful saved data, unauthorized persistence,
arbitrary code execution, escape beyond the project boundary, cross-user or
system harm, or comparable concrete loss.

Red remains limited to high-confidence demonstrated malicious/compromised
behavior or a critical, readily exploitable vulnerability. Scanner severity,
dependency advisory severity, incomplete coverage, and uncertainty cannot
raise the public color.

Contextual policy advances from 3 to 4 and prompt version advances from v6 to
v7. The assessment object remains `contextual-assessment-v2`; no field-shape
change is needed. Historical reports remain immutable and parseable.

## Catalog eligibility and priority

A current report matches all of the following:

- the manifest's exact target SHA;
- the current scanner policy version; and
- contextual-review policy version 4.

Every manifest repository without that complete tuple is ordinary eligible
work. Catalog observation remains solely to distinguish a newly submitted
repository ID from an updated target SHA. Queue entries retain that provenance
after the observation advances.

Runnable automatic work is ordered:

1. `catalog_change: new`;
2. `catalog_change: updated`;
3. every other out-of-version catalog repository.

Protected staff authority remains higher than automatic work. Failure and
provider-hold deadlines remain authoritative within every class.

The first policy-4 catch-up bypasses the rolling 48-hour rescan delay whenever
the preferred report does not use the current scanner/contextual version tuple.
After a policy-4 report exists, an ordinary changed-SHA rescan again uses the
existing 48-hour deadline.

The one-time top-20 plus latest-20 coverage workflow and its queue eligibility
are retired. Reconciliation clears the legacy campaign collection. The schema
field remains as an empty backward-compatible tombstone until a future
operations-state schema migration.

## Differential contextual review

All deterministic scanners run fresh against every acquired exact SHA. Cache
reuse occurs only after scanner collection and evidence validation, and never
suppresses a scanner or candidate.

### Stable review identity

Each evidence group receives a `review_input_digest` over canonical meaningful
input:

- source and repository identity;
- project kinds, repository path, and file role;
- normalized candidate identities and scanner evidence;
- redacted source/import windows and every bounded expansion;
- representation stages and transform depths;
- stated project purpose and ecosystem context;
- scanner policy, scanner version, rule catalog, and pinned tool versions;
- contextual policy, prompt, and assessment-schema versions; and
- provider, endpoint origin, and exact model name.

Commit SHA, evidence SHA, group ID, raw file byte count, and full-file hashes
that are not shown to the reviewer are excluded. They remain independently
validated by the prepared-evidence contract. The prompt also omits those
volatile identifiers so equal review digests correspond to equal meaningful
model evidence.

### Durable cache

The publisher atomically maintains
`reports/github/<repository-id>/review-cache.json`. The cache is a bounded
manifest pointing to one immutable V5 report and mapping each review-input
digest to its candidate IDs and original report provenance. It contains no raw
source, scanner output, credentials, or duplicate model narrative.

The next review loads the referenced immutable report, validates its report
identity and policy/reviewer tuple, extracts the mapped assessments and
observations, and replays them through the existing authoritative evidence
coverage validator against the current group.

An entry is reusable only when every mapped assessment and observation has:

- `recommended_risk: low`;
- `risk_exposure: not_demonstrated`; and
- exact current candidate/evidence/location bindings after validation.

Any material/high/demonstrated result is always sent to the model again.
Malformed, missing, stale, mismatched, or unvalidated cache data is an ordinary
cache miss, never a low-risk conclusion and never a scan failure.

### Publication and audit

The completed candidate carries a sanitized cache manifest alongside the V5
report. Publication writes the immutable report, preferred index, history,
operations state, and replacement review cache in one rollback-safe operation.

New V5 reports contain optional `review_reuse` aggregate provenance with fresh
and reused group/candidate counts plus originating report IDs. Old V5 reports
remain valid without the field. Report identity covers the provenance.

## Failure and invalidation rules

Reuse becomes impossible when any meaningful input changes, including:

- contextual policy, prompt, schema, ecosystem context, provider, or model;
- scanner policy, rule catalog, scanner binary, or tool version;
- advisory/package identity or normalized scanner evidence;
- candidate membership, source/import/expansion context, file role, project
  kinds, or project purpose; or
- the referenced immutable report or cache manifest failing validation.

Provider/cache accounting is separate. Reused work contributes no model token
usage; provider-reported prompt-cache tokens continue to use
`review_usage.cache_read_tokens`.

## Release sequence

1. Land policy 4, full-catalog eligibility, priority, retired 20+20 behavior,
   and review-cache support together.
2. Keep every existing report immutable; do not seed reuse from policy 3.
3. Reconcile current catalog state. Clear the legacy coverage campaign and
   queue every target missing the current exact version tuple.
4. Prove queue ordering is new, updated, then remaining catalog, and prove the
   policy-4 catch-up has no 48-hour rescan deadline.
5. Run canary scans under policy 4, verify every scanner still executes, and
   verify cache counts are cold.
6. Continue the full catalog pass.
7. On a later authentic update with unchanged evidence, prove a cache hit,
   lower model usage, immutable-source provenance, and complete final coverage.

## Verification

Required automated proof includes:

- prompt fixtures for low-impact recoverable local degradation and the concrete
  yellow/red harm boundary;
- policy-4 report and index compatibility;
- all out-of-version targets becoming eligible;
- exact new, updated, rest priority;
- one-time version-catch-up cooldown bypass followed by normal 48-hour behavior;
- retirement and clearing of coverage campaigns;
- stable review digests across commit-only changes and invalidation for every
  meaningful input class;
- rejection of material/high/demonstrated or malformed cache entries;
- zero model calls for complete cache hits and model calls only for misses;
- progress-resume compatibility with mixed reused/fresh groups;
- atomic cache publication and rollback; and
- full TypeScript, Vitest, formatting, workflow-policy, schema-generation, and
  hosted CI gates.
