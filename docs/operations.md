# TavernKeeper Operations

All privileged workflows run from trusted TavernKeeper code. Keep `main`
protected, use `tavernkeeper-scanner` for unattended scans, and use
`tavernkeeper-staff` only to control privileged operations. A complete
production result never waits for human approval. The automation boundary is
normative in [`development-rules.md`](development-rules.md).

## Runtime configuration

Configure these secrets in `tavernkeeper-scanner`:

- `TAVERNKEEPER_ARTIFACT_KEY`: canonical base64 encoding of exactly 32 random
  bytes, used only for the authenticated matrix-to-publisher handoff.
- `TAVERNKEEPER_API_ENDPOINT`: the configured provider's complete
  OpenAI-compatible chat-completions endpoint.
- `TAVERNKEEPER_API_KEY`: provider credential sent as an
  `Authorization: Bearer` header.
- `TAVERNKEEPER_MODEL`: provider model identifier. Model selection is runtime
  configuration and is not hardcoded into scan policy.

Provider credentials are exposed only to the fresh contextual-review job and
the protected provider compatibility check. They are absent from acquisition,
scanners, the secret-free prepared artifact, finalization, publication, and
telemetry. A model change
must pass `provider-check.yml` against the complete contextual response schema
before production scanning resumes. TavernKeeper requests strict
OpenAI-compatible `json_schema` structured output using that response schema,
then independently validates the exact local schema, evidence identity, and
complete candidate coverage. A provider that explicitly rejects JSON Schema
with HTTP 400 or 422 receives one compatibility retry in `json_object` mode;
authentication, quota, and other provider failures never trigger that retry.
Do not add automatic model fallback.

The credential-free prepare job first uploads one bounded
`prepared-${repository_id}` artifact for one day. It contains only validated
scanner metadata, coverage, provenance digests, and redacted evidence windows;
it receives no repository secret. A fresh review job validates that artifact
without a target checkout. The shared workflow then encrypts the sanitized
candidate and transition envelope with AES-256-GCM before upload, removes the plaintext handoff, retains the
ciphertext artifact for one day, and decrypts it only in the serialized
publisher job. Generate the artifact key with a cryptographically secure random
source. Never reuse an App key.

Configure `TAVERNARY_WAKE_APP_ID` and `TAVERNARY_WAKE_APP_PRIVATE_KEY` only in
TavernKeeper. The App is installed only on Tavernary with Actions write and
metadata read. Tavernary stores the inverse TavernKeeper wake App credentials;
they are not TavernKeeper secrets.

Configure these environment secrets separately in both
`tavernkeeper-scanner` and `tavernkeeper-staff`:

- `TAVERNKEEPER_PUBLISHER_APP_ID`
- `TAVERNKEEPER_PUBLISHER_APP_PRIVATE_KEY`

`TavernKeeper Publisher` is installed only on TavernKeeper with contents
read/write and metadata read. It has no Actions permission. Mutation jobs mint
a short-lived token scoped to `MentallyQuill/TavernKeeper`, disable persisted
checkout credentials, and fail if authentication or push fails. There is no
contents-write fallback.

Do not put secret values in workflow inputs, repository files, Issues, logs,
reports, artifacts, telemetry, or shell history. Treat GitHub App installation
tokens as opaque variable-length strings: never parse, length-check, cache, or
persist them.

## Normal reconciliation

`reconcile.yml` runs every six hours and accepts input-free workflow and
repository dispatches. `retry.yml` also reconciles every five minutes so due
recovery work does not wait for the safety-net schedule. Reconciliation first
synchronizes Tavernary's live V2 or V3 target manifest and TavernKeeper's V5
preferred current reports into committed schema-3 queue state. It then selects
at most five due tickets and calls `scan-and-publish.yml`, which runs at most two
credential-free prepare jobs and two fresh review jobs concurrently. Standard,
retry, targeted, and policy-campaign scans
converge on the same automatic V5 publication path. Committed queue work starts
the next input-free batch independently of Pages deployment.

The first incremental synchronization snapshots the current Tavernary manifest
without treating unreported legacy repositories as work. Later manifest deltas
enqueue a newly observed repository ID or a changed observed SHA. A changed SHA
with a preferred report remains delayed until 48 hours after that report's
completion. Scanner-policy changes require an explicit protected campaign.

The queue is a durable monotonic ticket ledger reconciled against current
eligibility. A target that advances before acquisition keeps its ticket while
its queued identity moves to the newest manifest SHA. Once exact-SHA
acquisition begins, TavernKeeper
completes and publishes that immutable SHA even if the catalog advances.
Tavernary keeps the assessment and marks freshness separately. A staff request
created after a prior completed report is appended as an intentional forced
rescan, and a same-SHA replacement may become preferred without erasing
history.

Changed-SHA automatic rescans enter the durable queue immediately, but cannot
run until 48 hours after the latest completed report. Further pushes replace the
queued SHA without moving that deadline. The cooldown does not apply to initial
scans, staff-targeted scans, retry entries with a failure streak, or active
policy-campaign scans.

### One-time top and latest-release coverage

`coverage-campaign.yml` is a protected, input-free, one-time operation. It takes
one atomic manifest snapshot, selects the repositories currently ranked 1
through 20 by Tavernary popularity plus the 20 repositories with the newest
qualifying GitHub releases, and commits their deduplicated current repository
IDs as a fixed campaign. Overlap between those lists can make the cohort smaller
than 40. The fixed campaign ID makes a repeated workflow dispatch an idempotent
no-op rather than a second campaign.

This operation is not a recurring schedule and does not rescan the catalog. It
only makes the selected current targets eligible for the ordinary durable queue.
Every member retains normal exact-SHA, retry, concurrency, and 48-hour rescan
rules; selection never grants staff or policy-campaign cooldown authority.

Ticket allocation is the fairness guarantee among new, updated, retry, and
explicit staff work; the legacy catalog is not automatically ticketed. Any
failure removes that target from its old position and assigns it the next tail
ticket behind every project currently assigned to be scanned. Later catalog
deltas receive higher tickets, so they cannot repeatedly push an older failure
backward. Targeted rescans use durable tickets and are marked as staff
requested. Once due, staff requests are selected before ordinary due tickets
so an approved investigation does not wait behind automatic work. Priority
never bypasses an emergency stop, automatic hold, retry cooldown,
exact-SHA validation, batch size, or concurrency limit.

## Scan lifecycle

For every exact target, TavernKeeper:

1. acquires and inventories the repository without executing target code;
2. runs all required deterministic scanners, including policy-4 raw, decoded,
   normalized, and bundle-module JavaScript analysis;
3. validates and groups every candidate with bounded evidence context;
4. revalidates exact HEAD, deletes the target checkout, and validates a bounded
   secret-free GitHub artifact on a fresh runner;
5. asks the configured model to assess every finding candidate under the versioned
   ecosystem prompt and strict response schema;
6. rejects missing context, invented citations, invalid structured output,
   provider errors, and hard scanner or evidence-integrity failures;
7. publishes bounded unresolved JavaScript coverage as `incomplete`, without
   changing advisory color or concern counts;
8. constructs the complete Technical Report V5;
9. transports the sanitized candidate through authenticated encryption; and
10. atomically publishes immutable JSON/HTML, history, and the preferred index
    for every complete successful outcome in the batch.

The model may classify candidate evidence as expected behavior, a minor
weakness, a material vulnerability, or credible malicious behavior. It does
not assign Tavernary's final project color. Tavernary performs a separate
strict synthesis and enforces deterministic project risk after import. High is
reserved for high-confidence credible malicious or compromised behavior, or a
high-confidence critical vulnerability that is readily exploitable in the
shipped project. A critical advisory with only plausible runtime exploitation
remains material.

## Durable recovery

Operations state schema V3 records one queue entry per repository. Never edit
state concurrently with publication.

- Every failed project rotates to the current tail and receives a cooldown of 5
  minutes, 30 minutes, 2 hours, then 6 hours capped for every later attempt.
- The fifth consecutive failure marks the entry `chronic` and creates or
  updates a sanitized staff Issue. It is diagnostic, not terminal; the ticket
  remains scheduled forever until a success or a newer eligible SHA resets the
  streak. The Issue is keyed by repository ID plus exact SHA, independent of
  the latest failure class, and closes when that exact target is no longer
  chronic.
- Each entry retains only its latest four sanitized failure descriptors and
  fingerprints. This makes alternating parser, timeout, evidence, and model
  failures visible without retaining raw stderr, repository paths, source
  excerpts, provider responses, or rejected prose.
- Target-local failure domains remain isolated to their project. Shared and
  security failures create a fingerprinted automatic circuit so a broken
  provider, credential, toolchain, or integrity boundary is probed once instead
  of being hammered by the full catalog. The probe delay is 5 minutes, 30
  minutes, 2 hours, then 6 hours capped. A due circuit admits exactly one
  lowest-ticket target. A matching successful probe clears only that circuit
  and normal ticket order resumes immediately. No circuit exhausts or requires
  a staff resume; its fifth failure is chronic diagnostic state only.
- Unknown system failures default to the shared circuit. Only explicitly
  recognized authentication, configuration, identity, response-origin, and
  policy-integrity failures use the security domain.
- Only a deliberate `pause` through the protected staff workflow creates an
  emergency stop. Common runtime failures cannot invoke it.

Every selected matrix target still finishes independently. The serialized
publisher retains complete reports from peer repositories and applies all queue
transitions in request order. Ordinary continuation uses only persisted queue
work and does not wait for deployment. `pages-reconcile.yml` independently
checks the committed main SHA against the deployed source marker every fifteen minutes and
repairs drift. External project owners receive no operational-failure
notification.

Provider exhaustion, context insufficiency, invalid model output, and missing
review coverage are failures, never permission to skip finding candidates,
reduce the policy, switch models automatically, or infer a low result. A
bounded deterministic JavaScript parser or transform limitation is different:
it is published as explicit incomplete coverage and remains visible without
changing advisory color or concern counts. See [`SCANNING.md`](SCANNING.md).

Each contextual-review attempt has a 20-minute process timeout in addition to
the model client's request policy, and the retrying review job is bounded at 62
minutes. These guards cover a provider that returns headers but never closes
its response stream. A timed-out step still reaches the always-run sanitized
transition, encrypted publication, queue rotation, and continuation path; it
cannot retain the global scan concurrency slot indefinitely.

OpenGrep policy 4 treats only warning-level code 2 `Other syntax error` and
warning-level code 3 `PartialParsing` tuple diagnostics as bounded parser
limitations. Valid findings remain eligible for contextual review when those
warnings occur. Unknown warnings, error-level diagnostics, malformed output,
nonzero exits, and process failures remain target-local scanner failures unless
the pinned tool itself is unavailable, which is a shared transient failure.
Rejected OpenGrep diagnostics are categorized as `parser_syntax` or
`rule_timeout` when possible; paths and raw diagnostic text are not persisted.
A scanner finding on a non-text artifact retains its verified size, digest, and
scanner metadata without exposing raw binary to the model. The report publishes
`completed-with-limitations` contextual coverage and cannot appear low solely
because the model could not inspect the raw contents.

Invalid contextual-model responses receive one corrective prompt that names
only the rejected schema field category. If the next response fails in the
same category, TavernKeeper stops the immediate loop and rotates the target;
it never copies the rejected response back into a prompt or queue state.

Any change to scanner behavior or output requires a clean canary baseline.
Before reactivation, remove the existing Wandlight and Recursion report trees
and preferred-index entries, prove Tavernary has imported the empty state, and
then scan each canary once under the new policy. Do not reset other repository
history as part of this release gate.

Batch scheduling, retention, or deployment-routing changes that do not alter
scanner behavior or report output do not trigger the Wandlight and Recursion
reset gate.

## Staff workflows

- `provider-check.yml` makes one benign, bounded review request and validates
  the configured endpoint, Bearer authentication, model, and response contract.
- `targeted-scan.yml` accepts only a repository-ID hint from the immutable
  Tavernary wake-App actor, refetches the public V2 or V3 manifest, synchronizes
  the current queue, commits the targeted tail ticket, and dispatches ordinary
  reconciliation. Staff begin this flow through Tavernary's exact-GitHub-URL
  Action.
- `policy-rescan.yml` schedules a campaign under the current reviewed policy.
- `coverage-campaign.yml` creates the fixed one-time top-20 and latest-release
  cohort, commits it once, and dispatches ordinary reconciliation.
- `staff-operations.yml` sets or clears the explicit emergency stop, makes one
  target immediately due, or performs a protected legacy-to-V3 state migration.
- `deploy-pages.yml` deploys only an exact commit proven to be on `main`;
  manual runs require staff protection.
- `pages-reconcile.yml` automatically repairs a missing or stale Pages
  deployment without participating in scan continuation.

Public Issues and comments do not trigger these workflows. A false-positive
appeal cannot change an individual report. If evidence exposes a scanner,
prompt, or assessment-policy defect, staff change global versioned policy
through ordinary code review and TavernKeeper automatically rescans affected
targets.

No production candidate waits for review, dismissal, or recoloring. Context,
model, schema, evidence, sanitizer, tool-integrity, or hard scanner failure
publishes nothing and enters the classified retry path. Bounded policy-4
JavaScript and metadata-only contextual coverage limitations publish visibly
without changing advisory color or concern counts.
Complete high/immediate-danger reports are published through the same path as
all other results. They remain visible in TavernKeeper and Tavernary and never
automatically hide, quarantine, downrank, or delist a project.

## Release checks

Before deployment, run:

```text
npm run check
npm run test:e2e
npm run build
npm run scanners:verify
npm run scanners:smoke
actionlint .github/workflows/*.yml
```

Run `provider-check.yml` after configuring or changing the endpoint, key, or
model. Confirm hostile fixture markers, raw model output, hidden reasoning, and
credentials do not appear in reports or site output; the public report-index
digest equals the deployed source digest; contextual review covers every
candidate; and Tavernary imports only matching repository IDs and SHAs.

`npm run test:e2e` uses controlled doubles for Git history, external binary
adapters, model transport, and exact-HEAD verification while exercising the
real non-executing JavaScript derivative engine over inert hostile canaries.
`npm run scanners:smoke` proves raw OpenGrep path closure plus real decoded and
bundle-module rescans with the pinned binary on Linux x64. Real provider
behavior and exact validated checkouts remain release and live-canary gates.

For the durable-queue rollout: publish and verify Tavernary's complete ranked
manifest; migrate to schema V3; confirm the automatic legacy stop became a
finite due probe, all eligible projects have unique increasing tickets, and
legacy retry targets remain represented. Verify the first selected repositories
follow ticket order, a fifth failure remains queued and chronic, later arrivals
receive larger tickets than an already-rotated failure, shared/security recovery
probes happen without staff action, scanning continues while Pages is
reconciled independently, and no common failure path can create an emergency
stop. Migration itself never dispatches scanning.
