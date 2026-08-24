# TavernKeeper Operations

All privileged workflows run from trusted TavernKeeper code. Keep `main`
protected, use `tavernkeeper-scanner` for unattended scans, and use
`tavernkeeper-staff` only to control privileged operations. A complete
production result never waits for human approval. The automation boundary is
normative in [`development-rules.md`](development-rules.md).

## Runtime configuration

Configure these secrets in `tavernkeeper-scanner`:

- `TAVERNKEEPER_ARTIFACT_KEY`: canonical base64 encoding of exactly 32 random
  bytes, used only for the authenticated review-to-publisher handoff.
- `TAVERNKEEPER_API_ENDPOINT`: the configured provider's complete
  OpenAI-compatible chat-completions endpoint.
- `TAVERNKEEPER_API_KEY`: provider credential sent as an
  `Authorization: Bearer` header.
- `TAVERNKEEPER_MODEL`: provider model identifier. Model selection is runtime
  configuration and is not hardcoded into scan policy.
- `JSONREPAIR_API_ENDPOINT`: the OpenAI-compatible chat-completions endpoint
  used only to repair a final invalid DeepSeek binding response.
- `JSONREPAIR_API_KEY`: Bearer credential for the JSON repair endpoint.
- `JSONREPAIR_MODEL`: the GPT-5.6 Luna model identifier used only by the
  bounded repair protocol.

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
There is no automatic reviewer or summary-model fallback. After the configured
reviewer exhausts all immediate attempts, one parsed completed response may
receive one Luna JSON binding patch only for invalid assessment evidence IDs,
observation evidence IDs, or observation locations. The repair request contains
only failed hash bindings or locally proven invalid observation indices: it
contains no source, file paths, line numbers, scanner finding text, repository
identity, narratives, or project summary.
Luna cannot change a disposition, impact, exploitability, confidence, exposure,
risk, title, explanation, action, or candidate identity. The patched response
may only replace an assessment's evidence hashes or drop an optional observation
with invalid evidence or locations; it never relocates or rewrites an
observation. It must pass the ordinary authoritative evidence validator. Malformed or
semantically invalid responses, provider failures, and failed Luna patches keep
the original target-local failure.

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

Configure `TAVERNKEEPER_PUBLISHER_CLIENT_ID` as a non-secret environment
variable and `TAVERNKEEPER_PUBLISHER_APP_PRIVATE_KEY` as an environment secret
separately in both `tavernkeeper-scanner` and `tavernkeeper-staff`. Do not store
either value at repository scope.

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
recovery work does not wait for the safety-net schedule. One claim job
synchronizes Tavernary's live V2 or V3 target manifest and TavernKeeper's V5
preferred reports into committed schema-3 state, expires claims older than two
hours, and fills at most two globally available slots. Each claimed target calls
`scan-and-publish.yml` independently and publishes immediately after it
finishes. Standard, retry, targeted, coverage, and policy-campaign scans
converge on this same V5 publication path. A completed target dispatches fresh
reconciliation independently of Pages deployment.

Synchronization considers a target current only when its preferred report
matches the exact target SHA, scanner policy, and contextual-review policy.
Every missing exact tuple is admitted. Catalog observation still marks new and
updated work explicitly so it retains priority over the ordinary freshness tail;
the active frozen coverage campaign and protected staff or policy work keep
their existing authority.

The queue is a durable monotonic ticket ledger reconciled against current
eligibility. A target that advances before acquisition keeps its ticket while
its queued identity moves to the newest manifest SHA. Once exact-SHA
acquisition begins, TavernKeeper
completes and publishes that immutable SHA even if the catalog advances.
Tavernary keeps the assessment and marks freshness separately. A staff request
created after a prior completed report is appended as an intentional forced
rescan, and a same-SHA replacement may become preferred without erasing
history.

Changed-SHA automatic rescans and coverage rescans enter the durable queue
immediately, but cannot run until 48 hours after the latest completed report.
Further pushes replace the queued SHA without moving that deadline. Initial
scans, protected staff scans, retry deadlines, and active policy campaigns keep
their existing authority.

`coverage-campaign.yml` recalculates the current top 20 projects by popularity
plus latest 20 stable GitHub releases exactly once for campaign V2. It commits
the deduplicated membership, up to 40 repositories, so later catalog changes do
not move the campaign boundary.

Selection order is protected staff and policy work, new submissions, updated
projects, frozen coverage work, then all other missing or stale exact tuples. Any
failure removes that target from its old position and assigns it the next tail
ticket behind every project currently assigned to be scanned. Later catalog
deltas retain their priority class without bypassing an emergency stop,
automatic hold, retry cooldown, exact-SHA validation, claim capacity, or
concurrency limit.

## Scan lifecycle

For every exact target, TavernKeeper:

1. acquires and inventories the repository without executing target code;
2. runs all required deterministic scanners, including policy-5 raw, decoded,
   normalized, and bundle-module JavaScript analysis;
3. validates and groups every candidate with bounded evidence context;
4. revalidates exact HEAD, deletes the target checkout, and validates a bounded
   secret-free GitHub artifact on a fresh runner;
5. classifies execution scope and applies conservative deterministic triage,
   escalating unknown, ambiguous runtime, cross-boundary, and dangerous
   correlated behavior;
6. calculates the canonical review-input digest only for contextual groups and
   reuses exact, validated low-risk/not-demonstrated matches from the current
   repository cache;
7. packs contextual cache misses in source order into input- and output-token-bounded
   calls of at most five evidence groups and asks the configured model to
   assess each independently under the versioned ecosystem prompt and strict
   response schema;
8. rejects missing context, invented citations, invalid structured output,
   provider errors, and hard scanner or evidence-integrity failures;
9. publishes bounded unresolved JavaScript coverage as `incomplete`, without
   changing advisory color or concern counts;
10. constructs the complete Technical Report V5 with triage, budget, and
    fresh/reused provenance;
11. transports the sanitized report and replacement review-cache manifest
    through authenticated encryption; and
12. atomically publishes immutable JSON/HTML, history, the preferred index, and
    `reports/github/<repository-id>/review-cache.json` for that complete
    successful target.

Report versions and supersession are repository-global rather than scoped to a
target SHA or policy. A first report is version 1. Every later request advances
the current preferred repository report by exactly one and supersedes its report
ID. The publisher checks that lineage before creating an immutable path, so a
stale concurrent outcome fails closed instead of becoming invisible history or
regressing the preferred index.

Policy 5 starts cold: earlier-policy reports cannot seed its cache. On
subsequent scans, a contextual cache hit requires an identical evidence-group digest, exact candidate
IDs, an exact scanner/tool/reviewer identity, and a valid immutable source
report. Only groups whose assessments and related observations are all low with
exposure not demonstrated are reusable. Any missing, malformed, stale,
mismatched, material, high-risk, or demonstrated entry is treated as a miss and
reviewed fresh. All deterministic scanners still rerun regardless of reuse.
Operators can audit reuse through the report's `review_reuse` counts and source
report IDs and through the repository cache manifest. Reports also publish
`review_batches`, including each call's group/candidate counts, conservative
input estimate, over-budget singleton flag, and actual provider token usage.
Deterministic assessments never enter the model-review cache. Valid contextual
groups from a partially invalid response are retained in memory and only
missing or invalid groups are retried.

Fresh contextual work is capped at 12 behavior cases, 6 provider calls
including repairs, 200,000 estimated input tokens, 250,000 actual input tokens,
and 40,000 output tokens per target. The planner rejects an oversized target
before the first request; cumulative overflow stops before the next request.
Either outcome publishes no report and enters the target retry path.

Before contextual grouping, repeated JS-X-Ray warnings of the same kind in one
immutable JavaScript representation become one evidence-preserving review
family. Every warning location still contributes a bounded evidence window,
the report exposes occurrence and family counts, and the JavaScript-analysis
tool version binds this behavior into review-cache identity. Findings from all
other scanners remain independent cards.

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

Every claimed target finishes independently and clears only its own committed
claim. The claim job and per-target publisher both replay their deterministic
transition after a push conflict. Ordinary continuation uses only persisted
queue and claim state and does not wait for deployment. `pages-reconcile.yml`
independently checks the committed main SHA against the deployed source marker
every fifteen minutes and repairs drift. External project owners receive no
operational-failure notification.

Provider exhaustion, context insufficiency, invalid model output, and missing
review coverage are failures, never permission to skip finding candidates,
reduce the policy, switch reviewers automatically, or infer a low result. The
bounded JSON binding repair described above is not a review fallback. A
bounded deterministic JavaScript parser or transform limitation is different:
it is published as explicit incomplete coverage and remains visible without
changing advisory color or concern counts. See [`SCANNING.md`](SCANNING.md).

Each contextual-review attempt has a 20-minute process timeout in addition to
the model client's request policy, and the retrying review job is bounded at 62
minutes. These guards cover a provider that returns headers but never closes
its response stream. A timed-out step still reaches the always-run sanitized
transition, encrypted publication, queue rotation, and continuation path; it
cannot retain the global scan concurrency slot indefinitely.

OpenGrep policy 5 treats only warning-level code 2 `Other syntax error` and
warning-level code 3 `PartialParsing` tuple diagnostics as bounded parser
limitations. Valid findings remain eligible for deterministic triage when those
warnings occur. Unknown warnings, error-level diagnostics, malformed output,
nonzero exits, and process failures remain target-local scanner failures unless
the pinned tool itself is unavailable, which is a shared transient failure.
Rejected OpenGrep diagnostics are categorized as `parser_syntax` or
`rule_timeout` when possible; paths and raw diagnostic text are not persisted.
A scanner finding on a non-text artifact retains its verified size, digest, and
scanner metadata without exposing raw binary to the model. The report publishes
`completed-with-limitations` contextual coverage and cannot appear low solely
because the model could not inspect the raw contents.

Invalid contextual-model responses use every configured immediate attempt with
corrective guidance naming only the rejected field category. The rejected prose
is never copied into another review prompt or persisted. After the last attempt,
only a parsed completed response with an allowlisted evidence-binding diagnostic
may use the one-call Luna patch protocol; all other invalid output rotates the
target unchanged.

Any change to scanner behavior or output requires a clean canary baseline.
Before reactivation, remove the existing Wandlight and Recursion report trees
and preferred-index entries, prove Tavernary has imported the empty state, and
then scan each canary once under the new policy. Do not reset other repository
history as part of this release gate.

Queue scheduling, retention, or deployment-routing changes that do not alter
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
- `coverage-campaign.yml` freezes the one-time top-20-popular plus
  latest-20-stable-release cohort and dispatches reconciliation.
- `staff-operations.yml` sets or clears the explicit emergency stop, makes one
  target immediately due, revokes an unconsumed staff request, or performs a
  protected legacy-to-V3 state migration. `revoke` removes only
  `staff_requested`, preserves retry history and the emergency stop, is
  idempotent, and does not dispatch reconciliation.
- `prepare-diagnostic.yml` is an owner-only, `main`-only deterministic probe.
  It checks out the immutable request, runs preparation and pinned scanners,
  removes all repository/session data, and retains only a sanitized
  `result.json` artifact for one day. It has no model, repair, Publisher,
  queue, report, deployment, or reconciliation authority.
- `deploy-pages.yml` deploys only an exact commit proven to be on `main`;
  manual runs require staff protection.
- `pages-reconcile.yml` automatically repairs a missing or stale Pages
  deployment without participating in scan continuation.
- `publisher-verification.yml` is an input-free owner-only canary. From `main`,
  it first mints and uses a Publisher token in `tavernkeeper-scanner`, then
  waits for that empty audit commit before entering `tavernkeeper-staff` and
  repeating the protected-main write. Approve the existing staff environment
  gate, verify both commits were authored through the Publisher App, and verify
  each action post step reports token revocation. Only after both lanes succeed
  may the obsolete `TAVERNKEEPER_PUBLISHER_APP_ID` environment secrets be
  removed; retain the Client ID variable and private-key secret in both
  environments.

To revoke CharacterLibrary's unconsumed staff request while preserving full
maintenance and retry history, run:

```text
gh workflow run staff-operations.yml --repo MentallyQuill/TavernKeeper --ref main -f operation=revoke -f repository_id=1139430137
```

For a model-free preparation diagnosis, save the reviewed immutable scan
request as `request.json`, then run:

```text
gh workflow run prepare-diagnostic.yml --repo MentallyQuill/TavernKeeper --ref main -f request_json="$(jq -c . request.json)"
```

Download only the resulting `preparation-diagnostic-<repository-id>` artifact.
`status: prepared` means deterministic preparation succeeded; it grants no
scan authorization and does not permit a contextual-model request.

Public Issues and comments do not trigger these workflows. A false-positive
appeal cannot change an individual report. If evidence exposes a scanner,
prompt, or assessment-policy defect, staff change global versioned policy
through ordinary code review and TavernKeeper automatically rescans affected
targets.

No production candidate waits for review, dismissal, or recoloring. Context,
model, schema, evidence, sanitizer, tool-integrity, or hard scanner failure
publishes nothing and enters the classified retry path. Bounded policy-5
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
digest equals the deployed source digest; deterministic and contextual
assessments together cover every candidate; and Tavernary imports only matching
repository IDs and SHAs.

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
