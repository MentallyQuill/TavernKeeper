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

Provider credentials are exposed only to the contextual-review step and the
protected provider compatibility check. They are absent from acquisition,
scanners, finalization, artifacts, publication, and telemetry. A model change
must pass `provider-check.yml` against the complete contextual response schema
before production scanning resumes. TavernKeeper requests the standard
OpenAI-compatible `json_object` response format, then independently validates
the exact local schema, evidence identity, and complete candidate coverage. Do
not add automatic model fallback.

The shared workflow encrypts the sanitized candidate and transition envelope
with AES-256-GCM before upload, removes the plaintext handoff, retains the
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
recovery work does not wait for the safety-net schedule. Reconciliation derives
work from Tavernary's live V2 or V3 target manifest minus TavernKeeper's V5
preferred current reports. It selects at most five repositories and calls
`scan-and-publish.yml`, which runs at most two scan jobs concurrently. Standard,
retry, targeted, and policy-campaign scans converge on the same automatic V5
publication path. If work remains after verified publication and deployment,
the publisher dispatches another input-free batch.

On the first staff resume, TavernKeeper records an immutable
`coverage_started_at` timestamp. Manifest V3 initial coverage is strict
`popularity_rank` order. Reconciliation selects runnable primary catalog work
before any due target retry. Only after that primary pass is empty may it admit
one due automatic retry slot per exact target in the round. Manual quarantines
remain visible in queue telemetry but are not runnable. V2 remains a temporary
compatibility path: current Top 30, submissions first cataloged on or after
coverage start, and older projects. V2 new and old lanes sort by
`first_cataloged_at`, and thirty-day age boosts prevent starvation.

The queue is derived. A target that advances before acquisition is coalesced to
the newest manifest SHA. Once exact-SHA acquisition begins, TavernKeeper
completes and publishes that immutable SHA even if the catalog advances.
Tavernary keeps the assessment and marks freshness separately. A staff request
created after a prior completed report remains an intentional forced rescan,
and a same-SHA replacement may become preferred without erasing history.

## Scan lifecycle

For every exact target, TavernKeeper:

1. acquires and inventories the repository without executing target code;
2. completes all required applicable deterministic scanners;
3. validates and groups every candidate with bounded evidence context;
4. asks the configured model to assess every candidate under the versioned
   ecosystem prompt and strict response schema;
5. rejects missing context, incomplete coverage, invented citations, invalid
   structured output, provider errors, and exhausted token or byte limits;
6. revalidates exact HEAD and constructs the complete Technical Report V5;
7. transports the sanitized candidate through authenticated encryption; and
8. atomically publishes immutable JSON/HTML, history, and the preferred index
   for every complete successful outcome in the batch.

The model may classify candidate evidence as expected behavior, a minor
weakness, a material vulnerability, or credible malicious behavior. It does
not assign Tavernary's final project color. Tavernary performs a separate
strict synthesis and enforces deterministic risk floors after import.

## Pause and recovery

Operations state schema V2 separates three failure domains. Never edit state
concurrently with publication.

- `target`: classify deterministic failures as manual quarantines and transient
  failures as automatic retries. A new manifest SHA is a new primary target;
  otherwise a manual quarantine runs only through protected staff rescan.
  Automatic retries wait for the primary catalog pass and then use delays of 5
  minutes, 30 minutes, and 2 hours. A fourth failed attempt exhausts only that
  exact SHA, creates one staff Issue keyed by repository ID plus SHA, and leaves
  the rest of the catalog runnable.
- `shared`: pause new catalog targets and admit one due recovery probe per
  complete failure fingerprint, with two probes maximum per batch. Delays are
  5, 15, 30, and 60 minutes, then 3 hours capped indefinitely. Four failures
  create a staff Issue, but probing never becomes terminal. The first successful
  probe clears its hold and ordinary reconciliation resumes automatically.
- `security`: fail closed with reason `SECURITY_HOLD`. Repair the credential,
  configuration, authenticity, authorization, encryption, or integrity
  boundary; run the relevant compatibility check; then explicitly resume
  through `staff-operations.yml`. Unknown system failures take this path.

Every selected matrix target still finishes independently. The serialized
publisher retains complete reports from peer repositories, persists the real
failure domains, and exposes `continuation_blocked`. Ordinary continuation uses
only the persisted publisher result plus successful deployment; target-local
matrix failures do not suppress it. External project owners receive no
operational-failure notification.

Provider exhaustion, context insufficiency, invalid model output, and missing
review coverage are failures, never permission to skip candidates, reduce the
policy, switch models automatically, infer a low result, or publish an
incomplete repository report.

OpenGrep policy 3 treats only warning-level code 2 `Other syntax error` and
warning-level code 3 `PartialParsing` tuple diagnostics as bounded parser
limitations. Valid findings remain eligible for contextual review when those
warnings occur. Unknown warnings, error-level diagnostics, malformed output,
nonzero exits, and process failures remain target-local scanner failures unless
the pinned tool itself is unavailable, which is a shared transient failure.

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
  Tavernary wake-App actor, refetches the public V2 or V3 manifest, and derives a
  standard scan request. Staff begin this flow through Tavernary's
  exact-GitHub-URL Action.
- `policy-rescan.yml` schedules a campaign under the current reviewed policy.
- `staff-operations.yml` pauses, resumes, retries a target, or performs the
  protected one-time V1-to-V2 state migration.
- `deploy-pages.yml` deploys only an exact commit proven to be on `main`;
  manual runs require staff protection.

Public Issues and comments do not trigger these workflows. A false-positive
appeal cannot change an individual report. If evidence exposes a scanner,
prompt, or assessment-policy defect, staff change global versioned policy
through ordinary code review and TavernKeeper automatically rescans affected
targets.

No production candidate waits for review, dismissal, or recoloring. Scanner,
context, model, schema, coverage, evidence, sanitizer, or tool incompleteness
publishes nothing and enters the classified retry path.

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

`npm run test:e2e` uses controlled doubles for Git history, external scanner
adapters, model transport, and exact-HEAD verification. Real provider behavior,
digest-pinned tools, and exact validated checkouts remain release and
live-canary gates.

For the V3 autonomous rollout: publish and verify Tavernary's complete ranked
manifest; merge TavernKeeper while operations remain stopped; run the protected
`migrate` operation and verify schema V2 plus its numeric classification
summary; run provider and pinned-tool compatibility checks; then use a separate
protected `resume`. Verify the first selected repositories have ascending
popularity ranks, Pages matches the committed report index, a real shared hold
admits a probe and clears on success, and no security hold remains. Migration
itself never dispatches scanning.
