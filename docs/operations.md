# TavernKeeper Operations

All privileged workflows run from trusted TavernKeeper code. Keep `main`
protected, use `tavernkeeper-scanner` for unattended scans, and use
`tavernkeeper-staff` only to control privileged operations. A complete
production result never waits for human approval. The automation boundary is
normative in [`development-rules.md`](development-rules.md).

## Runtime configuration

Configure this secret in `tavernkeeper-scanner`:

- `TAVERNKEEPER_ARTIFACT_KEY`: canonical base64 encoding of exactly 32 random
  bytes, used only for the authenticated matrix-to-publisher handoff.

The shared workflow encrypts the sanitized candidate and transition envelope
with AES-256-GCM before upload, removes the plaintext handoff, retains the
ciphertext artifact for one day, and decrypts it only in the serialized
publisher job. Generate the key with a cryptographically secure random source.
Never reuse an App key.

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
reports, or shell history. The production scanner has no language-model
credential, endpoint, transport, or fallback.

## Normal reconciliation

`reconcile.yml` runs every six hours and accepts input-free workflow and
repository dispatches. It derives work from Tavernary's live V2 target manifest
minus TavernKeeper's V4 preferred current reports. It selects at most five
repositories and calls `scan-and-publish.yml`, which runs at most two scan jobs
concurrently. Standard, retry, targeted, and policy-campaign scans converge on
this automatic publication path. If work remains after verified deployment, it
dispatches another input-free batch.

On the first staff resume, TavernKeeper records an immutable
`coverage_started_at` timestamp. Ordinary work uses three lanes: current Top 30,
submissions first cataloged on or after that timestamp, and older projects. New
and old lanes sort by `first_cataloged_at`; due retries return to their source
lane. Thirty-day age boosts prevent starvation without changing lane identity.

The queue is derived. A target that advances before acquisition is coalesced to
the newest manifest SHA. Once exact-SHA acquisition begins, TavernKeeper
completes and publishes that immutable SHA even if the catalog advances.
Tavernary then presents a clean older report as pending. A staff request created
after a prior completed report remains an intentional forced rescan, and a
same-SHA replacement may supersede the preferred report without erasing
history.

## Pause and recovery

The tracked initial state is staff-paused with reason `INITIAL_ROLLOUT`. Use
`staff-operations.yml` to pause, resume, or request a retry. The first resume
records `coverage_started_at`; later cycles preserve it. Never edit state
concurrently with publication.

System failures stop ordinary scanning and engage the circuit breaker. No
degraded report is published. Retries run at T+1, T+2, and T+3 hours from the
initial failure. No staff or owner notification is sent for intermediate
failures. After the third delayed retry fails, TavernKeeper creates or updates
one deduplicated `scanner-operations` Issue and remains stopped until staff fix
the cause and explicitly resume. Repository-specific failures delay only that
target. External project owners receive no operational-failure notification.

## Staff workflows

- `targeted-scan.yml` accepts only a repository-ID hint from the immutable
  Tavernary wake-App actor, refetches the public V2 manifest, and derives a
  standard scan request. Staff begin this flow through Tavernary's
  exact-GitHub-URL action.
- `policy-rescan.yml` schedules a campaign under the current reviewed policy.
- `staff-operations.yml` pauses, resumes, or retries a target.
- `deploy-pages.yml` deploys only an exact commit proven to be on `main`;
  manual runs require staff protection.

Public Issues and comments do not trigger these workflows. A false-positive
appeal cannot change an individual report. If evidence exposes a scanner defect,
staff change global versioned policy through ordinary code review and
TavernKeeper automatically rescans affected targets.

No production candidate waits for review, dismissal, or recoloring. Schema,
coverage, evidence, sanitizer, or tool incompleteness publishes nothing and
enters the classified retry path.

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

Confirm hostile fixture markers and credentials do not appear in reports or
site output, the public report-index digest equals the deployed source digest,
and Tavernary imports only matching repository IDs and SHAs.

`npm run test:e2e` uses deterministic doubles for Git history, external scanner
adapters, and exact-HEAD verification. Real digest-pinned tools and exact
validated checkouts remain release and live-canary gates.

For the first rollout, keep ordinary operations paused and use Tavernary's
staff-targeted GitHub-URL action to prove Recursion and Wandlight through the
complete production path. Neither repository is hardcoded into policy. Resume
the Top-30/new/old backlog only after both reports, Pages publication, Tavernary
import, and inline scan-result presentation are verified live.
