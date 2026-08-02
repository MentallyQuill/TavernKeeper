# TavernKeeper Operations

All privileged workflows run from trusted TavernKeeper code. Keep `main` protected, use the `tavernkeeper-scanner` environment for unattended scans, and use `tavernkeeper-staff` only to control who may initiate a privileged operation. A complete production result never waits for environment or staff approval. The automation boundary is normative in [`development-rules.md`](development-rules.md).

## Runtime configuration

Configure these Actions secrets in the unattended `tavernkeeper-scanner` environment. Workflow policy permits provider credentials only on the shared workflow step named `Review with configured model` and the staff-authorized workflow step named `Check configured model provider`:

- `TAVERNKEEPER_API_ENDPOINT`: the complete HTTPS OpenAI-compatible Chat Completions endpoint
- `TAVERNKEEPER_API_KEY`: provider credential
- `TAVERNKEEPER_MODEL`: provider model identifier; the initial production value is `deepseek/deepseek-v4-flash-0731:thinking`
- `TAVERNKEEPER_ARTIFACT_KEY`: canonical base64 encoding of exactly 32 random bytes, used only for the authenticated matrix-to-publisher handoff

The shared workflow encrypts the sanitized candidate/transition envelope with AES-256-GCM before artifact upload, deletes the plaintext handoff files, retains the ciphertext artifact for one day, and decrypts it only in the serialized publisher job. Generate this value from a cryptographically secure random source. Never reuse the model key or an App key.

Configure `TAVERNARY_WAKE_APP_ID` and `TAVERNARY_WAKE_APP_PRIVATE_KEY` only in TavernKeeper. The GitHub App must be installed only on Tavernary with Actions write and metadata read. It receives no contents write access.

Tavernary stores `TAVERNKEEPER_WAKE_APP_ID` and `TAVERNKEEPER_WAKE_APP_PRIVATE_KEY`; they are not TavernKeeper secrets. That App is installed only on TavernKeeper with Actions write and metadata read.

Configure these environment secrets separately in both `tavernkeeper-scanner` and `tavernkeeper-staff`:

- `TAVERNKEEPER_PUBLISHER_APP_ID`
- `TAVERNKEEPER_PUBLISHER_APP_PRIVATE_KEY`

`TavernKeeper Publisher` must be installed only on TavernKeeper with contents read/write and mandatory metadata read. It receives no Actions permission. Mutation jobs mint a short-lived token scoped explicitly to `MentallyQuill/TavernKeeper`, disable persisted checkout credentials, and fail if App authentication or the push fails. Never add the Publisher credentials as repository-level secrets and never add a `GITHUB_TOKEN` contents-write fallback.

Protect `main` with the active ruleset `Protect main; allow TavernKeeper Publisher`. The ruleset targets only the default branch, requires pull requests and the GitHub Actions `check` status for ordinary actors, blocks deletion and non-fast-forward updates, and grants an always bypass only to the Publisher App Integration actor.

Do not put secret values in workflow inputs, repository files, Issues, logs, reports, or shell history. Workflows pass model secrets only to the step named `Review with configured model`.

Before enabling or resuming production scans, run `provider-check.yml`. The protected preflight proves the configured Bearer endpoint and then exercises the same private chunk-text and strict repository-synthesis response contracts used by production, without checking out a repository or mutating scan state. The production review covers the complete eligible corpus, retains chunk prose only as private synthesis input or a content-addressed private cache entry, and makes exactly one final JSON synthesis call after all chunks and tools succeed. Cache entries never contain raw source chunks, prompts, credentials, or raw provider responses.

The initial release uses only the configured DeepSeek model. Adding Luna or any second model is not an automatic fallback: it requires a separate, approved, versioned scanner/prompt policy revision with tests and an explicit credential-placement review.

## GitHub App key rotation

Generate a replacement private key from the App settings before revoking the active key. For a wake App, update both source-repository secret values, prove an input-free destination dispatch, then revoke the old key. For the Publisher App, update the ID and private key in both protected environments, prove one protected operational-state publication, then revoke the old key. Resolve every downloaded PEM to the expected Downloads directory, remove it immediately after GitHub secret storage, and verify only secret names in logs.

## Normal reconciliation

`reconcile.yml` runs every six hours and accepts input-free workflow and repository dispatches. It derives work from Tavernary's live V2 target manifest minus TavernKeeper's V2 preferred current reports. It selects at most five repositories and calls `scan-and-publish.yml`, which runs at most two scan jobs concurrently. Standard, retry, targeted, deep, and policy-campaign scans all converge on this automatic publication path. If work remains after a verified publication/deployment, it dispatches another input-free batch.

On the first staff resume, TavernKeeper records the immutable `coverage_started_at` timestamp. Ordinary work uses three lanes: current Top 30, submissions first cataloged on or after that timestamp, and older projects. New and old lanes sort by `first_cataloged_at`; due retries return to their target's source lane. Thirty-day age boosts prevent a lower lane from starving without changing its lane identity.

The queue is derived, not separately mutable. A target that advances before it starts is coalesced to the newest manifest SHA. All scan entry points share one non-cancelling global queue. A duplicate targeted request records its immutable GitHub workflow creation time; after it reaches the resolver, it coalesces when the same SHA was completed after that request entered the queue or when the target already has a scheduled retry. A staff request created after a prior completed report remains an intentional forced rescan. Resolution uses the committed report index, so a Pages deployment delay cannot cause duplicate model spend. Once exact-SHA acquisition begins, TavernKeeper completes and publishes that immutable SHA even if the catalog advances; Tavernary then presents a clean older report as pending an updated scan. Success and failure transitions both clear any matching active-scan state.

## Pause and recovery

The tracked initial state is staff-paused with reason `INITIAL_ROLLOUT` and has no coverage-start timestamp. Use `staff-operations.yml` in the protected staff environment to pause, resume, or request a retry. The first resume records `coverage_started_at`; later pause/resume cycles preserve it. Never edit state concurrently with a publication workflow.

Repository-scoped `MODEL_INVALID_RESPONSE` failures receive up to three immediate attempts inside one scan execution. If the review still fails, system/provider failures stop ordinary scanning and engage the circuit breaker. No degraded report is published. Delayed retries run at T+1, T+2, and T+3 hours, measured from the initial failure. No staff or owner notification is sent for intermediate failures. After the T+3 retry also fails, TavernKeeper creates or updates one deduplicated `scanner-operations` Issue for staff and remains stopped until staff correct the cause and explicitly resume.

Repository-specific failures delay only that target. External project owners receive no operational-failure notification.

## Staff workflows

- `provider-check.yml`: after protected staff authorization, sends a one-token status request through the configured production Bearer path, then validates fixed repository-free requests against the production chunk-review and repository-synthesis response parsers. It tries `x-api-key` only after a 401 or 403 on the status request. Logs contain only a pass record, an allowlisted response-stage diagnostic, and when applicable an integer HTTP error status from 400 through 599; endpoint, model output, reasoning, headers, and provider bodies are never logged. The action cannot scan repositories, mutate operational state, publish reports, or wake Tavernary.
- `targeted-scan.yml`: accepts only a repository-ID routing hint from the immutable Tavernary wake-App actor, refetches the public V2 manifest, and derives a standard scan request. Humans begin this flow only through Tavernary's staff-only exact-GitHub-URL action.
- `deep-scan.yml`: rescan every eligible first-party text file for one repository ID.
- `policy-rescan.yml`: schedule a staff-initiated campaign under a new policy.
- `staff-operations.yml`: pause, resume, or manually retry a target.
- `deploy-pages.yml`: deploy only an exact commit proven to be on `main`; manual runs require staff protection.

Public Issues and Issue comments do not trigger these workflows. A false-positive appeal supplies only an immutable report identity, finding fingerprint, and maintainer evidence. It cannot trigger work or change an individual report. If the evidence exposes a scanner defect, staff change global versioned policy through ordinary code review and TavernKeeper automatically rescans affected targets.

No complete production candidate waits for staff review, environment approval, dismissal, or recoloring. Schema, coverage, evidence, sanitizer, or provider incompleteness publishes nothing and enters the classified retry path instead.

## Release checks

Before deploying scanner or workflow changes, run:

```text
npm run check
npm run test:e2e
npm run build
actionlint .github/workflows/*.yml
```

Confirm the hostile fixture marker does not exist, fixture credentials do not appear in cache/report/site output, the public report index digest equals the deployed source digest, and Tavernary imports only matching repository IDs and SHAs.

`npm run test:e2e` is an in-process hostile-data safety and publication gate, not a real-tool or live-provider certification. Its fixtures run real inventory, classification, static rules, redaction, chunking, and publication while deterministically replacing Git history, external scanner adapters, exact-HEAD verification, and model transport. Unit and contract tests cover external scanner adapters and model transport. The release and live-canary gates are the real digest-pinned tools, the configured provider, and an exact validated checkout SHA; do not represent the fixture suite as having run any of them.

For the first live rollout, keep normal operations paused and use Tavernary's general staff-targeted GitHub-URL action to prove Recursion and Wandlight through the complete production path. Neither repository is hardcoded into scanner policy. Enable the ordinary Top-30/new/old backlog only after both reports, Pages publication, Tavernary import, and inline scan-result presentation have been inspected.
