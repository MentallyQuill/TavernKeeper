# TavernKeeper Operations

All privileged workflows run from trusted TavernKeeper code. Keep `main` protected, use the `tavernkeeper-scanner` environment for unattended scans, and use `tavernkeeper-staff` only to control who may initiate a privileged operation. A complete production result never waits for environment or staff approval. The automation boundary is normative in [`development-rules.md`](development-rules.md).

## Runtime configuration

Configure these repository Actions secrets for the configured-model transport. Workflow policy permits them only on the `Review with configured model` step, and both workflows that can reach that step are protected by an approved scan environment:

- `TAVERNKEEPER_API_ENDPOINT`: the complete HTTPS OpenAI-compatible Chat Completions endpoint
- `TAVERNKEEPER_API_KEY`: provider credential
- `TAVERNKEEPER_MODEL`: provider model identifier

Configure `TAVERNARY_WAKE_APP_ID` and `TAVERNARY_WAKE_APP_PRIVATE_KEY` only in TavernKeeper. The GitHub App must be installed only on Tavernary with Actions write and metadata read. It receives no contents write access.

Tavernary stores `TAVERNKEEPER_WAKE_APP_ID` and `TAVERNKEEPER_WAKE_APP_PRIVATE_KEY`; they are not TavernKeeper secrets. That App is installed only on TavernKeeper with Actions write and metadata read.

Configure these environment secrets separately in both `tavernkeeper-scanner` and `tavernkeeper-staff`:

- `TAVERNKEEPER_PUBLISHER_APP_ID`
- `TAVERNKEEPER_PUBLISHER_APP_PRIVATE_KEY`

`TavernKeeper Publisher` must be installed only on TavernKeeper with contents read/write and mandatory metadata read. It receives no Actions permission. Mutation jobs mint a short-lived token scoped explicitly to `MentallyQuill/TavernKeeper`, disable persisted checkout credentials, and fail if App authentication or the push fails. Never add the Publisher credentials as repository-level secrets and never add a `GITHUB_TOKEN` contents-write fallback.

Protect `main` with the active ruleset `Protect main; allow TavernKeeper Publisher`. The ruleset targets only the default branch, requires pull requests and the GitHub Actions `check` status for ordinary actors, blocks deletion and non-fast-forward updates, and grants an always bypass only to the Publisher App Integration actor.

Do not put secret values in workflow inputs, repository files, Issues, logs, reports, or shell history. Workflows pass model secrets only to the step named `Review with configured model`.

## GitHub App key rotation

Generate a replacement private key from the App settings before revoking the active key. For a wake App, update both source-repository secret values, prove an input-free destination dispatch, then revoke the old key. For the Publisher App, update the ID and private key in both protected environments, prove one protected operational-state publication, then revoke the old key. Resolve every downloaded PEM to the expected Downloads directory, remove it immediately after GitHub secret storage, and verify only secret names in logs.

## Normal reconciliation

`reconcile.yml` runs every six hours and accepts input-free workflow and repository dispatches. It derives work from Tavernary's live target manifest minus TavernKeeper's preferred current reports. It selects at most five repositories and runs at most two scan jobs concurrently. If work remains after a verified publication/deployment, it dispatches another input-free batch.

The queue is derived, not separately mutable. A target that advances before it starts is coalesced to the newest manifest SHA. Once exact-SHA acquisition begins, TavernKeeper completes and publishes that immutable SHA even if the catalog advances; Tavernary then presents a clean older report as pending an updated scan.

## Pause and recovery

The tracked initial state is staff-paused with reason `INITIAL_ROLLOUT`. Use `staff-operations.yml` in the protected staff environment to pause, resume, or request a retry. Never edit state concurrently with a publication workflow.

System/provider failures stop ordinary scanning and engage the circuit breaker. No degraded report is published. The first failure is retried after one hour, again after two hours, and again after three hours, measured from the initial failure. No staff or owner notification is sent for intermediate failures. After the third retry also fails, TavernKeeper creates or updates one deduplicated `scanner-operations` Issue for staff and remains stopped until staff correct the cause and explicitly resume.

Repository-specific failures delay only that target. External project owners receive no operational-failure notification.

## Staff workflows

- `deep-scan.yml`: rescan every eligible first-party text file for one repository ID.
- `policy-rescan.yml`: schedule a staff-initiated campaign under a new policy.
- `staff-operations.yml`: pause, resume, or manually retry a target.
- `deploy-pages.yml`: deploy only an exact commit proven to be on `main`; manual runs require staff protection.

Public Issues and Issue comments do not trigger these workflows. A false-positive appeal supplies only an immutable report identity, finding fingerprint, and maintainer evidence. It cannot trigger work or change an individual report. If the evidence exposes a scanner defect, staff change global versioned policy through ordinary code review and TavernKeeper automatically rescans affected targets.

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
