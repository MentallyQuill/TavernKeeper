# Architecture

The canonical cross-repository design is maintained in Tavernary at
`docs/superpowers/specs/2026-07-31-tavernkeeper-cross-repository-security-design.md`.
This document is the TavernKeeper operator summary.
[`development-rules.md`](development-rules.md) defines the mandatory automation
boundary.

## Repository responsibilities

Tavernary is authoritative for catalog eligibility, GitHub repository identity,
the current healthy head SHA, the public target manifest, card mapping, report
import, freshness, and presentation. TavernKeeper is authoritative for scan
policy, exact-SHA acquisition, deterministic evaluation, queue and retry state,
finding normalization, immutable publication and history, staff incidents, and
policy rescans.

The wake-up event in either direction carries no target, budget, clone URL, or
report URL. It only asks the destination to reconcile its own public input.
Each side also reconciles on a six-hour schedule.

The two wake Apps are Actions-only bridges installed on one destination
repository apiece. A third App, `TavernKeeper Publisher`, is installed only on
TavernKeeper with contents write. Protected mutation jobs mint a short-lived
Publisher token; continuation dispatches use a separate Actions-only token.

```text
Tavernary target manifest (repository ID + exact SHA)
  -> input-free wake or scheduled reconciliation
  -> TavernKeeper derives at most 5 pending targets
  -> at most 2 disposable scan jobs run concurrently
  -> exact checkout and portable-path inventory
  -> history, TavernKeeper rules, and all applicable pinned scanners
  -> normalized evidence and deterministic Scan Package digest
  -> fixed severity/confidence policy and fixed-template summaries
  -> authenticated encrypted candidate handoff
  -> serialized V4 validation and immutable publication/history
  -> verified TavernKeeper Pages report index
  -> input-free Tavernary wake
  -> Tavernary validates summaries and rebuilds cards
```

## Trust and execution boundaries

Repository content is untrusted data. Checkout URLs are derived from the
validated GitHub repository name; arbitrary clone URLs are not accepted. Git
hooks, credential helpers, LFS smudging, submodules, recursive clones, local
protocols, and interactive prompts are disabled. Target dependencies, scripts,
Actions, builds, tests, containers, and executables are never run.

Inventory establishes path and byte coverage before scanning. TavernKeeper's
rules and every external adapter operate on the checkout as data. The trusted
Malcontent image is digest-pinned, network-disabled, read-only, capability-free,
and receives only a read-only target mount. Raw target data remains in
disposable runner storage.

The complete normalized evidence set becomes Scan Package V1. Package and
policy digests bind every report to its evidence and rule versions. Result
derivation is fixed: red requires at least one medium-or-higher finding at
medium-or-higher confidence; otherwise the completed result is teal. Concise
public explanations and remediation are selected from versioned rule templates,
not generated text.

## Atomic reporting

Every applicable deterministic scanner must complete. Evidence validation must
prove cited paths, line ranges, fingerprints, content mappings, coverage, and
the scanned SHA. TavernKeeper rechecks exact HEAD before finalization. A tool,
coverage, evidence, schema, sanitizer, or publication failure yields no
candidate and enters the retry path.

Reports are addressed by provider, immutable GitHub repository ID, exact SHA,
scanner-policy version, and report version. Matrix jobs encrypt sanitized
outcomes before a one-day artifact handoff. A serialized publisher decrypts in
ephemeral storage, prevalidates the whole batch, writes immutable V4 JSON and
script-free HTML plus repository history, updates the preferred V4 index, and
rolls back partial writes on failure.

Every direct write to `main` uses the dedicated Publisher App. Checkout
credentials are never persisted, `GITHUB_TOKEN` retains contents-read, and
Publisher authentication failure stops the mutation with no fallback.

## Public states

- `teal`: complete policy with no qualifying finding.
- `red`: complete policy with at least one medium-or-higher finding at
  medium-or-higher confidence.
- Orange, gray, and dark teal are Tavernary presentation states for
  outdated-clean, eligible-unscanned or unavailable, and unsupported sources.

Teal means only that the completed policy found no qualifying concern at that
commit. It never means safe, trusted, verified, or certified. Scan results never
hide, quarantine, rank, or delist Tavernary projects automatically.
