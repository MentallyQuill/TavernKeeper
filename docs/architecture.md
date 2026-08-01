# Architecture

The canonical cross-repository design is maintained in Tavernary at `docs/superpowers/specs/2026-07-31-tavernkeeper-cross-repository-security-design.md`. This document is the TavernKeeper operator summary.

## Repository responsibilities

Tavernary is authoritative for catalog eligibility, GitHub repository identity, the current healthy head SHA, the public target manifest, card mapping, report import, freshness, and presentation. TavernKeeper is authoritative for scan policy, exact-SHA acquisition, deterministic and model review, queue and retry state, finding normalization, immutable publication, staff incidents, deep scans, policy rescans, and adjudication.

The wake-up event in either direction contains no target, scan mode, budget, clone URL, model, or report URL. It only asks the destination to reconcile its own public input. Each side also reconciles on a six-hour schedule.

```text
Tavernary target manifest (repository ID + exact SHA)
  -> input-free Actions wake or scheduled reconciliation
  -> TavernKeeper derives at most 5 pending targets
  -> at most 2 disposable scan jobs run concurrently
  -> exact checkout, full inventory, required scanners
  -> redacted streaming model review and final synthesis
  -> serialized validation and immutable publication
  -> verified TavernKeeper Pages report index
  -> input-free Actions wake
  -> Tavernary validates/imports summaries and rebuilds cards
```

## Trust and execution boundaries

Repository content is untrusted data. Checkout URLs are derived from the validated GitHub repository name; arbitrary clone URLs are not accepted. Git hooks, credential helpers, LFS smudging, submodules, recursive clones, local protocols, and interactive prompts are disabled. Target dependencies, scripts, actions, builds, tests, containers, and executables are never run.

Inventory establishes portable path safety and byte/file coverage before expensive work. Deterministic tools receive TavernKeeper-owned rules and configuration. Raw target data stays in disposable runner storage. Model credentials are injected only into the configured-model review step. The provider endpoint and model identifier are runtime configuration, so the pipeline is model-agnostic.

## Atomic reporting

Every applicable deterministic scanner must complete. Every eligible selected source path must appear in the chunk plan. Every chunk must complete model review. Final synthesis must preserve deterministic evidence. The exact target SHA is rechecked immediately before model use. A quota, token, provider, tool, malformed-output, coverage, schema, redaction, or publication failure yields no candidate.

Reports are addressed by provider, immutable GitHub repository ID, exact SHA, scanner-policy version, mode, and report version. A serialized publisher prevalidates the whole batch, writes report JSON and script-free HTML to immutable paths, updates the preferred index, and rolls back partial writes on failure.

## Public states

- `green`: complete policy, with no active medium-or-higher finding at medium-or-higher confidence.
- `yellow`: complete policy, with at least one such finding.
- `gray`: Tavernary presentation state when it cannot match a complete preferred report to the current repository SHA and policy.

Green means no actionable finding under this completed scan policy. It never means safe, trusted, verified, or certified. Scan results never hide, quarantine, rank, or delist Tavernary projects automatically.
