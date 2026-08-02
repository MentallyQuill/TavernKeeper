# Architecture

The canonical cross-repository design is maintained in Tavernary at `docs/superpowers/specs/2026-07-31-tavernkeeper-cross-repository-security-design.md`. This document is the TavernKeeper operator summary. [`development-rules.md`](development-rules.md) defines the mandatory automation boundary.

## Repository responsibilities

Tavernary is authoritative for catalog eligibility, GitHub repository identity, the current healthy head SHA, the public target manifest, card mapping, report import, freshness, and presentation. TavernKeeper is authoritative for scan policy, exact-SHA acquisition, deterministic and model review, queue and retry state, finding normalization, automated validation, immutable publication and history, staff incidents, deep scans, and policy rescans.

The wake-up event in either direction contains no target, scan mode, budget, clone URL, model, or report URL. It only asks the destination to reconcile its own public input. Each side also reconciles on a six-hour schedule.

The two wake Apps are Actions-only bridges installed on one destination repository apiece. A third App, `TavernKeeper Publisher`, is installed only on TavernKeeper with contents write and mandatory metadata read. It cannot wake Tavernary or continue a scan batch. Mutation jobs obtain a short-lived Publisher token from the protected `tavernkeeper-scanner` or `tavernkeeper-staff` environment; any local continuation dispatch is a separate Actions-only step using the repository-local token.

```text
Tavernary target manifest (repository ID + exact SHA)
  -> input-free Actions wake or scheduled reconciliation
  -> TavernKeeper derives at most 5 pending targets
  -> at most 2 disposable scan jobs run concurrently
  -> exact checkout, full inventory, required scanners
  -> redacted private text review for every eligible chunk
  -> one strict JSON repository synthesis
  -> deterministic evidence validation and result derivation
  -> authenticated encrypted candidate handoff
  -> serialized validation and immutable publication
  -> verified TavernKeeper Pages report index
  -> input-free Actions wake
  -> Tavernary validates/imports summaries and rebuilds cards
```

## Trust and execution boundaries

Repository content is untrusted data. Checkout URLs are derived from the validated GitHub repository name; arbitrary clone URLs are not accepted. Git hooks, credential helpers, LFS smudging, submodules, recursive clones, local protocols, and interactive prompts are disabled. Target dependencies, scripts, actions, builds, tests, containers, and executables are never run. The trusted Malcontent scanner runs in its official linux-amd64 image pinned by immutable digest, with networking disabled, a read-only root filesystem, all capabilities dropped, no-new-privileges, and only the target checkout mounted read-only.

Inventory establishes portable path safety and byte/file coverage before expensive work. Deterministic tools receive TavernKeeper-owned rules and configuration. Raw target data stays in disposable runner storage. Model credentials are injected only into the one configured-model review step. The initial production configuration uses NanoGPT with `deepseek/deepseek-v4-flash-0731:thinking`; the endpoint and model identifier remain runtime configuration rather than architecture.

The configured model reviews the complete eligible current-tree corpus, split into deterministic byte-bounded text chunks with stable evidence IDs. Each chunk returns bounded private prose. After every chunk and scanner completes, one repository synthesis receives the complete set of validated chunk recaps, observations, and sanitized tool results and must return the strict assessment JSON contract. The former multi-role review chain has been removed; tool findings remain independently visible and are never disposed of by model prose.

Successful private cache entries contain only a validated chunk result or final synthesis plus content-addressed identity metadata and usage/completion metadata. Cache keys bind the endpoint origin, model identifier, policy versions, prompt/stage digest, and input digests. Raw source chunks, prompts, credentials, and raw provider responses never enter the cache or a public report.

## Atomic reporting

Every applicable deterministic scanner must complete. Every eligible selected source path must appear in the chunk plan. Every private chunk review and the one repository synthesis must complete. Deterministic validation must prove every cited path, line range, content mapping, fingerprint, and scanned SHA. The exact target SHA is rechecked immediately before model use. A quota, token, provider, tool, malformed-output, coverage, evidence, schema, redaction, or publication failure yields no candidate.

Reports are addressed by provider, immutable GitHub repository ID, exact SHA, scanner-policy version, mode, and report version. Matrix jobs encrypt sanitized outcomes before the one-day artifact handoff; plaintext target content, model traffic, and scan handoffs are never uploaded. A serialized publisher decrypts in ephemeral storage, prevalidates the whole batch, writes report JSON and script-free HTML plus repository history to immutable paths, updates the preferred V2 index, and rolls back partial writes on failure.

Every direct write to `main` uses the dedicated Publisher App. Checkout credentials are never persisted, `GITHUB_TOKEN` retains contents-read, and Publisher authentication failure stops the mutation with no fallback. TavernKeeper's main ruleset requires a pull request and the `check` CI status for ordinary actors, blocks deletion and non-fast-forward updates, and grants the only direct-write bypass to the Publisher App Integration actor.

## Public states

- `teal`: complete policy with no confirmed medium-or-higher finding at medium-or-higher confidence.
- `red`: complete policy with at least one such confirmed finding.
- Orange, gray, and dark teal are Tavernary presentation states for outdated-clean, eligible-unscanned/unavailable, and unsupported sources.

Teal means only that the completed policy found no confirmed review-level concern at that commit. It never means safe, trusted, verified, or certified. Scan results never hide, quarantine, rank, or delist Tavernary projects automatically.
