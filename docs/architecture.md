# Architecture

The canonical cross-repository design is maintained in Tavernary at
`docs/superpowers/specs/2026-07-31-tavernkeeper-cross-repository-security-design.md`.
This document is the TavernKeeper operator summary.
[`development-rules.md`](development-rules.md) defines the mandatory automation
boundary.

## Repository responsibilities

Tavernary is authoritative for catalog eligibility, GitHub repository identity,
the current healthy head SHA, the public target manifest, Tavernary final risk,
freshness, card mapping, and presentation. TavernKeeper is authoritative for
scan policy, exact-SHA acquisition, deterministic candidate collection,
file-centered contextual review, queue and retry state, immutable Technical
Report V5 publication and history, staff incidents, and policy rescans.

The wake-up event in either direction is non-authoritative. It asks the
destination to reconcile its own public input and carries no clone URL, report
URL, model, token budget, scan mode, or priority. A targeted wake may contain
only a repository-ID hint, which TavernKeeper resolves again from Tavernary's
public manifest. Each side also reconciles on a six-hour schedule.

The two wake Apps are Actions-only bridges installed on one destination
repository apiece. A third App, `TavernKeeper Publisher`, is installed only on
TavernKeeper with contents write. Protected mutation jobs mint a short-lived
Publisher token; continuation dispatches use a separate Actions-only token.

```text
Tavernary target manifest (repository ID + exact SHA)
  -> input-free wake, repository-ID hint, or scheduled reconciliation
  -> TavernKeeper synchronizes the durable ticket queue
  -> TavernKeeper selects at most 5 due targets in ticket order
  -> at most 2 disposable scan jobs run concurrently
  -> exact checkout and portable-path inventory
  -> history, TavernKeeper rules, and all applicable pinned scanners
  -> normalized candidates and deterministic Scan Package digest
  -> bounded file context for every candidate
  -> configured model returns schema-validated contextual assessments
  -> exact-HEAD, evidence, coverage, schema, and sanitizer validation
  -> authenticated encrypted candidate handoff
  -> serialized V5 validation and immutable publication/history
  -> committed report and queue state
     -> immediate next reconciliation when queue work remains
     -> independent TavernKeeper Pages reconciliation and deployment
        -> input-free Tavernary wake
  -> Tavernary validates the complete report
  -> Tavernary Luna synthesis plus deterministic risk floors
  -> atomic assessment history update and card deployment
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

The normalized evidence set becomes Scan Package V1. Package and policy digests
bind each report to its evidence and rule versions. Deterministic scanners are
candidate locators, not verdict engines. Every candidate is grouped with
bounded source context, related data-flow evidence, project-purpose metadata,
and a versioned SillyTavern ecosystem context. Repository text is explicitly
untrusted and cannot override the reviewer prompt or response contract.

Provider secrets exist only in the contextual-review step. Preparation and
finalization cannot read them. The model is selected through runtime
configuration; model choice cannot change the accepted assessment vocabulary,
coverage rules, evidence binding, or V5 report schema. Raw provider responses
and hidden reasoning are never persisted or published.

## Atomic reporting

Every applicable scanner must complete, and every candidate must receive
exactly one valid contextual assessment. TavernKeeper attaches each
assessment's location from validated deterministic candidate evidence instead
of asking the model to reproduce it. Model-authored observation locations must
still match supplied source context. Evidence validation proves cited paths,
line ranges, identities, content mappings, coverage, and the scanned SHA.
TavernKeeper rechecks exact HEAD before finalization. A tool, provider, context,
review, quota, evidence, schema, sanitizer, or publication failure yields no
report for that repository and enters the retry path.

Matrix targets finish independently. The serialized publisher pairs each
completed transition with its own candidate, records every failed transition,
and atomically publishes the complete successful subset. A peer failure never
turns a completed report into degraded output and never causes that report to
be discarded. Committed publisher state, not matrix or Pages job status, drives
continuation after a mixed batch. A separate scheduled reconciler repairs Pages
drift without holding the scan queue.

Every sanitized failure carries a bounded domain, component, code, and optional
diagnostic stage. Domains preserve useful incident classification, but no
ordinary failure domain can pause scheduling. A failed exact target receives a
new tail ticket and a finite cooldown; after the fifth consecutive failure it
is chronic and staff-visible but remains nonterminal. The queue retains the
latest four sanitized failure descriptors so a changing sequence remains
diagnosable without preserving raw tool output, source paths, or model prose.
The chronic Issue identity is derived from repository ID and exact SHA rather
than the failure descriptor. Unknown failures use the sanitized shared circuit,
so unexpected diagnostics receive a finite automatic probe instead of halting
the catalog.

OpenGrep exposes bounded `parser_syntax` and `rule_timeout` categories, and
unsupported non-text contextual evidence exposes `evidence_non_text`. Model
schema retries receive the rejected field category only; identical corrective
feedback is not retried indefinitely.

Operations state schema V3 persists one monotonic ticket ledger. Tavernary
manifest V3 adds a complete positive `popularity_rank`, which controls initial
seeding strictly from rank 1 upward. A failure moves behind every project
already assigned a ticket; later catalog arrivals append behind that rotated
failure. The sole scheduling stop is an explicit protected staff emergency
stop. Manifest V2 remains a temporary compatibility input and uses the earlier
Top-30/new/old order when seeding.

Reports are addressed by provider, immutable GitHub repository ID, exact SHA,
scanner and contextual-policy versions, and report version. Matrix jobs encrypt
sanitized outcomes before a one-day artifact handoff. A serialized publisher
decrypts in ephemeral storage, prevalidates the whole successful subset, writes
immutable V5 JSON and script-free HTML plus repository history, updates the
preferred V5 index, and rolls back partial writes on failure.

Every direct write to `main` uses the dedicated Publisher App. Checkout
credentials are never persisted, `GITHUB_TOKEN` retains contents-read, and
Publisher authentication failure stops the mutation with no fallback.

## Risk and public states

TavernKeeper publishes complete technical evidence and per-item contextual
recommendations (`low`, `material`, or `high`), but it does not assign the
project's public color. Tavernary's separate strict synthesis applies
deterministic minimum-risk floors and produces the final project assessment:

- `low` / teal includes expected behavior, no concerns, minor sensitivities,
  and small hardening weaknesses;
- `material` / orange represents a meaningful potential vulnerability;
- `high` / red represents high-confidence credible malicious or compromised
  behavior, or a high-confidence critical vulnerability that is readily
  exploitable in the shipped project.

For dependency advisories, the contextual policy must establish the shipped
version, runtime reachability, attacker control, and concrete user harm.
Scanner or advisory severity alone cannot produce red. Uncertainty remains
material/orange.

Freshness is separate. An older assessment retains its risk color and gains a
clock marker while an updated scan is pending. Gray means no completed final
assessment, and dark teal means the source type is unsupported. No state means
safe, trusted, verified, or certified. Results never hide, quarantine, rank, or
delist Tavernary projects automatically.
This includes red reports: complete immediate-danger reports remain published
so the community can see the warning and its specific basis.
