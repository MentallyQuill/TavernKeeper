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
  -> TavernKeeper selects at most 2 due targets in ticket order
  -> at most 2 credential-free prepare jobs run concurrently
  -> exact checkout and portable-path inventory
  -> history, pinned scanners, and policy-5 JavaScript derivative analysis
  -> normalized candidates and deterministic Scan Package digest
  -> bounded file context and conservative execution scope for every candidate
  -> target checkout deleted; prepared-${repository_id} GitHub artifact
  -> fresh review job validates the artifact without target source
  -> deterministic policy resolves bounded known cases
  -> configured model reviews only ambiguous contextual behavior within hard budgets
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

Policy 5 retains policy 4's treatment of every inventoried JavaScript and TypeScript path as a scan
candidate, including committed dependencies, generated bundles, and minified
distributions. Repository OpenGrep must account for the exact raw path set.
Literal-only decoders and trusted, non-executing webcrack normalization produce
bounded derivatives; signatures, JS-X-Ray, and OpenGrep rescan every novel
representation. Only original repository paths and fixed provenance survive.
The complete pipeline and limits are in [`SCANNING.md`](SCANNING.md).

The normalized evidence set becomes Scan Package V1. Package and policy digests
bind each report to its evidence and rule versions. Deterministic scanners are
candidate locators, not verdict engines. Every candidate is grouped with
bounded source context, related data-flow evidence, project-purpose metadata,
and a versioned SillyTavern ecosystem context. Repository text is explicitly
untrusted and cannot override the reviewer prompt or response contract.

Provider secrets exist only in the fresh contextual-review job. The
credential-free prepare job cannot read model, artifact-encryption, or
Publisher credentials. Its target checkout is deleted before the bounded
`prepared-${repository_id}` GitHub artifact is uploaded. The review job has no
target checkout path and restores only validated redacted evidence. The model
is selected through runtime configuration; model choice cannot change the
accepted assessment vocabulary, coverage rules, evidence binding, or V5 report
schema. Raw provider responses and hidden reasoning are never persisted or
published.

## Atomic reporting

Every required scanner must produce a validated result, and every finding
candidate must receive exactly one valid deterministic-policy or contextual-model
assessment. Bounded policy-5 JavaScript limitations publish as explicit
`incomplete` coverage.
Findings on non-text artifacts publish verified scanner metadata as
`completed-with-limitations` contextual evidence without sending raw binary to
the model. Both limitations remain visible without altering advisory color or
concern counts. Hard scanner or integrity failures still produce no report.
TavernKeeper attaches each
assessment's location from validated deterministic candidate evidence instead
of asking the model to reproduce it. Model-authored observation locations must
still match supplied source context. Evidence validation proves cited paths,
line ranges, identities, content mappings, coverage, and the scanned SHA.
TavernKeeper rechecks exact HEAD before finalization. A tool, provider, context,
review, quota, evidence, schema, sanitizer, or publication failure yields no
report for that repository and enters the retry path.

Committed `active_scans` claims provide two global scan slots with two-hour
leases. Each target runs in its own reusable workflow and publishes immediately
after its review succeeds. Claim and publication commits replay their
deterministic state transition after an optimistic push conflict, so overlapping
wake-ups cannot overfill the slots or discard a completed report. Committed
publisher state, not child-workflow or Pages status, drives continuation. A
separate scheduled reconciler repairs Pages drift without holding the scan
queue.

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

OpenGrep exposes bounded `parser_syntax` and `rule_timeout` categories.
Non-text findings remain evidence candidates with an explicit metadata-only
coverage limitation. Model schema retries receive the rejected field category
only; identical corrective feedback is not retried indefinitely.

Operations state schema V3 persists one monotonic ticket ledger. A target is
current only when one preferred report matches its exact manifest SHA, scanner
policy, and contextual-review policy. Reconciliation admits every missing exact
tuple. Catalog observation preserves higher-priority new and updated provenance;
selection order is staff and policy work, new submissions, updates, frozen
coverage work, then the ordinary freshness tail. Failure and provider-hold
deadlines remain authoritative.

The coverage workflow calculates one fresh, fixed campaign from Tavernary's
current top 20 projects by popularity plus latest 20 stable GitHub releases.
The deduplicated membership is committed under campaign V2 and does not drift
as catalog rankings or release dates change.

Reports are addressed by provider, immutable GitHub repository ID, exact SHA,
scanner and contextual-policy versions, and report version. Each claimed target
uses a one-day secret-free GitHub artifact between prepare and review, then an
authenticated encrypted artifact between review and publication. Its publisher
decrypts in ephemeral storage, validates the complete outcome, writes immutable
V5 JSON and script-free HTML plus repository history, updates the preferred V5
index and the repository's bounded `review-cache.json`, clears the target's
claim, and rolls back partial writes on failure.

Report version and supersession form one repository-global monotonic chain. A
new request advances the current preferred repository report even when its SHA
or policy changes. The publisher validates that exact next version and
predecessor before any immutable write, while target and policy remain immutable
report-address dimensions.

Deterministic scanners always run from scratch for every target. Model-review
reuse is a separate optimization keyed by a canonical digest of the complete
evidence group and the scanner, tool, contextual-policy, prompt, assessment,
provider, endpoint-origin, and model identity. Group IDs, target SHA, raw source
bytes, and representation hashes are excluded only where the canonical input
already binds their relevant semantic content. Candidate IDs must still match
exactly. Only complete contextual-model groups whose assessments and observations are all
`low` with `risk_exposure: not_demonstrated` enter the cache; material, high,
demonstrated, partial, or invalid results never do.

JS-X-Ray warnings are normalized into path-, rule-, and
representation-specific review families before contextual review. The family
keeps every occurrence location for evidence-window construction, while one
assessment replaces repetitive per-occurrence prose. Public JavaScript
coverage reports both raw warning occurrences and resulting review-family
counts. Other scanner origins are never folded into these families.

The policy-5 migration intentionally has no earlier-policy cache compatibility,
so the first policy-5 contextual pass is cold. Cache absence, corruption, identity drift,
source-report mismatch, or per-group validation failure becomes a miss and
sends the group to the model. It never removes a scanner result. Technical
Report V5 records fresh and reused group/candidate counts and all immutable
source report IDs used. Cache misses are packed into input- and
output-token-bounded calls of at most five groups; each response remains
independently bound and replayed per group, and only invalid or missing entries
are retried. Technical Report V5 also records estimated and actual usage for
every batch, making every saved model call auditable.

Every direct write to `main` uses the dedicated Publisher App. Checkout
credentials are never persisted, `GITHUB_TOKEN` retains contents-read, and
Publisher authentication failure stops the mutation with no fallback.

## Risk and public states

TavernKeeper publishes complete technical evidence and per-item contextual
recommendations (`low`, `material`, or `high`), but it does not assign the
project's public color. Tavernary's separate strict synthesis applies
deterministic minimum-risk floors and produces the final project assessment:

- `low` / teal includes expected behavior, minor security hygiene, coverage
  limitations, risk whose exposure or reachability is not demonstrated, and
  recoverable local/self slowdowns, memory or CPU spikes, frozen tabs, client
  crashes, restarts, or loss of unsaved generated content;
- `material` / yellow represents a high-confidence, demonstrated,
  non-malicious vulnerability in shipped or executable behavior with a
  plausible path to meaningful harm such as credential theft, private-content
  exfiltration, persistent saved-data damage, unauthorized persistence,
  arbitrary code execution, or cross-user/system harm; and
- `high` / red represents high-confidence demonstrated malicious or
  compromised behavior, or a demonstrated critical vulnerability that is
  readily exploitable in the shipped project.

For dependency advisories, the contextual policy must establish the shipped
version, runtime reachability, attacker control, and concrete user harm.
Scanner or advisory severity alone cannot produce red. Uncertainty remains
teal with its findings and limitations visible.

Freshness is separate. An older assessment retains its risk color and gains a
clock marker while an updated scan is pending. Gray means no completed final
assessment, and dark teal means the source type is unsupported. No state means
safe, trusted, verified, or certified. Results never hide, quarantine, rank, or
delist Tavernary projects automatically.
This includes red reports: complete immediate-danger reports remain published
so the community can see the warning and its specific basis.
