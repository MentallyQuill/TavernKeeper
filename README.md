# TavernKeeper

TavernKeeper performs advisory, exact-commit security scans for public GitHub
repositories listed by [Tavernary](https://tavernary.org). It uses deterministic
scanners to locate candidates, reviews every candidate in its real file and
project context with a configured language model, and publishes immutable,
sanitized Technical Report V5 artifacts through GitHub Pages.

TavernKeeper does **not** certify that software is safe and does not assign the
color shown on Tavernary. Tavernary independently synthesizes each complete V5
report, applies deterministic risk rules, and presents `low`, `material`, or
`high` risk separately from report freshness. `high` means immediate danger:
high-confidence credible malicious or compromised behavior, or a
high-confidence critical vulnerability that is readily exploitable in the
shipped project. Scanner severity or a critical dependency advisory alone is
not enough.

## Safety boundary

Target repositories are hostile data:

- TavernKeeper checks out one validated GitHub repository ID and exact SHA in a
  disposable GitHub-hosted runner.
- It never installs target dependencies or runs target scripts, builds, tests,
  hooks, Actions, macros, containers, or executables.
- It inventories without following links and rejects unsafe or ambiguous
  paths.
- It runs TavernKeeper-owned rules plus digest-pinned Gitleaks, Opengrep,
  OSV-Scanner, zizmor, and Malcontent adapters when applicable.
- Policy 5 inventories every committed JavaScript/TypeScript candidate,
  including minified distributions and vendored packages, then safely decodes,
  normalizes, unpacks, and rescans bounded derivative representations without
  executing target code.
- Scanner output locates review candidates; a keyword or scanner severity is
  not treated as a security conclusion.
- Every finding candidate receives one schema-validated assessment bound to
  immutable evidence and locations. Known bounded cases are decided by local
  policy; only ambiguous runtime or cross-boundary behavior reaches the model.
  Hard scan failures produce no
  report; bounded incomplete JavaScript coverage is published explicitly and
  remains visible without changing advisory color or concern counts.
- Published JSON and HTML exclude raw source excerpts, raw tool or model
  payloads, credentials, hidden reasoning, and runner-local paths.

## Operation

Tavernary owns catalog eligibility, exact GitHub identity and SHA, final risk
assessment, freshness, and card presentation. TavernKeeper owns isolated
acquisition, deterministic evidence collection, contextual review, backlog and
retry state, immutable Technical Report V5 publication, and technical history.
Input-free GitHub App wake-ups reduce latency in both directions; scheduled
reconciliation repairs missed wake-ups.

TavernKeeper maintains two durable scan slots. Each claimed repository runs in
its own reusable workflow and publishes its complete Technical Report V5 as
soon as that target finishes; it never waits for another repository or a batch
barrier. Publication removes a successful target from the durable queue, while
a failure clears its claim and rotates it behind the currently assigned queue.
A failure never creates an automatic pause or terminal retry; only an explicit
protected staff emergency stop can suspend scheduling.

Only Tavernary staff can initiate a targeted scan, through Tavernary's
exact-GitHub-URL Action. TavernKeeper accepts only the authorized wake App's
repository-ID hint and resolves the repository again from Tavernary's public
manifest. Public Issues do not trigger scans. Committed claim leases enforce a
global limit of two concurrently scanned repositories across every wake-up.
Due staff-requested scans run before ordinary due tickets. They do not bypass
an emergency stop, automatic recovery hold, retry cooldown, exact-SHA checks,
claim capacity, or concurrency limit.

Provider configuration is model-agnostic. `TAVERNKEEPER_MODEL` selects the
configured OpenAI-compatible reviewer without changing the report contract or
policy. `JSONREPAIR_*` configures GPT-5.6 Luna for one binding-patch request
only after the primary reviewer returns an otherwise complete response that
still fails evidence-ID or location validation. Luna receives no source, file
paths, line numbers, or narrative fields and cannot perform review, create
findings, change risk, or write summaries. A provider, token, context,
validation, or required-scanner
failure cannot fall back to a degraded report. Failed projects cool down for 5
minutes, 30 minutes, 2 hours, and then 6 hours capped indefinitely. The fifth
consecutive failure marks a chronic operational incident but the project stays
in the current queue and continues retrying automatically. Queue state retains
only the latest four sanitized failure categories, never raw scanner or model
output. Chronic Issues use repository ID plus exact commit as their stable
identity, so a changing failure category updates one incident instead of
creating duplicates.

When a contextual model response violates the bounded schema, every configured
immediate attempt receives only the rejected field category as corrective
feedback. Rejected prose is never echoed into the review prompt or persisted.
After those attempts, the optional one-call Luna path can replace only a
candidate's evidence hashes or drop an optional observation whose evidence or
location is invalid; deterministic validation still decides whether the
original review is accepted.

Automatic eligibility continuously reconciles every Tavernary target to a
preferred report for the exact current target SHA, scanner policy, and
contextual-review policy. Protected staff and policy work runs first, followed
by new submissions, updates, the frozen one-time coverage cohort, and all other
missing or stale exact tuples. Updated and coverage targets observe a rolling
seven-day cooldown; durable retry and provider-hold deadlines remain authoritative.
See
[operations](docs/operations.md), [architecture](docs/architecture.md),
[scanning policy](docs/SCANNING.md), and [rule documentation](docs/rules.md).

Every scan reruns the complete deterministic scanner suite. Policy 5 first
classifies execution scope and resolves bounded advisories, known workflow
rules, inert tooling signals, and low local robustness issues without a model.
Only contextual-model groups are cacheable, and only when the full evidence
group and review identity have the same content digest and every reused
assessment remains low-risk with exposure not demonstrated. Material,
high-risk, demonstrated, changed, or unverifiable groups always receive fresh
model review. A missing, stale, malformed, or mismatched cache is only a cache
miss and cannot suppress scanning or review.
Reports publish fresh/reused group and candidate counts plus source report IDs,
while each repository's atomically replaced `review-cache.json` points back to
the immutable source report. Fresh misses are reviewed in conservative input-
and output-token-bounded calls of at most five evidence groups. Every group
keeps an independent response identity and validator, only failed group entries
retry, and reports expose estimated and actual token usage for each model
batch.

Fresh contextual work is capped per target at 12 behavior cases, 6 provider
calls including repairs, 200,000 estimated input tokens, 250,000 actual input
tokens, and 40,000 output tokens. Preflight or cumulative overflow fails the
target before another provider request and publishes no report.

Every complete report remains public regardless of risk. An immediate-danger
report is an awareness signal, never an automatic hide, quarantine, ranking,
or delisting instruction.

## Local verification

Requires Node.js 24.

```text
npm ci
npm run check
npm run test:e2e
npm run build
```

Scanner binaries used in Actions are version- and digest-pinned in
`config/scanners.v1.json`. `npm run workflows:check` separately enforces
triggers, permissions, action pins, secret placement, Publisher-token
placement, checkout authentication, claim capacity, concurrency, and the
required prepare-review-publish boundary.

`npm run test:e2e` is an in-process hostile-data safety and publication gate.
It exercises inventory, classification, scanner evidence, contextual review,
Scan Package binding, authenticated artifact transport, V5 reporting, and
publication against hostile fixtures. Git history, external scanner adapters,
model transport, and exact-HEAD verification use controlled test doubles; the
real configured provider, digest-pinned tools, and an exact validated checkout
remain release and live-canary gates.

## License

TavernKeeper is licensed under the GNU Affero General Public License v3.0. See
`LICENSE`.
