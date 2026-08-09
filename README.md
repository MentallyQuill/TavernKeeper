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
- Policy 4 inventories every committed JavaScript/TypeScript candidate,
  including minified distributions and vendored packages, then safely decodes,
  normalizes, unpacks, and rescans bounded derivative representations without
  executing target code.
- Scanner output locates review candidates; a keyword or scanner severity is
  not treated as a security conclusion.
- Every finding candidate receives one schema-validated contextual assessment
  bound to immutable evidence and locations. Hard scan failures produce no
  report; bounded incomplete JavaScript coverage is published explicitly and
  prevents an otherwise-low advisory from appearing low.
- Published JSON and HTML exclude raw source excerpts, raw tool or model
  payloads, credentials, hidden reasoning, and runner-local paths.

## Operation

Tavernary owns catalog eligibility, exact GitHub identity and SHA, final risk
assessment, freshness, and card presentation. TavernKeeper owns isolated
acquisition, deterministic evidence collection, contextual review, backlog and
retry state, immutable Technical Report V5 publication, and technical history.
Input-free GitHub App wake-ups reduce latency in both directions; scheduled
reconciliation repairs missed wake-ups.

Every selected repository finishes independently inside its bounded batch.
The serialized publisher keeps every complete Technical Report V5 candidate,
publishes the valid subset atomically, removes successful targets from the
durable queue, and rotates every unsuccessful target behind the currently
assigned queue. A failure never creates an automatic pause or terminal retry;
only an explicit protected staff emergency stop can suspend scheduling.

Only Tavernary staff can initiate a targeted scan, through Tavernary's
exact-GitHub-URL Action. TavernKeeper accepts only the authorized wake App's
repository-ID hint and resolves the repository again from Tavernary's public
manifest. Public Issues do not trigger scans. Automatic work is limited to five
repositories per batch and two concurrent repositories.
Due staff-requested scans run before ordinary due tickets. They do not bypass
an emergency stop, automatic recovery hold, retry cooldown, exact-SHA checks,
batch limit, or concurrency limit.

Provider configuration is model-agnostic. `TAVERNKEEPER_MODEL` selects the
configured OpenAI-compatible model without changing the report contract or
policy. A provider, token, context, validation, or required-scanner failure
cannot fall back to a degraded report. Failed projects cool down for 5 minutes,
30 minutes, 2 hours, and then 6 hours capped indefinitely. The fifth
consecutive failure marks a chronic operational incident but the project stays
in the current queue and continues retrying automatically. Queue state retains
only the latest four sanitized failure categories, never raw scanner or model
output. Chronic Issues use repository ID plus exact commit as their stable
identity, so a changing failure category updates one incident instead of
creating duplicates.

When a contextual model response violates the bounded schema, its next
immediate attempt receives only the rejected field category as corrective
feedback. Repeated identical violations stop early; rejected prose is never
echoed into the prompt or persisted.

Initial V3 catalog coverage follows Tavernary's complete popularity rank.
TavernKeeper temporarily accepts V2 manifests with the legacy Top-30/new/old
fallback during rollout. Durable tickets preserve that initial order: a failed
project receives a new tail ticket, and projects discovered later receive still
higher tickets, so neither can starve the other. See
[operations](docs/operations.md), [architecture](docs/architecture.md),
[scanning policy](docs/SCANNING.md), and [rule documentation](docs/rules.md).

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
placement, checkout authentication, batch size, concurrency, and the required
prepare-review-finalize boundary.

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
