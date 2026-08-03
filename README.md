# TavernKeeper

TavernKeeper performs advisory, exact-commit security scans for public GitHub
repositories listed by [Tavernary](https://tavernary.org). It uses deterministic
scanners to locate candidates, reviews every candidate in its real file and
project context with a configured language model, and publishes immutable,
sanitized Technical Report V5 artifacts through GitHub Pages.

TavernKeeper does **not** certify that software is safe and does not assign the
color shown on Tavernary. Tavernary independently synthesizes each complete V5
report, applies non-lowerable risk floors, and presents `low`, `material`, or
`high` risk separately from report freshness.

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
- Scanner output locates review candidates; a keyword or scanner severity is
  not treated as a security conclusion.
- Every candidate receives one schema-validated contextual assessment bound to
  immutable evidence and locations. Missing review or scanner coverage produces
  no report.
- Published JSON and HTML exclude raw source excerpts, raw tool or model
  payloads, credentials, hidden reasoning, and runner-local paths.

## Operation

Tavernary owns catalog eligibility, exact GitHub identity and SHA, final risk
assessment, freshness, and card presentation. TavernKeeper owns isolated
acquisition, deterministic evidence collection, contextual review, backlog and
retry state, immutable Technical Report V5 publication, and technical history.
Input-free GitHub App wake-ups reduce latency in both directions; scheduled
reconciliation repairs missed wake-ups.

Only Tavernary staff can initiate a targeted scan, through Tavernary's
exact-GitHub-URL Action. TavernKeeper accepts only the authorized wake App's
repository-ID hint and resolves the repository again from Tavernary's public
manifest. Public Issues do not trigger scans. Automatic work is limited to five
repositories per batch and two concurrent repositories.

Provider configuration is model-agnostic. `TAVERNKEEPER_MODEL` selects the
configured OpenAI-compatible model without changing the report contract or
policy. A provider, token, context, validation, or required-scanner failure
cannot fall back to a degraded report. System failures retry at T+1, T+2, and
T+3 hours before TavernKeeper notifies staff and remains stopped.

The initial rollout is staff-paused in `operations/state.json`. See
[operations](docs/operations.md), [architecture](docs/architecture.md), and
[rule documentation](docs/rules.md).

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
