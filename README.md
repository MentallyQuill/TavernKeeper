# TavernKeeper

TavernKeeper performs advisory, exact-commit security scans for public GitHub
repositories listed by [Tavernary](https://tavernary.org). It runs a fixed,
versioned deterministic scanner policy and publishes immutable, sanitized
reports through GitHub Pages.

TavernKeeper does **not** certify that software is safe. A teal result means
only that every required scanner completed for the named commit without a
medium-or-higher finding at medium-or-higher confidence. A red result means
the completed scan produced at least one such finding. Tavernary derives
orange, gray, and unsupported presentation states locally.

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
- Required coverage cannot be silently skipped. Any incomplete scanner,
  validation, or publication operation produces no report.
- Published JSON and HTML contain normalized findings and coverage totals, not
  source excerpts, raw payloads, credentials, or runner-local paths.

## Operation

Tavernary owns the exact-SHA target manifest and the mapping from GitHub
repositories to cards. TavernKeeper owns scan policy, backlog and retry state,
immutable automated reports, and its Pages site. Input-free GitHub App wake-ups
reduce latency in both directions; scheduled reconciliation repairs missed
wake-ups.

Only Tavernary staff can initiate a targeted scan, through Tavernary's
exact-GitHub-URL action. TavernKeeper accepts only the authorized wake App's
repository-ID hint and resolves the repository again from Tavernary's public
manifest. Public Issues do not trigger scans. Automatic work is limited to five
repositories per batch and two concurrent repositories. System failures retry
at T+1, T+2, and T+3 hours before TavernKeeper notifies staff and remains
stopped. A degraded report is never published.

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
placement, checkout authentication, batch size, concurrency, and the direct
deterministic prepare-to-finalize path.

`npm run test:e2e` is an in-process hostile-data safety and publication gate.
It exercises inventory, classification, static rules, scan packaging,
authenticated artifact transport, V4 reporting, and publication against
hostile fixtures. Git history, external scanner adapters, and exact-HEAD
verification use deterministic test doubles; the real digest-pinned tools and
an exact validated checkout SHA remain release and live-canary gates.

## License

TavernKeeper is licensed under the GNU Affero General Public License v3.0. See
`LICENSE`.
