# TavernKeeper

TavernKeeper performs advisory, exact-commit security scans for public GitHub repositories listed by [Tavernary](https://tavernary.org). It combines deterministic security tools with a required, configurable OpenAI-compatible model review, then publishes immutable, sanitized reports through GitHub Pages.

TavernKeeper does **not** certify that software is safe. A teal result means only that every required deterministic scanner plus analyzer, challenger, and arbiter call completed for the named commit without a confirmed review-level concern. A red result means the completed scan confirmed at least one review-level concern. Tavernary derives orange, gray, and unsupported presentation states locally.

## Safety boundary

Target repositories are treated as hostile data:

- TavernKeeper checks out one validated GitHub repository ID and exact SHA in a disposable GitHub-hosted runner.
- It never installs target dependencies or runs target scripts, builds, tests, hooks, Actions, macros, containers, or executables.
- It inventories without following links and rejects unsafe or ambiguous paths.
- Required deterministic coverage cannot be silently skipped.
- Analyzer, challenger, and arbiter review must cover every selected chunk and preserve deterministic evidence identity.
- Any incomplete scanner, model, quota, token, validation, or publication operation produces no report.
- Published JSON and HTML contain normalized findings and coverage totals, not source excerpts, raw payloads, credentials, or local paths.

## Operation

Tavernary owns the exact-SHA target manifest and the mapping from GitHub repositories to cards. TavernKeeper owns scan policy, backlog/retry state, immutable automated reports, and its Pages site. Input-free GitHub App wake-ups reduce latency in both directions; scheduled reconciliation repairs missed wake-ups.

Three single-repository GitHub Apps keep authority separate. Each bridge App can dispatch Actions only in its one destination repository. The dedicated `TavernKeeper Publisher` App is installed only on TavernKeeper and can write repository contents but cannot dispatch Actions. Protected mutation jobs create short-lived Publisher installation tokens; TavernKeeper's workflow-local token remains contents-read.

Only Tavernary staff can initiate targeted standard scans, through Tavernary's exact-GitHub-URL action; TavernKeeper accepts only the authorized wake App's repository-ID hint. Public Issues do not trigger scan workflows. Automatic work is limited to five repositories per batch and two concurrent repositories. A system/provider failure pauses normal scanning; the initial attempt is followed by three retries at one-hour intervals, and TavernKeeper staff are notified only after the third retry fails. TavernKeeper never publishes a reduced-coverage report.

The initial rollout is intentionally staff-paused in `operations/state.json`. See [operations](docs/operations.md), [architecture](docs/architecture.md), and [rule documentation](docs/rules.md).

## Local verification

Requires Node.js 24.

```text
npm ci
npm run check
npm run test:e2e
npm run build
```

Scanner binaries used in Actions are version- and digest-pinned in `config/scanners.v1.json`. `npm run workflows:check` separately enforces trigger, permission, action-pin, model-secret placement, Publisher-token placement, checkout authentication, batch-size, and concurrency policy.

`npm run test:e2e` is an in-process hostile-data safety and publication gate. It exercises real inventory, classification, static-rule, redaction, chunking, authenticated artifact transport, and publication behavior against hostile fixtures, but deliberately replaces Git history, external scanner adapters, exact-HEAD verification, and provider transport with deterministic doubles. Unit and contract tests cover those scanner adapters and model transport. Real pinned tools, provider behavior, and an exact validated checkout SHA are release and live-canary gates, not claims made by the fixture suite.

## License

TavernKeeper is licensed under the GNU Affero General Public License v3.0. See `LICENSE`.
