# TavernKeeper Publisher App Design

**Status:** Approved on 2026-08-01

**Repository:** `MentallyQuill/TavernKeeper`

## Purpose

TavernKeeper publishes immutable scan reports and secret-free operational state directly to its normal `main` branch. Ordinary contributors and repository automation must use pull requests and pass CI, while this narrow generated-data path must remain automatic. A dedicated GitHub App provides that one direct-write identity without giving either cross-repository wake App contents access.

## App boundary

The GitHub App is named `TavernKeeper Publisher`. It is installed only on `MentallyQuill/TavernKeeper` and receives only:

- Repository metadata: read, as required by GitHub.
- Repository contents: read and write.

It receives no Actions, Issues, Pages, Administration, Pull requests, or cross-repository permission. Its private key and App ID are stored as `TAVERNKEEPER_PUBLISHER_APP_PRIVATE_KEY` and `TAVERNKEEPER_PUBLISHER_APP_ID` in both protected TavernKeeper environments: `tavernkeeper-scanner` and `tavernkeeper-staff`. They are not repository-level secrets.

Each mutation job creates a short-lived installation token with the pinned `actions/create-github-app-token` action, explicitly scopes it to owner `MentallyQuill` and repository `TavernKeeper`, and requests only `permission-contents: write`. Checkout never persists the workflow token. The commit step authenticates Git with the App token immediately before pushing.

The App token is used by exactly these mutation jobs:

| Workflow | Job | Mutation |
| --- | --- | --- |
| `reconcile.yml` | `publish` | reports and `operations/state.json` |
| `deep-scan.yml` | `scan` | staff deep-scan report and state |
| `adjudicate.yml` | `adjudicate` | superseding report, state, dismissal rules |
| `policy-rescan.yml` | `schedule` | policy campaign state |
| `staff-operations.yml` | `operate` | pause, resume, and retry state |

Publisher authentication is fail-closed. A missing secret, invalid key, missing installation, token failure, rejected push, or ruleset rejection fails the job. No workflow falls back to `GITHUB_TOKEN` for a contents write and no degraded report is published.

## Separation from wake Apps

The two bridge Apps remain independent:

- `Tavernary Wake TavernKeeper` is installed only on TavernKeeper and can dispatch Actions only.
- `TavernKeeper Wake Tavernary` is installed only on Tavernary and can dispatch Actions only.
- `TavernKeeper Publisher` is installed only on TavernKeeper and can write Contents only.

The Publisher App cannot dispatch workflows. When publication must continue the TavernKeeper queue, the workflow uses a separate step with repository-local `GITHUB_TOKEN` and `actions: write`. That token retains `contents: read`. Cross-repository wake tokens never appear in mutation jobs.

## Main-branch ruleset

An active repository ruleset named `Protect main; allow TavernKeeper Publisher` targets only `~DEFAULT_BRANCH` and:

- requires all ordinary changes to arrive through a pull request;
- requires the `check` status from GitHub Actions integration ID `15368` against the latest main;
- blocks branch deletion;
- blocks non-fast-forward pushes;
- grants an `always` bypass only to the `TavernKeeper Publisher` Integration actor.

There is no user, administrator, generic GitHub Actions, role, team, or wake-App bypass. The Publisher App cannot force-push or delete because the workflows issue an ordinary `git push origin HEAD:main` and the App lacks Administration permission.

## Policy enforcement

Repository tests and `scripts/check-workflow-policy.mjs` enforce the boundary:

- all external Actions are pinned to 40-character commit SHAs;
- mutation workflows expose `contents: read` through `GITHUB_TOKEN`;
- every direct push job creates a Publisher App token in the same protected environment;
- every checkout in a mutation job uses `persist-credentials: false`;
- every push step uses `steps.publisher-token.outputs.token` and never `github.token`;
- publisher secrets occur only in the token-creation step;
- continuation dispatches occur in separate Actions-only steps;
- configured model secrets remain confined to the model-review step.

## Rollout order

1. Create and install both Actions-only wake Apps and store their credentials only in their source repositories.
2. Create and install `TavernKeeper Publisher`; store its credentials only in the two protected TavernKeeper environments.
3. Land the tested workflow migration while `main` is not yet ruleset-protected.
4. Create and verify the active ruleset with only the Publisher App bypass.
5. Resume scanning and run the approved Wandlight canary, then Recursion.
6. Verify report publication, Tavernary wake/import, exact-SHA summaries, and live cards before clearing the initial rollout pause.

