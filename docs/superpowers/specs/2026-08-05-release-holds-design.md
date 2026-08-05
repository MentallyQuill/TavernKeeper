# Release Holds Workflow Design

## Goal

Provide an explicit, staff-gated GitHub Action that clears TavernKeeper's automatic recovery holds and immediately restarts backlog reconciliation.

## Design

Add a dedicated workflow named `Release Holds`. It runs only through `workflow_dispatch`, shares the `tavernkeeper-global-scan` concurrency group, and requires the existing `tavernkeeper-staff` environment. The workflow checks out trusted `main`, applies a validated `release-holds` operation through the existing retry CLI, commits the resulting operational state with the TavernKeeper publisher app, and dispatches `reconcile.yml`.

The state operation clears every entry in `automatic_holds`, updates `updated_at`, and preserves the emergency stop, scan queue, retry histories, active scans, and policy campaigns. It is idempotent: invoking it when no holds exist produces no state commit but still dispatches reconciliation.

## Safety and failure behavior

- The action does not erase queued targets or their failure evidence.
- The action does not override a staff emergency stop.
- Repository writes use the existing publisher-app credential boundary.
- The staff environment remains the authorization gate.
- A failed state mutation or failed push stops the workflow before reconciliation.
- Reconciliation may recreate a hold if the shared dependency is still failing; that is expected circuit-breaker behavior.

## Verification

Unit coverage proves the state transition clears only automatic holds. CLI coverage proves `release-holds` is accepted. Workflow coverage proves the action is manual, staff-gated, concurrency-safe, idempotent at commit time, and dispatches reconciliation. The repository's typecheck, unit suite, workflow-policy check, and build must pass before publication.
