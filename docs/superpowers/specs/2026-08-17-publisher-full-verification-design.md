# TavernKeeper Publisher Full Verification Design

**Status:** Approved on 2026-08-17

## Goal

Complete TavernKeeper's migration from deprecated GitHub App ID authentication
to the GitHub-recommended Client ID and provide repeatable live proof for both
protected Publisher environments and the protected `main` bypass.

## Client ID migration

Store `TAVERNKEEPER_PUBLISHER_CLIENT_ID` as a non-secret variable in both
`tavernkeeper-scanner` and `tavernkeeper-staff`. Every Publisher token step uses
`client-id: ${{ vars.TAVERNKEEPER_PUBLISHER_CLIENT_ID }}` with the existing
environment-scoped private key. The workflow-policy checker rejects `app-id`,
rejects the legacy App ID secret name, and still requires explicit owner,
repository, and Contents-write scoping.

The legacy `TAVERNKEEPER_PUBLISHER_APP_ID` secrets are removed only after all
migrated workflows are merged and both protected environments successfully mint
and use Client-ID-authenticated tokens.

## Verification workflow

Add an owner-only, input-free `publisher-verification.yml` workflow. The first
job runs in `tavernkeeper-scanner`, creates an empty audit commit, and pushes it
to protected `main`. The second job waits for the first, runs in
`tavernkeeper-staff`, checks out the now-current `main`, and repeats the empty
commit. Both jobs use only Contents-write App tokens, disable persisted checkout
credentials, use bounded non-force pushes, and rely on the action post step for
token revocation.

The staff deployment retains its existing MentallyQuill reviewer gate. The
scanner job's actor guard prevents contributors from using the canary as a
commit-spam surface.

## Policy and live proof

Existing parsed-workflow and policy-script tests enumerate both canary jobs and
all production mutation jobs. Tests require Client ID, the protected
environment, one token consumer, pinned actions, disabled checkout credentials,
and canonical push blocks.

After merge, approve the staff deployment, verify both App-authenticated commits
on `main`, confirm both tokens are revoked, and remove the obsolete App ID
secrets. A disposable ordinary-owner empty commit must be rejected by the
ruleset. Existing operational workflows remain deterministic and unchanged
apart from their authentication identifier.
