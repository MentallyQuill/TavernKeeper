# Progress-Aware Contextual Review Cutoff Design

**Status:** Approved for implementation on 2026-08-06
**Scope:** Contextual-review retry liveness inside the existing scan-and-publish workflow

## Problem

The production workflow gives each repository up to three twenty-minute contextual-review passes. Checkpointed progress makes that budget useful for large repositories, but a repository that completes no evidence group can consume the full sixty-minute retry window. Because batch publication waits for every matrix job, one non-progressing target delays completed outcomes and catalog continuation.

The current Lumiverse run demonstrates this gap: the other matrix targets completed, while one contextual-review step held the batch after its first twenty-minute boundary.

## Decision

Retain three passes only while sanitized checkpoint progress advances. Before and after every invocation, read only the count of `completed_group_ids` from the session-bound `review-progress.json` file.

- A successful invocation finishes normally.
- A `MODEL_REVIEW_TIMEOUT/target/contextual-model` failure retries only when the completed-group count increased during that pass.
- A `MODEL_PROVIDER/shared/contextual-model` failure may receive one no-progress retry for a transient provider interruption. Further retries require checkpoint advancement.
- Every other failure remains non-retryable.
- The existing maximum of three passes, twenty-minute command timeout, and sixty-two-minute outer ceiling remain fail-closed boundaries.

When a timeout makes no progress, the existing sanitized sentinel is encrypted and published as a target-local failure. The target remains in the durable retry queue while the completed batch publishes and catalog continuation proceeds.

## Security and Compatibility

The workflow reads only a numeric completed-group count through a dedicated helper that suppresses checkpoint-derived parse and validation errors. It does not print, upload, or persist checkpoint narratives, paths, prompts, provider bodies, or source excerpts. Malformed checkpoint files remain fail-closed without echoing their content.

The final checkpoint remains in the ephemeral session after `review.json` is written and is removed with the session during finalization. This closes the timeout boundary where the completed review exists but the process has not yet returned: a timeout still sees the final progress count and safely retries into the existing validated review. Public Report V5, operations-state V3, and Tavernary contracts do not change.

## Verification

- Workflow tests reject timeout retry logic that ignores checkpoint progress.
- Workflow tests require exactly one no-progress provider retry.
- Workflow policy rejects removal of the progress counter or no-progress cutoff.
- Executable tests prove malformed checkpoint content never reaches stdout or stderr.
- Session tests prove the final checkpoint survives review completion until finalization.
- Existing bounded timeout, checkpoint privacy, encrypted outcome, publication, and continuation tests remain green.
- Full repository checks, build, and workflow policy pass.
- After protected-main merge, a normal reconcile run publishes completed outcomes and advances the durable queue without allowing a no-progress target to occupy all three passes.
