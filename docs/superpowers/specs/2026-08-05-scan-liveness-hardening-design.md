# Scan Liveness Hardening Design

**Status:** Approved for implementation on 2026-08-05
**Scope:** Deterministic recovery wake-up, bounded contextual-review execution, catalog-first queue ordering, and prepare-stage failure attribution

## Problem

The scan-reliability repair prevents known publisher, OpenGrep, and contextual-review failures, but live reconciliation exposed four remaining liveness gaps:

1. A reconciliation run with no currently runnable probe terminates after planning and relies on `retry.yml`. Although that workflow is configured for every five minutes, its live scheduled executions are irregular and can be hours apart.
2. Contextual model requests may each wait up to fifteen minutes while the complete review step has a sixteen-minute ceiling. GitHub can kill the step before the CLI writes a sanitized failure, producing a global `SCAN_PHASE_FAILED/security/orchestrator` hold and discarding session-local progress.
3. Due retry tickets sort ahead of untouched catalog entries. Repeatedly failing repositories can therefore consume the next batches while clean catalog work remains.
4. An unexpected exception inside an individual scanner is reduced to prepare-wide `CLI_FAILED/orchestrator`, which avoids sensitive details but does not identify the scanner that needs repair.

## Goals

- Guarantee a bounded future reconciliation attempt whenever committed state has a `next_wake_at`, without depending solely on GitHub's scheduled workflow cadence.
- Let a long contextual review checkpoint and resume once inside the same job, while ensuring a hard execution cutoff produces a target-local sanitized failure.
- Run staff requests first, then untouched or changed catalog entries, then retries, retaining ticket order inside each lane.
- Convert otherwise-untyped scanner adapter failures into target-local, scanner-specific failures without exposing repository or process output.
- Ship these changes with the previously verified publisher ordering, OpenGrep limited-coverage, phase attribution, and contextual checkpoint repair.

## Non-goals

- Adding an external scheduler, queue, database, or long-lived service.
- Uploading contextual prompts, source excerpts, provider responses, or plaintext checkpoint files.
- Treating malformed scanner output, unknown OpenGrep diagnostics, or incomplete model coverage as success.
- Removing automatic holds for genuine shared provider or security-boundary failures.
- Rewriting current production queue or hold state by hand.

## Deterministic Delayed Wake

Add a dedicated `delayed-wake.yml` workflow. It accepts one required `wake_at` UTC timestamp, validates it as an exact ISO instant, calculates the remaining delay, sleeps for at most 20,400 seconds, and dispatches `reconcile.yml` on `main`. If the requested instant is farther away, the dispatched reconcile will calculate and schedule the next bounded segment.

The wake workflow has its own concurrency group with `cancel-in-progress: true`. A newer plan therefore replaces an older sleeping wake with the latest committed `next_wake_at`, while never holding the global scan concurrency group.

The reconcile planning job receives `actions: write`. When planning returns no scan requests, a nonzero remaining queue, and a nonempty `next_wake_at`, it dispatches the delayed-wake workflow. Existing immediate continuation remains unchanged for batches that actually run.

The five-minute scheduled retry remains as defense in depth, but it is no longer the sole liveness mechanism.

## Bounded Contextual Review

Reduce the per-provider request timeout from 900,000 milliseconds to 300,000 milliseconds so three immediate attempts can finish within a bounded invocation.

The review workflow step gains a forty-two-minute outer ceiling. Each invocation is wrapped by GNU `timeout` with a twenty-minute ceiling and a ten-second termination grace period. Before each invocation, the workflow writes a fixed sanitized sentinel:

```json
{
  "code": "MODEL_REVIEW_TIMEOUT",
  "domain": "target",
  "component": "contextual-model"
}
```

The CLI atomically replaces that sentinel when it catches a more specific failure. A first `MODEL_PROVIDER/shared/contextual-model` failure or an unchanged timeout sentinel receives exactly one second invocation. The second invocation validates and resumes `review-progress.json`; successful completion removes the sentinel. Any second failure ends the phase with its bounded record.

The outer GitHub timeout remains a final fail-closed boundary, but the two internal ceilings leave enough time for transition and encrypted-artifact cleanup.

## Catalog-First Queue Ordering

Available entries sort by:

1. explicit staff request before ordinary work;
2. zero consecutive failures before retry entries;
3. durable ticket ascending.

Cooldowns remain authoritative. An automatic shared recovery hold still admits only one probe, but that probe prefers clean catalog work and clears only the exact recovery fingerprint on success. Retry entries retain their complete failure history and remain queued for the later sweep.

## Scanner-Specific Unexpected Failures

`runApplicableScanners` wraps each external scanner invocation independently. Existing `ScannerError` instances remain authoritative. Any other thrown value becomes `SCANNER_FAILED/repository/<scanner>` with a fixed body-free message. This keeps a target-specific scanner incompatibility out of shared holds while making the failing component actionable.

Inventory, checkout, history, evidence-context, validation, and finalization contracts remain unchanged. The CLI-level prepare fallback remains the last target-local boundary for errors outside an individual scanner invocation.

## Security and Compatibility

- The delayed-wake input is data, never executable shell text, and is parsed by Node before sleeping.
- Wake and scan workflows receive only the permissions they require.
- The timeout sentinel, progress file, and phase errors contain no prompts, excerpts, paths, response bodies, or secrets.
- Public Report V5 and Tavernary's copied schema remain unchanged.
- Unknown or malformed scanner/model output remains fail-closed.

## Verification

- A future `next_wake_at` with an empty plan dispatches `delayed-wake.yml`; its delay is nonnegative and capped at 20,400 seconds.
- A replacement delayed wake cancels the older wake without affecting global scan concurrency.
- Review workflow policy proves two maximum invocations, the timeout sentinel, the 300,000 millisecond provider limit, and the forty-two-minute outer ceiling.
- A hard first-invocation timeout preserves progress for the second invocation and cannot become a global security hold.
- Clean entries precede retries in ordinary planning and automatic probes; staff requests still precede both.
- Untyped failures from each scanner become target-local and retain the exact scanner component; typed scanner failures are unchanged.
- Full formatting, typecheck, unit tests, workflow policy, build, generated-schema compatibility, and diff checks pass.

## Rollout

Commit the complete repair on a protected feature branch, open a pull request, wait for required checks, and merge through the protected-main path. After merge, verify the exact main SHA and ordinary reconcile execution. Observe a parser-limited target, a provider/timeout recovery, committed state advancement, delayed-wake behavior, and continued clean-catalog progress. Do not manually edit the production queue or holds.
