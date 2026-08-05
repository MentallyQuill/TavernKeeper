# Scan Reliability Repair Design

**Status:** Approved for implementation on 2026-08-05
**Scope:** Publisher state transitions, failure attribution, bounded OpenGrep partial coverage, and contextual-review recovery

## Problem

Repositories are repeatedly returning to the durable queue even though the configured model provider is available. Production evidence identifies three independent liveness failures:

1. The publisher applies outcomes in request order even though scan jobs finish in a different order. Two shared failures with the same fingerprint can therefore be recorded newest-first and oldest-second. The automatic-hold invariant then rejects `last_failed_at < first_failed_at`, the publisher exits before committing state, and the stale queue replays the whole batch.
2. OpenGrep treats known per-file syntax failures and bounded rule timeouts as total scanner failures even when its JSON output contains valid findings from the rest of the repository.
3. Contextual review discards completed evidence groups when a later model request fails. Repeated schema diagnostics also stop one attempt early, and most repair prompts do not explain the rejected field's exact contract.

Generic CLI exceptions compound the problem by becoming shared `CLI_FAILED/orchestrator` failures even when the failing phase is repository-local.

## Goals

- Make publication independent of artifact completion order.
- Attribute otherwise-untyped failures to the phase that owns them without exposing error text.
- Publish honest reports for repositories where OpenGrep completed only bounded portions of its work.
- Preserve completed contextual-review groups across a bounded retry of the review command.
- Keep unknown scanner diagnostics, malformed output, invalid evidence, and report finalization fail-closed.

## Non-goals

- Treating an unavailable scanner, malformed JSON, unknown diagnostic, or process-level timeout as successful coverage.
- Publishing a report with incomplete contextual assessment coverage.
- Persisting model prompts, repository excerpts, provider response bodies, or secrets in artifacts or repository state.
- Adding an external queue, database, or long-lived runtime service.
- Changing risk vocabulary or synthesis rules.

## Stage 1: Publisher and failure attribution

Automatic recovery holds become order-independent. For a repeated fingerprint, `first_failed_at` is the minimum observed timestamp, `last_failed_at` is the maximum, and `next_probe_at` is calculated from the maximum timestamp and updated failure count. This preserves the state invariant regardless of request or artifact ordering.

CLI sanitization accepts a bounded phase fallback. Typed and allowlisted failure descriptors remain authoritative. Only an otherwise-untyped exception uses the supplied fallback:

- prepare: target / orchestrator;
- review: target / contextual-model;
- finalize: target / finalization;
- publish: shared / publication.

The fallback contains only an allowlisted domain and component. Exception messages, stacks, response bodies, paths, and provider fields remain absent from the transition artifact.

## Stage 2: Honest partial OpenGrep coverage

Tool coverage gains a backward-compatible `completed-with-limitations` status and an optional bounded `limitations` list. The only limitation codes initially supported are `parser_syntax` and `rule_timeout`.

OpenGrep may return completed-with-limitations only when all reported errors are one of:

- the parser warnings already accepted by scanner policy 3;
- warning code 3 with exact type `Syntax error`;
- warning code 2 with exact type `Timeout`.

Exit status must still be 0, 2, or 3 and nonzero status 2 or 3 must be backed by at least one recognized diagnostic. Any unknown code, level, type, malformed diagnostic, malformed finding, unexpected exit status, command timeout, output limit, or launch failure remains fatal.

Valid findings are preserved. The Scan Package and Technical Report record OpenGrep as `completed-with-limitations`, and the public report adds fixed prose explaining that some files or rule/file combinations were not analyzed. No scanner-supplied paths or messages are persisted in the limitation.

## Stage 3: Contextual-review recovery

Contextual review writes an atomic, session-local progress bundle after every completed evidence group. The bundle is bound to the prepared session ID and evidence digest and contains only already-sanitized assessments, observations, usage totals, completion IDs, and the exact completed group prefix.

On a second invocation in the same scan job, the review phase validates and resumes that prefix instead of resending completed groups. The workflow performs one additional invocation only for a sanitized `MODEL_PROVIDER` failure; configuration, authentication, evidence, and schema failures do not trigger a command-level replay.

Within a group, repository-specific invalid responses use every configured immediate attempt even when the same diagnostic repeats. Repair guidance becomes field-specific for every allowlisted assessment diagnostic plus observation and top-level schema failures. A successful final review must still contain exactly one assessment per candidate and unique, evidence-valid observations before `review.json` is written.

The progress file is removed after a complete review and is never uploaded as part of the encrypted public outcome. Finalization continues to require a complete validated review bundle.

## Compatibility

Existing Scan Package V1 and Report V5 documents remain valid because tool limitations are optional and existing tool statuses are unchanged. New reports can additionally use `completed-with-limitations`. Report identities continue to cover the complete report content.

Prepared sessions add optional tool limitation data while retaining schema version 5. The field is optional for compatibility with already-created local fixtures; newly prepared sessions always emit it when present.

## Verification

- Reversed same-fingerprint failure timestamps publish successfully and produce identical automatic-hold time bounds regardless of request order.
- Untyped review and finalization failures are target-local; untyped publication failures remain shared publication failures; typed failures retain their existing domain.
- Recognized OpenGrep syntax and rule-timeout diagnostics preserve findings and emit bounded limitations; unknown and malformed diagnostics remain fatal.
- Scan Package, Report V5, sanitizer, renderer, and fixtures accept and preserve limited coverage without weakening evidence validation.
- Contextual review resumes a validated completed-group prefix, retries a transient provider failure without repeating earlier groups, exhausts the configured schema-repair attempts, and rejects mismatched or malformed progress.
- Focused tests, the full test suite, type checking, build, and workflow-policy tests pass.

## Rollout

Ship the stages together in source but verify them independently. After deployment, run the ordinary reconciliation path and confirm that publication advances operations state. Then observe previously failing parser/timeout and contextual-review targets as they naturally return to the queue. No production state is manually rewritten by this implementation pass.
