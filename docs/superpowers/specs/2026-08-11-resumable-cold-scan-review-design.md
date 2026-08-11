# Resumable Cold Scan Review Design

## Problem

Policy-5 preparation deliberately fails closed when contextual review cannot fit
inside one bounded model-review session. That protects cost and coverage, but it
currently treats a large valid target like a failed target: reconciliation
backs off and later repeats checkout, dependency inspection, deterministic
scanners, evidence normalization, and review planning before reaching the same
limit.

This is the wrong cost boundary. Large extensions are valid inputs. The cold
scan should be purchased once for an exact repository revision, while model
review may continue through as many independently bounded waves as its prepared
evidence requires.

The same missing persistence also makes a late report-finalization error
expensive: completed model assessments exist only inside the workflow run, so a
retry can repurchase both scanning and review.

## Goals

- Run checkout and deterministic scanners once for an exact scan identity.
- Review any finite number of contextual evidence groups through bounded waves.
- Preserve every current per-wave provider, input-token, output-token, and case
  limit.
- Resume only exact, authenticated evidence and already validated assessments.
- Publish a report only after all evidence is covered and final validation
  succeeds.
- Resume finalization without another model call when review is complete.
- Keep existing policy-5 assessment semantics and exact review-cache identity.
- Make partial progress a normal queue transition rather than a scan failure.

## Non-Goals

- Dropping, merging, or sampling contextual cases to fit a fixed total cap.
- Repairing an old report without replaying it against exact prepared evidence.
- Weakening dangerous-correlation escalation, output validation, review budgets,
  or publication gates.
- Reusing a checkpoint after the repository SHA, scanner rules, prompt, model,
  provider, assessment schema, or normalized evidence changes.
- Making plaintext repository contents or model prompts durable artifacts.

## Versioning Decision

Scanner policy 5, contextual policy 5, prompt `contextual-review-v7`, and
assessment schema `contextual-assessment-v2` remain the assessment identity.
Neither the scanner rules nor the meaning of an assessment changes.

Resumption is a separate execution concern. New checkpoints and reports carry
`review_protocol_version: 2`. Protocol 2 defines bounded review waves and the
associated accounting fields. Existing policy-5 reports remain valid protocol-1
documents; their immutable contents are not rewritten and their exact review
cache entries remain eligible.

The current report contract interprets
`review_budget.configured.max_fresh_behavior_cases` as a whole-report maximum.
Protocol 2 changes that interpretation to a per-wave maximum and records both
`wave_count` and `total_fresh_behavior_cases`. Validation requires every wave to
respect its configured caps and the total to equal the sum of validated waves.
There is intentionally no whole-report case cap.

This avoids a contextual-policy bump that would falsely imply new assessment
semantics and invalidate otherwise exact policy-5 work across the catalog.

## Durable Checkpoint

Each active queue entry may reference one immutable encrypted checkpoint:

- checkpoint protocol and phase;
- repository ID, canonical repository name, and exact target SHA;
- scanner policy, scanner rule-catalog digest, contextual policy, prompt,
  assessment schema, provider, and model identity;
- scan request digest, prepared-session digest, evidence digest, and file
  digests;
- ordered completed group IDs and replay-valid assessments;
- observations and cumulative usage/audit records;
- artifact run ID, artifact ID, artifact name, ciphertext digest, creation time,
  and expiry time.

The checkpoint payload contains the bounded prepared session plus contextual
review progress. It is packed and encrypted with the existing AES-GCM artifact
key before upload. Its authenticated envelope binds every identity field above
as additional authenticated data. The durable artifact contains no plaintext
checkout, source file, prepared evidence, prompt, or model response.

Checkpoint artifacts use a 90-day retention window. Operations state advances
to schema version 4 and stores only the checkpoint reference and identity
summary, never the decryption key or plaintext payload. A newer checkpoint is
committed to state only after upload and digest verification succeed. The
previous checkpoint remains referenced until that atomic transition completes.

## Wave Planning and Accounting

The planner processes unresolved evidence groups in stable evidence order. It
selects the largest non-empty prefix that fits all configured per-wave limits:

- fresh contextual cases;
- provider calls;
- estimated input tokens;
- actual input tokens as calls complete;
- actual output tokens as calls complete; and
- the existing per-call group, input, and structured-output bounds.

Each wave starts a fresh budget ledger. Cumulative usage remains in checkpoint
history for audit and final reporting, but it does not consume the next wave's
allowance. A valid cached assessment consumes neither a fresh case nor a
provider call and is replay-validated before acceptance.

If adding another group would exceed a planning limit, the current non-empty
wave runs and the group remains for the next wave. If one indivisible group
cannot fit into an empty wave even after the existing bounded context-reduction
rules, the target has a structural oversized-group failure. Raising the number
of waves cannot repair that condition, so it is reported distinctly and does
not enter blind retry.

When actual usage reaches a wave limit after accepting some groups, accepted
groups are checkpointed and the target continues in a later wave. When no group
was accepted, the existing provider/retry classification applies.

## Workflow

### Cold start

1. Reconciliation leases the queue entry and finds no valid checkpoint.
2. Preparation performs checkout, dependency inspection, deterministic scans,
   normalization, triage, and prepared-session validation once.
3. The prepared session is sealed into a durable checkpoint before contextual
   review begins.
4. Review restores that checkpoint, completes one bounded wave, validates every
   accepted assessment, and seals the successor checkpoint.

### Review continuation

1. Reconciliation leases an entry with a checkpoint in `prepared` or
   `reviewing` phase.
2. The workflow skips checkout and all deterministic scanners.
3. It downloads, authenticates, decrypts, and replay-validates the checkpoint.
4. It runs the next bounded wave and publishes a successor checkpoint.
5. If unresolved groups remain, state records normal progress and immediately
   requeues the target without increasing its failure streak or applying
   exponential backoff.

### Finalization continuation

After the last group is accepted, the successor checkpoint enters `reviewed`
phase before report construction. A finalization run restores that checkpoint,
builds and validates the report, and publishes only the complete outcome. It
does not run scanners or call the model.

On successful publication, reconciliation clears the checkpoint reference and
failure history. Artifact expiry then removes the encrypted intermediates. A
finalization failure retains the reviewed checkpoint and records a specific
failure fingerprint. Repeating the same deterministic fingerprint reaches a
terminal structural state instead of repurchasing work indefinitely.

## Failure Semantics

- `REVIEW_WAVE_PENDING` is progress, not failure. It schedules immediate
  continuation and does not consume the chronic-failure threshold.
- Provider timeouts, throttling, authentication failures, or malformed output
  before durable progress retain their current retry/backoff behavior.
- A missing, expired, corrupt, unauthenticated, or identity-mismatched
  checkpoint fails closed. State clears the unusable reference and permits one
  new cold preparation for the still-current target identity.
- A checkpoint mismatch caused by a changed target SHA or policy identity is
  ordinary invalidation, not repairable resumption.
- An indivisible oversized group and a repeated identical finalization failure
  are structural blockers with distinct public-safe operator diagnostics.
- Reports remain complete-or-nothing. No checkpoint, partial assessment set, or
  intermediate wave changes the preferred report index.

## Deterministic Triage Correction

Unknown group execution scope must not automatically turn every otherwise
deterministic candidate into a contextual case. Known deterministic candidates,
including exact OSV advisory matches, remain in the deterministic lane unless a
hard dangerous-correlation escalator applies to the group. Unknown candidates
still receive contextual review.

This correction reduces unnecessary model work without suppressing evidence.
It is independent of resumability: genuinely large targets continue through as
many review waves as necessary.

## Security Properties

- Checkpoint confidentiality and integrity use the existing protected artifact
  key and AES-GCM envelope.
- Decryption remains isolated to protected scanning/reconciliation jobs.
- Exact identity validation occurs before any cached or checkpointed assessment
  is trusted.
- Every resumed assessment is replayed through the authoritative coverage and
  candidate/evidence/path identity validator.
- Only the newest state-referenced checkpoint is authoritative; unreferenced
  artifacts cannot redirect a queue entry.
- Publication still requires complete coverage, schema validation, report
  identity validation, and the existing protected publisher path.
- Per-wave cost limits stay hard. Unbounded target size increases the number of
  authenticated continuations, not the authority or size of a single call.

## Current Campaign Migration

The five repositories already published at the exact policy-5 tuple require no
work. The eight remaining repositories will receive one cold preparation under
protocol 2 because their previous one-day plaintext artifacts were not durable
checkpoints. Each then advances through review waves until it reaches a reviewed
checkpoint and complete publication.

The frozen 13-repository campaign and its complete-or-nothing behavior remain
unchanged. A repository satisfies the campaign only when its preferred report
matches its exact current SHA and the required scanner policy 5, contextual
policy 5, prompt v7, and assessment schema v2 identity.

## Verification

- Planner tests prove a target larger than 12 cases is partitioned into stable
  waves and every wave independently respects all caps.
- Planner tests prove cached cases do not consume fresh-wave allowance and one
  indivisible oversized group produces a structural error.
- Progress tests prove wave-local ledgers reset while cumulative audit totals
  remain exact and cannot be double-counted after interruption.
- Checkpoint tests prove authenticated round trips, exact-identity enforcement,
  corruption rejection, expiry handling, and replay validation.
- State tests prove schema-v3 migration, atomic checkpoint replacement,
  immediate progress continuation, ordinary transient backoff, and structural
  terminal classification.
- Workflow-policy tests prove resumed review skips checkout/scanners, reviewed
  finalization skips the model, plaintext artifacts remain short-lived, and
  durable checkpoints are encrypted.
- Report-contract tests prove protocol-1 compatibility and protocol-2 per-wave
  accounting with no total case ceiling.
- Triage tests prove deterministic OSV candidates stay deterministic under
  unknown scope while hard dangerous correlations still escalate.
- End-to-end tests interrupt after preparation, after a partial wave, and before
  finalization, then prove exact resumption and one complete publication.
- Full formatting, type checking, unit tests, workflow-policy checks, build, and
  hostile-fixture tests must pass before deployment.

## Rollout and Acceptance

Protocol 2 first runs against one large campaign target as a canary. Acceptance
requires evidence that deterministic scanners ran once, at least two bounded
review waves resumed from authenticated checkpoints, final publication was
complete, and the preferred report matched the exact required tuple. The
remaining seven targets then resume under the same protocol.

The campaign is terminal only when all 13 preferred reports match the exact
tuple or a target exposes a diagnosed structural blocker. After terminal
success, the deployed VectHare landing card and detail report must derive the
same advisory from the same preferred report.
