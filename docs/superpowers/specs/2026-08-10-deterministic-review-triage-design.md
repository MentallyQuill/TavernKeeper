# Deterministic Review Triage Design

**Date:** 2026-08-10  
**Status:** Approved  
**Scope:** TavernKeeper scanner evidence triage, contextual-model budgeting, report transparency, and the required Tavernary reader update

## Problem

TavernKeeper currently sends every validated scanner candidate through contextual model review. Multi-card batching and exact-finding reuse reduced repeated work, but they do not solve cold-scan cost. The Recursion canary produced 64 candidates and consumed 1,298,743 model tokens across 33 calls. Sixty candidates came from JavaScript analysis, 51 were tooling-only, 63 were expected behavior, and the only real issue was a low-impact regular-expression slowdown.

This is the wrong trust boundary. Scanner output is evidence, not a mandate for model review. Known benign patterns, structured advisories, and self-contained low-impact weaknesses should be decided by versioned deterministic policy. The model should be reserved for ambiguous behavior whose danger depends on execution reachability, correlated capabilities, or cross-boundary data flow.

## Goals

- Continue running every applicable scanner on every selected project.
- Preserve all validated evidence in the technical report.
- Keep deterministically benign evidence visible in a collapsed technical-evidence section without allowing it to influence public caution coloring.
- Use the model only for ambiguous, potentially dangerous behavior cases.
- Combine correlated signals into behavior cases instead of reviewing isolated hits.
- Bound model calls and tokens before any provider request.
- Fail closed when suspicious work exceeds the configured model budget.
- Preserve exact-finding contextual-review reuse for unchanged ambiguous cases.
- Keep the approved scheduler behavior: new submissions, updated projects, and the frozen 20 popular plus 20 latest-release cohort, with two scan lanes and per-target publication.
- Avoid a catalog-wide policy migration.

## Non-goals

- Proving that no unknown malicious behavior exists.
- Removing or disabling scanners.
- Treating scanner severity as public danger severity.
- Using the model to rewrite structured scanner facts into nicer prose.
- Silently dropping evidence that was deterministically resolved.
- Publishing a green report after model-budget exhaustion.

## Considered Approaches

### 1. Scanner-specific deterministic triage with fail-safe model escalation

This is the approved approach. Each scanner rule has an explicit deterministic policy. Known benign and self-contained findings receive local assessments. Ambiguous or correlated dangerous behavior becomes a contextual-review case. Unknown rules default to contextual review. A preflight budget stops oversized model plans before the first provider call.

This provides the largest cost reduction without weakening detection because it changes who interprets evidence, not which scanners run.

### 2. Severity and confidence thresholds

Only medium/high scanner findings would reach the model. This is simple but unsafe: weak signals can become important when correlated, while noisy medium findings such as `unsafe-regex` would still dominate cost. Scanner severity also does not represent realistic SillyTavern harm.

### 3. One model call for the entire scan

This reduces call count but creates oversized prompts, poor evidence locality, truncation risk, brittle structured output, and expensive retries. The Recursion canary showed that provider validation failures already cause split retries. Making the initial call larger worsens that failure mode.

## Threat Model and Safety Rule

The governing rule is:

> Deterministic policy may resolve a finding only when it can prove the bounded conclusion it publishes. Missing, unknown, or conflicting context escalates to the model; it never defaults to benign.

TavernKeeper prioritizes realistic harm for a locally operated SillyTavern roleplay environment. Local, recoverable slowdown is low impact unless evidence demonstrates a broader service, credential, execution, persistence, or cross-user boundary.

File location alone is not a benign proof. Tooling can still execute through package lifecycle scripts, workflows, update hooks, or imports from runtime code. Deterministic dismissal therefore requires both an eligible rule and a proven non-runtime execution scope.

## Architecture

### Execution-scope analyzer

A pure analyzer classifies each evidence location as one of:

- `runtime`: reachable from a SillyTavern client/server entrypoint or package runtime export;
- `install-update`: reachable from install, update, lifecycle, or migration hooks;
- `automation`: reachable from repository workflows or release automation;
- `tooling-only`: executable tooling with no path from runtime, install/update, or automation roots;
- `test-documentation-data`: inert test, documentation, fixture, or data content;
- `unknown`: reachability cannot be proven.

Roots come from known SillyTavern entrypoints, package `main`, `module`, `exports`, `bin`, and lifecycle scripts, workflow command paths, and statically resolvable imports. Unresolved dynamic imports or computed execution paths produce `unknown`.

### Behavior-case correlator

Validated findings are correlated by representation, path, and nearest available source scope. The correlator joins capabilities such as:

- credential, environment, host-state, or user-data sources;
- network, file, process, DOM, persistence, or dynamic-execution sinks;
- decoding or obfuscation stages;
- install/update and automation reachability;
- signals from multiple scanners at the same behavior boundary.

One behavior case may contain multiple findings. Deterministic assessments remain per candidate for report compatibility, but contextual review receives the complete case so the model does not repeatedly rediscover the same behavior.

### Deterministic triage engine

The engine is a pure, versioned function. It receives a behavior case, execution scope, scanner metadata, and sanitized evidence features. It returns one of:

- `deterministic-assessment`, including the complete assessment fields and a stable reason code;
- `contextual-review`, including escalation reason codes;
- `triage-incomplete`, when required evidence or analysis is unavailable.

Rule ordering is fail-safe:

1. hard dangerous-behavior escalators;
2. scanner-specific direct findings;
3. scanner-specific benign proofs;
4. default contextual review.

A benign rule can never override a hard escalator or unresolved execution scope.

### Contextual-review planner

Only contextual cases enter the existing exact-finding reuse and batching pipeline. Reusable cases are removed before budget calculation. Fresh cases are batched using the existing input/output limits.

The planner enforces all of these preflight limits before the first provider call:

- at most 12 fresh contextual behavior cases;
- at most 6 provider calls including validation-repair splits;
- at most 200,000 estimated fresh input tokens;
- at most 250,000 cumulative actual input tokens and 40,000 output tokens.

If the initial plan exceeds its case or estimated-input limit, the target fails immediately with `MODEL_REVIEW_BUDGET_EXCEEDED` and makes no model request. If actual usage or call count reaches its limit during review, the target fails before another request. Completed progress remains available for an explicit staff retry, but automatic retries do not bypass the same cumulative budget.

Budget exhaustion does not produce a green or caution report. It is a fail-closed operational outcome requiring staff review or a policy improvement.

## Scanner Policy

### JavaScript / JS-X-Ray

- `unsafe-regex` is deterministic. Tooling/test-only occurrences become expected behavior with no demonstrated impact. Runtime occurrences become a low-risk minor weakness when potentially attacker-influenced; bounded or structurally safe expressions remain expected behavior. Regular-expression findings cannot alone produce a yellow caution rating.
- `serialize-environment` and `data-exfiltration` escalate when runtime, install/update, or automation reachable, or when correlated with a network, process, file, persistence, or dynamic-execution sink. Proven isolated tooling/test serialization is deterministic expected behavior.
- `shady-link` is deterministic for recognized namespaces and inert tooling/test URLs. Runtime resource or network destinations, nonstandard schemes, literal IPs, credential-bearing URLs, and unresolved destinations escalate.
- `encoded-literal` is deterministic only when decoding completed and the derived representation has no execution, network, persistence, credential, or unresolved-analysis signal. Otherwise it escalates.
- TavernKeeper correlation rules such as credential-to-network, downloaded-code execution, dynamic execution, or persistence escalate as one behavior case regardless of file-role labels.
- Unknown X-Ray rules escalate.

### Gitleaks

- Syntactically invalid, known placeholder, or fixture-only values may be deterministically classified as expected behavior after a local validity/placeholder check. Raw values remain discarded.
- Plausible secrets remain contextual unless the scanner can prove a direct structured verdict. The model is never used to test a credential against an external service.
- Confirmed structured secret exposure is reported directly; prose generation is not required.

### OSV Scanner

Dependency advisories are deterministic structured findings. Assessment uses package identity, installed version, dependency scope, advisory severity, known exploitation metadata when present, and fix availability. The model is not called to restate an advisory.

Unchanged advisory assessments retain stable identities across project updates. This covers findings such as a persistent RUSTSEC advisory without repeatedly paying for narrative review.

### Zizmor

Known workflow rules use deterministic severity and exposure mappings. Contextual review is reserved for a rule explicitly marked context-dependent or a case correlated with another scanner signal.

### OpenGrep and TavernKeeper static rules

Every owned rule declares `deterministic`, `contextual`, or `correlation-only` triage behavior in the versioned rule catalog. High-confidence self-contained violations can be assessed directly. Source-to-sink, trust-boundary, and intent-dependent rules become behavior cases.

### Malcontent

Capability matches remain literal-free. Runtime-reachable executable or binary capabilities escalate when intent or provenance is ambiguous. Inert assets and known benign capability matches use deterministic mappings. Strong malicious signatures may produce a direct high-risk assessment without model prose.

## Report Contract

The report remains schema version 5 for compatibility, but scanner policy and contextual-review policy advance from version 4 to version 5. Policy-v5 reports require new triage fields; older reports remain valid under their declared policies.

Each policy-v5 assessment records:

- `assessment_source`: `deterministic-policy` or `contextual-model`;
- `triage_reason_code`: a stable policy-owned identifier;
- the existing disposition, impact, exploitability, confidence, exposure, risk, explanations, action, and locations.

The report adds `review_triage` with:

- deterministic-triage policy version;
- total, deterministic, contextual, and reused contextual candidate counts;
- behavior-case counts;
- reason-code counts;
- configured model budget and actual calls/tokens.

`contextual_reviewer` may be absent when no contextual request was made. `review_usage` remains present and is zero in an all-deterministic report. `review_batches` is absent when there were no model calls.

Public presentation separates:

- assessed security items, which participate in rating;
- collapsed deterministic technical evidence, which remains inspectable but does not create yellow caution coloring when every assessment recommends low risk;
- scanner coverage, which continues to prove all applicable tools ran.

Tavernary's strict copied schema and semantic reader must accept policy-v5 triage fields before policy-v5 reports are published.

## Version and Queue Migration

- Advance scanner policy to `5` and contextual-review policy to `5`.
- Use `POLICY_V5_CANARY_GATE` during rollout.
- Do not create a catalog-wide policy campaign.
- Do not queue repositories merely because their preferred report uses policy 4.
- Preserve only the existing new/updated queue and frozen 20-plus-20 coverage cohort.
- Policy-v5 scans supersede policy-v4 reports only when the normal scheduler, frozen cohort, or staff canary selects that repository.

## Failure Handling

- Unknown deterministic rule: contextual review.
- Unknown execution scope: contextual review.
- Missing correlation input: contextual review.
- More fresh ambiguous work than budget: fail before provider use.
- Budget reached during provider retries: stop before the next request and record a target-scoped budget failure.
- Deterministic policy invariant failure: repository scan failure; do not publish a partial safety verdict.
- Tavernary policy-v5 incompatibility: block publication during canary deployment rather than synthesize or quarantine blindly.

## Testing

### Unit contracts

- One table-driven test per scanner rule and execution scope.
- Hard escalators override benign classifications.
- Unknown rules and unknown scopes escalate.
- Deterministic assessments satisfy the same risk-exposure invariants as model assessments.
- Correlated signals form one behavior case without losing candidate locations.
- Policy-v5 reports reconcile deterministic, contextual, reused, and total counts.

### Budget tests

- Oversized fresh plans fail before the provider stub is called.
- Cached contextual cases are removed before preflight budgeting.
- Repair splits count toward call and token limits.
- Progress retries cannot reset cumulative budget accounting.

### Regression fixtures

- Recursion: all 64 candidates remain represented; at most 6 candidates require a cold model review, at most 2 initial model batches are planned, and the low-impact regex weakness remains visible without causing yellow caution.
- Wandlight: all five candidates remain represented and at most one requires model review.
- Directive: repeated X-Ray occurrences remain compacted into families, deterministic triage removes at least 80 percent of cold contextual candidates, and an over-budget remainder fails before model use.
- Existing material/high malicious fixtures continue to escalate or produce a direct high-risk verdict.

### End-to-end invariants

- All eight tool records remain present with completed/not-applicable status.
- Reports publish independently per target.
- Tavernary imports policy-v5 reports without starting unrelated backlog continuations for an exact canary import.
- The normal catalog scheduler remains paused until canaries pass.

## Rollout

1. Keep the current staff pause and zero active scan claims.
2. Merge Tavernary policy-v5 reader support before publishing a policy-v5 report.
3. Merge TavernKeeper deterministic triage and update the pause reason to `POLICY_V5_CANARY_GATE`.
4. Reset Wandlight and Recursion to an empty public/import baseline and run them as the only two staff canaries.
5. Verify scanner coverage, triage counts, model calls, token ledgers, ratings, per-target publication, and Tavernary imports.
6. Run Directive as the oversized canary. It must either fit the budget after deterministic triage or fail before provider use.
7. Resume two-lane normal scanning only after all canaries pass. Normal priority remains new submissions, updated projects, then the frozen 20 popular plus 20 latest-release cohort.

## Success Criteria

- Recursion cold model usage is at most 200,000 input tokens and 40,000 output tokens, with a target of less than 150,000 total tokens.
- Recursion retains its low-impact regex finding and no material/high finding is lost.
- Deterministically benign evidence stays publicly inspectable but does not create caution coloring.
- An adversarial evidence flood cannot force unbounded model spend.
- A rule or reachability state that policy does not understand is never auto-cleared.
- No catalog-wide policy-v5 rescan is created.
