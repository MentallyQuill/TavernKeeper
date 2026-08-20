# Contextual Review Opportunity Analyzer Design

**Date:** 2026-08-20  
**Status:** Approved for implementation  
**Scope:** Policy 5 report-corpus analysis, one conservative deterministic promotion, measured rollout, and bounded scanning restart

## Purpose

TavernKeeper's deterministic scanners should continue to surface technical evidence, while contextual model review should be reserved for behavior that cannot be resolved safely from authenticated evidence. This feature creates a repeatable, human-governed loop for finding expensive contextual patterns, promoting only mechanically decidable cases, and measuring the reduction without treating prior model verdicts as an allowlist.

The first production promotion is Zizmor's `artipacked` rule. TavernKeeper already treats a fixed set of known Zizmor rules as deterministic structured weaknesses. `artipacked` has the same structured scanner semantics but currently falls through as an unknown rule. Promoting it preserves the finding and classifies it conservatively; it does not suppress or relabel the workflow as safe.

## Goals

- Analyze only preferred reports referenced by `reports/index.json`, avoiding historical duplication.
- Validate every index and report through TavernKeeper's existing strict V5 contracts.
- Rank contextual-review burden by stable candidate attributes and outcome distributions.
- Keep exact candidate counts distinct from non-attributable provider-call token totals.
- Emit deterministic machine-readable JSON and human-readable Markdown.
- Promote `zizmor:artipacked` to deterministic structured-weakness assessment.
- Prove unknown Zizmor rules and case-wide hard escalators still fall through to contextual review.
- Measure the historical candidate reduction produced by the promoted condition.
- Keep model-cost maintenance active until a bounded post-merge canary succeeds.

## Non-goals

- Automatically generating, approving, or merging deterministic rules.
- Parsing free-form model explanations as promotion evidence.
- Claiming exact per-rule token savings from batch-level usage data.
- Suppressing scanner findings or removing them from published reports.
- Changing the public report schema, contextual prompt, assessment schema, provider, or model.
- Shipping maintainer self-check workflows, artifact attestations, or capability manifests in this phase.

## Architecture

### Corpus service

`src/analysis/review-opportunities.ts` owns pure corpus analysis. It accepts a parsed `ReportIndexV5`, an asynchronous report loader, and a contextual policy version. It returns a strict versioned result with:

- corpus totals: indexed/loaded/skipped reports, model-reviewed candidates, provider calls, and aggregate usage;
- rule summaries keyed by origin, rule ID, scanner version, execution scope, file role, scanner confidence, and triage reason;
- outcome counts for disposition, exposure, and recommended risk;
- distinct repositories and bounded representative candidate references;
- exact contextual reviewer/provider/model strata for mixed-model corpora;
- report-level associated usage, explicitly marked overlapping and non-additive;
- data-quality limitations, including contextual reuse that cannot be mapped to individual public candidates.

Only assessments with `assessment_source: contextual-model` count as contextual outcomes. Deterministic-policy assessments remain visible in corpus totals but do not contribute to opportunity rankings. Stable sorting and no generated timestamp make identical input produce byte-identical output.

The loader verifies that each report's identity matches its index entry. A missing, malformed, mismatched, or non-V5 preferred report fails the command instead of silently changing the denominator. Reports for other contextual policy versions are counted as skipped and never mixed with Policy 5.

### CLI and rendering

`src/cli/review-opportunities.ts` reads `reports/index.json` and its referenced local report files. The package script `review-opportunities` supports:

```text
npm run --silent review-opportunities -- --format json
npm run --silent review-opportunities -- --format markdown
```

JSON is the canonical contract. Markdown is a pure renderer over that result and includes the attribution warning beside every associated-token column. Output goes to stdout so CI or operators can redirect it without repository churn.

### Deterministic promotion

`src/triage/review-triage.ts` adds `artipacked` to the pinned known-Zizmor set. The existing deterministic assessment path records a structured weakness with `risk_exposure: not_demonstrated`, keeps the candidate in the final report, and does not claim expected behavior.

The existing group-level hard-escalator check remains authoritative. If an `artipacked` candidate shares an evidence case with a hard danger signal, the entire case remains contextual. Any unknown future Zizmor rule also remains contextual.

## Attribution boundary

Public `review_batches` record provider-call counts and token usage but not the candidate or group IDs carried by each call. Public reports also do not identify which individual contextual assessments were fresh versus reused. Therefore:

- candidate and project frequencies are exact;
- corpus-wide provider calls and token totals are exact;
- per-rule associated token totals are overlapping report-level envelopes;
- projected avoided candidates are exact for an exact deterministic predicate;
- projected avoided calls or tokens are not claimed.

A future telemetry design may add candidate-bound batch identities, but this feature does not change immutable report contracts merely to estimate historical savings.

## Safety invariants

- Historical low-risk frequency is never sufficient for promotion.
- Model prose never drives executable conditions.
- Findings remain public technical evidence after deterministic resolution.
- Unknown, malformed, mismatched, or ambiguous data fails closed.
- Any material/high or demonstrated historical counterexample is prominently counted, never filtered out.
- Scanner, policy, prompt, schema, and model identities remain available for stratified analysis.
- No model-backed workflow is used to build or backtest the analyzer.

## Testing

### Corpus analyzer

- Preferred index entries are loaded once; historical reports are not traversed.
- Mixed policy versions are separated.
- Candidate/assessment joins and distinct repository counts are exact.
- Deterministic assessments do not appear as model opportunities.
- Material/high and demonstrated counterexamples remain counted.
- Associated usage is deduplicated per report within a summary and labeled non-additive.
- Reuse limitations are surfaced.
- Missing, malformed, or identity-mismatched reports fail.
- JSON and Markdown ordering is deterministic.

### Rule promotion

- A synthetic `zizmor:artipacked` candidate receives deterministic structured-weakness assessment and remains visible.
- An unknown Zizmor rule remains contextual.
- A case containing `artipacked` plus a hard escalator remains wholly contextual.
- Existing known Zizmor and JavaScript triage behavior remains unchanged.

### Backtest and verification

Run the analyzer against the checked-in Policy 5 corpus before and after promotion. Record exact affected candidates and repositories, while explicitly declining token/call savings. Run focused tests, the full repository gate, build, and workflow-policy validation.

## Rollout and scanning restart

1. Keep `MODEL_COST_MAINTENANCE` active and verify `active_scans: 0` during development.
2. Merge through the normal protected-branch PR path after independent review and green CI.
3. Run the repository-free provider protocol check.
4. While maintenance remains active, grant one bounded staff canary to the smallest known-working target that exercises current Policy 5 review.
5. Require one completed report with no uncontrolled retry, valid usage accounting, and consumed one-shot authorization.
6. If the canary passes, clear model-cost maintenance and verify the scheduler claims no more than configured capacity. If it fails, retain maintenance and diagnose without opening the queue.
7. Publish the corpus measurement and canary evidence in the PR/operational handoff.

This restart restores existing queue policy; it does not bulk-authorize individual targets or widen concurrency.
