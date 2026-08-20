# Contextual Review Opportunity Baseline — 2026-08-20

## Snapshot

This baseline was generated from the preferred report index at `reports/index.json` on TavernKeeper `origin/main` commit `02daeba27d5525feb52465f3ca0bd974dd67a5c0`. The index declares `generated_at: 2026-08-18T05:01:51.854Z`.

Command:

```text
npm run review-opportunities -- --format json
```

The analyzer reads only preferred index entries, validates every selected report through the strict V5 contract, and includes only assessments whose source is `contextual-model`.

## Corpus totals

| Measure                                                                 | Exact value |
| ----------------------------------------------------------------------- | ----------: |
| Preferred reports indexed                                               |         389 |
| Policy 5 reports loaded                                                 |          60 |
| Other-policy reports skipped                                            |         329 |
| Contextual-model candidates                                             |         761 |
| Provider calls                                                          |         302 |
| Input tokens                                                            |  11,441,839 |
| Output tokens                                                           |     709,079 |
| Cache-read tokens                                                       |     524,865 |
| Reasoning tokens                                                        |           0 |
| Reports with contextual reuse not attributable to individual candidates |           2 |

Candidate and repository frequencies are exact. Corpus provider calls and token totals are exact.

## First promotion: `zizmor:artipacked`

Across the preferred Policy 5 corpus, `artipacked` reached contextual-model assessment 21 times in 10 distinct repositories. Those assessments split into two stable key variants:

| Origin   | Rule         | Scanner  | Scope        | File role | Scanner confidence | Triage reason  | Candidates | Repositories | Outcomes                                               |
| -------- | ------------ | -------- | ------------ | --------- | ------------------ | -------------- | ---------: | -----------: | ------------------------------------------------------ |
| `zizmor` | `artipacked` | `1.28.0` | `automation` | `tooling` | `low`              | `unknown-rule` |         20 |            9 | 20 expected behavior; 20 not demonstrated; 20 low risk |
| `zizmor` | `artipacked` | `1.28.0` | `automation` | `test`    | `low`              | `unknown-rule` |          1 |            1 | 1 expected behavior; 1 not demonstrated; 1 low risk    |

No `artipacked` assessment in this snapshot was material/high recommended risk, demonstrated exposure, or credible malicious behavior. That historical distribution is useful backtest evidence, but it is not the safety justification for the rule.

The affected repositories are:

- `Alphonsos88k/ste_summary_editor`
- `MultihogAurelius/SillyTavern-MultihogDnDFramework`
- `N0819/Sonder_Engine`
- `Windy-Sora/SillyTavern-GroupWorld`
- `brasen56/merged_world_tracker`
- `ddkhan24/hordestudio`
- `lunarblazepony/BlazeTracker`
- `pixelnull/sillytavern-DeepLore`
- `platberlitz/sillytavern-image-gen`
- `senjinthedragon/SillyTavern-Discord-Connector`

## Associated usage boundary

The tooling variant is associated with 9 reports whose report-level envelopes contain 95 provider calls, 3,785,070 input tokens, 212,713 output tokens, and 101,712 cache-read tokens. The test variant is associated with 1 report whose envelope contains 27 provider calls, 898,525 input tokens, 43,881 output tokens, and no cache-read tokens.

These figures are deliberately not presented as savings. Public `review_batches` do not record the candidate or evidence-group identities sent in each provider call. A report can contain many unrelated contextual candidates, and the same report-level usage envelope can appear under several opportunity groups. Associated calls and tokens therefore overlap, are non-additive, and cannot establish exact avoided calls or spend.

The exact projected effect of the predicate is narrower: if the same 21 candidates were triaged under the new rule and none shared a hard-escalated evidence case, 21 candidates across 10 repositories would be resolved without contextual review. The final avoided calls and tokens remain unknown.

## Why the promotion is bounded

The executable condition is exact scanner identity, not historical model wording:

```text
origin == "zizmor" && rule_id == "artipacked"
```

TavernKeeper already maps a pinned set of known Zizmor rule IDs to its deterministic `structured-weakness` assessment. Adding `artipacked` to that set preserves the scanner finding and records a conservative material-vulnerability disposition with `risk_exposure: not_demonstrated` and low recommended risk. It does not suppress the finding and does not relabel the workflow as expected behavior or safe.

The group-wide hard escalator runs before individual rule triage. An `artipacked` candidate sharing an evidence case with a credential, network, execution, persistence, or other hard-danger correlation remains contextual together with the whole case. Unknown present or future Zizmor rule IDs also remain contextual.

## Measurement conclusion

This first promotion removes a known structured scanner rule from the ambiguous-model path while preserving both evidence visibility and fail-safe escalation. The corpus analyzer makes future candidates for this treatment measurable, but any additional promotion still requires an exact mechanical predicate, unsafe and benign regression fixtures, and an explicit ambiguous-case fallback. Historical low-risk frequency alone is never sufficient.
