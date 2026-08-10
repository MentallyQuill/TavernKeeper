# Deterministic Review Triage Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Keep every scanner and every validated finding visible while resolving proven low-risk cases deterministically, sending only ambiguous behavior cases to the model, and enforcing a hard per-target model budget.

**Architecture:** Evidence preparation adds a conservative execution-scope classification to each existing evidence group. A pure policy-v5 triage engine partitions complete evidence into deterministic assessments and contextual behavior cases; the existing reuse and batching pipeline processes only the contextual partition. Finalization merges both sources into a schema-v5 report with policy-v5 provenance, and Tavernary learns that strict contract before any policy-v5 report is published.

**Tech Stack:** TypeScript 5, Node.js 24, Zod, Vitest, JSON Schema, GitHub Actions, TavernKeeper static HTML, Tavernary AJV importer

## Global Constraints

- Keep production scanning paused throughout implementation and pre-publication verification.
- Continue running all eight required tool records; triage changes interpretation, never scanner coverage.
- Scanner policy and contextual-review policy advance to exact version `5`; the public report stays schema version `5`.
- Unknown rules, unknown execution scope, incomplete correlation input, and conflicting evidence go to contextual review; they never default to benign.
- At most 12 fresh contextual behavior cases, 6 provider calls, 200,000 estimated fresh input tokens, 250,000 cumulative actual input tokens, and 40,000 cumulative output tokens are allowed per target.
- Budget overflow fails with `MODEL_REVIEW_BUDGET_EXCEEDED` before the next provider request and cannot publish a green or caution report.
- Preserve exact-finding contextual reuse, two scan lanes, per-target publication, and queue priority: new submissions, updated projects, then the frozen 20 popular plus 20 latest-release cohort.
- Do not create a catalog-wide policy-v5 migration.
- Do not publish policy-v5 reports until Tavernary's strict copied schema and semantic reader have merged.
- Do not resume scanning until Wandlight, Recursion, and Directive canaries pass.

---

## File Structure

- `config/scanner-policy.v5.json`: scanner policy v5, including bounded execution-scope analysis.
- `config/contextual-review.v5.json`: contextual policy v5 and all preflight/cumulative model limits.
- `src/config/policy.ts`: current policy constants and strict v5 config schemas.
- `src/triage/execution-scope.ts`: bounded source-graph classification with fail-closed `unknown` output.
- `src/triage/review-triage.ts`: policy-owned reason codes, behavior-case partitioning, and deterministic assessments.
- `src/model/contextual-review-budget.ts`: reusable preflight planning and cumulative request ledger.
- `src/model/contextual-review.ts`: contextual-only review execution using the budget planner/ledger.
- `src/orchestrator/session.ts`: persist execution scope, run triage, review the contextual partition, and merge final output.
- `src/contracts/reports-v5.ts`: conditional policy-v5 assessment provenance and `review_triage` reconciliation.
- `src/report/contextual-report.ts`: merge deterministic and contextual assessments into complete candidate coverage.
- `src/publish/render-report.ts`: separate assessed security items from collapsed deterministic technical evidence.
- `src/model/review-cache.ts`: cache only contextual-model units and support reports with no contextual reviewer.
- `src/operations/failure.ts`: classify the model-budget failure as target-scoped contextual review.
- `scripts/generate-contract-schemas.ts`: generate policy-v5 conditional JSON Schema.
- `.github/workflows/scan-and-publish.yml`: load v5 configs while retaining the existing bounded provider-secret step.
- `tests/execution-scope.test.ts`: reachability and conservative fallback contracts.
- `tests/review-triage.test.ts`: scanner-policy and hard-escalator table tests.
- `tests/contextual-review-budget.test.ts`: preflight and cumulative spend boundaries.
- Existing report, session, cache, renderer, workflow, contract, and fixture tests: policy-v5 integration coverage.
- Tavernary `data/schemas/tavernkeeper-scan-report.v5.schema.json` and `data/schemas/tavernkeeper-report-index.v5.schema.json`: copied generated contracts.
- Tavernary `scripts/security/tavernkeeper-reports.mjs` and `.d.mts`: strict policy-v5 semantic validation and types.
- Tavernary `tests/unit/tavernkeeper-reports.test.ts`: importer acceptance and rejection tests.

### Task 1: Versioned policy-v5 configuration and failure attribution

**Files:**

- Create: `config/scanner-policy.v5.json`
- Create: `config/contextual-review.v5.json`
- Modify: `src/config/policy.ts`
- Modify: `src/operations/failure.ts`
- Modify: `src/orchestrator/scan-handler.ts`
- Modify: `src/scanners/run-scanners.ts`
- Modify: `src/scanners/javascript-analysis.ts`
- Modify: `src/cli/prepare-target.ts`
- Modify: `scripts/smoke-scanners.ts`
- Modify: `tests/policy.test.ts`
- Modify: `tests/failure.test.ts`
- Modify: `tests/scan-package.test.ts`

**Interfaces:**

- Produces: `ScannerPolicyV5`, current `ScannerPolicy`, and `ContextualReviewPolicy` with `maxFreshBehaviorCases`, `maxProviderCalls`, `maxEstimatedInputTokens`, `maxActualInputTokens`, and `maxActualOutputTokens`.
- Produces: `JavascriptScannerPolicy = ScannerPolicyV4 | ScannerPolicyV5` for scanner functions that share the JavaScript-analysis shape, while current CLI entrypoints parse v5 only.
- Produces: `MODEL_REVIEW_BUDGET_EXCEEDED` classified as `{ domain: "target", component: "contextual-model" }`.

- [ ] **Step 1: Write the failing policy test**

```ts
const policy = await loadContextualReviewPolicy(
  "config/contextual-review.v5.json",
);
expect(policy).toMatchObject({
  version: "5",
  maxFreshBehaviorCases: 12,
  maxProviderCalls: 6,
  maxEstimatedInputTokens: 200_000,
  maxActualInputTokens: 250_000,
  maxActualOutputTokens: 40_000,
});
```

- [ ] **Step 2: Run the focused tests and observe the missing v5 contract**

Run: `npm.cmd test -- tests/policy.test.ts tests/failure.test.ts`

Expected: FAIL because the v5 files/fields and budget failure attribution do not exist.

- [ ] **Step 3: Add strict v5 config schemas and current constants**

`config/contextual-review.v5.json` must contain:

```json
{
  "version": "5",
  "promptVersion": "contextual-review-v7",
  "schemaVersion": "contextual-assessment-v2",
  "maxImmediateAttempts": 3,
  "maxOutputTokens": 32768,
  "maxResponseBytes": 5000000,
  "timeoutMs": 300000,
  "maxBatchGroups": 5,
  "maxBatchInputTokens": 64000,
  "maxFreshBehaviorCases": 12,
  "maxProviderCalls": 6,
  "maxEstimatedInputTokens": 200000,
  "maxActualInputTokens": 250000,
  "maxActualOutputTokens": 40000
}
```

Copy scanner v4 limits into scanner v5 and add a bounded `executionScope` object with `maxFiles: 10000`, `maxTotalBytes: 67108864`, and `maxFileBytes: 2097152`. Preserve v3/v4 parsers for historical fixtures, but make v5 current.

Update scanner function parameter types to accept the shared JavaScript-analysis shape without weakening either strict config schema. Change `prepare-target.ts` and the scanner smoke command to load v5; historical v4 unit fixtures continue to parse through `ScannerPolicyV4Schema`.

- [ ] **Step 4: Add target-scoped budget failure classification**

Add `MODEL_REVIEW_BUDGET_EXCEEDED` to `TargetSystemCodes`; do not add a public diagnostic containing token or prompt data.

- [ ] **Step 5: Run focused tests**

Run: `npm.cmd test -- tests/policy.test.ts tests/failure.test.ts tests/scan-package.test.ts`

Expected: PASS.

- [ ] **Step 6: Commit**

```powershell
git add config/scanner-policy.v5.json config/contextual-review.v5.json src/config/policy.ts src/operations/failure.ts src/orchestrator/scan-handler.ts src/scanners/run-scanners.ts src/scanners/javascript-analysis.ts src/cli/prepare-target.ts scripts/smoke-scanners.ts tests/policy.test.ts tests/failure.test.ts tests/scan-package.test.ts
git commit -m "feat: define policy v5 review budgets"
```

### Task 2: Conservative execution-scope analysis

**Files:**

- Create: `src/triage/execution-scope.ts`
- Create: `tests/execution-scope.test.ts`
- Modify: `src/context/evidence-context.ts`
- Modify: `src/orchestrator/session.ts`
- Modify: `tests/evidence-context.test.ts`
- Modify: `tests/scan-session.test.ts`

**Interfaces:**

- Produces: `ExecutionScope = "runtime" | "install-update" | "automation" | "tooling-only" | "test-documentation-data" | "unknown"`.
- Produces: `analyzeExecutionScopes(input: { root: string; files: readonly InventoryFile[]; limits: ExecutionScopeLimits }): Promise<ReadonlyMap<string, ExecutionScope>>`.
- Consumes: inventory-verified paths and bytes; source graph reads are capped by policy and any unresolved path returns `unknown`.
- Extends: `EvidenceContextGroupSchema` with required `execution_scope`.

- [ ] **Step 1: Write a failing table test for observable scope decisions**

```ts
it.each([
  ["src/index.js", "runtime"],
  ["scripts/release.mjs", "automation"],
  ["scripts/postinstall.mjs", "install-update"],
  ["scripts/local-check.mjs", "tooling-only"],
  ["tests/fixture.js", "test-documentation-data"],
  ["src/computed-loader.js", "unknown"],
] as const)("classifies %s as %s", async (path, expected) => {
  const scopes = await analyzeExecutionScopes(fixture.input);
  expect(scopes.get(path)).toBe(expected);
});
```

The fixture must use a real temporary directory and real files: package `exports` reaches `src/index.js`; a workflow reaches `scripts/release.mjs`; `postinstall` reaches `scripts/postinstall.mjs`; `scripts/local-check.mjs` is unreferenced; and a computed import prevents proof for `src/computed-loader.js`.

- [ ] **Step 2: Run the new test and observe the missing module**

Run: `npm.cmd test -- tests/execution-scope.test.ts`

Expected: FAIL because `analyzeExecutionScopes` does not exist.

- [ ] **Step 3: Implement bounded source loading and graph roots**

Parse only inventory-verified UTF-8 files within all three policy limits. Roots are package `main`, `module`, `exports`, and `bin`; `preinstall`, `install`, `postinstall`, update, and migration scripts; `.github/workflows/*.yml`, `.yaml`, and local action commands; plus explicit SillyTavern entry files such as root `index.js`, `script.js`, and `server.js` when present. Traverse only statically resolvable relative imports/requires. A missing file, dynamic/computed import, over-limit source, parse ambiguity, or conflicting scope marks the affected node `unknown`.

- [ ] **Step 4: Run the scope test**

Run: `npm.cmd test -- tests/execution-scope.test.ts`

Expected: PASS.

- [ ] **Step 5: Persist the scope on evidence groups**

Pass the map into `buildEvidenceContextGroups`; historical findings and paths absent from the map receive `unknown`. Preserve the current `file_role` as presentation metadata, but do not use it as a substitute for reachability.

- [ ] **Step 6: Prove evidence identities include scope**

Add a test that changes only `execution_scope` and expects the evidence bundle digest to change, then run:

Run: `npm.cmd test -- tests/evidence-context.test.ts tests/scan-session.test.ts`

Expected: PASS.

- [ ] **Step 7: Commit**

```powershell
git add src/triage/execution-scope.ts src/context/evidence-context.ts src/orchestrator/session.ts tests/execution-scope.test.ts tests/evidence-context.test.ts tests/scan-session.test.ts
git commit -m "feat: classify evidence execution scope"
```

### Task 3: Pure deterministic triage and behavior-case partitioning

**Files:**

- Create: `src/triage/review-triage.ts`
- Create: `tests/review-triage.test.ts`
- Modify: `src/policy/rule-descriptions.ts`
- Modify: `tests/rule-descriptions.test.ts`

**Interfaces:**

- Produces: `AssessmentSourceSchema = z.enum(["deterministic-policy", "contextual-model"])`.
- Produces: `TriageReasonCodeSchema` as a bounded lower-case kebab identifier.
- Produces: `triageEvidenceGroups(groups: readonly EvidenceContextGroup[]): ReviewTriagePlan`.
- `ReviewTriagePlan` contains `deterministicAssessments`, filtered `contextualGroups`, one decision per candidate, behavior-case counts, and sorted reason-code counts.
- Advances: `RULE_CATALOG_VERSION` from `1` to `2` and declares every owned rule `deterministic`, `contextual`, or `correlation-only`.

- [ ] **Step 1: Write one failing hard-escalator precedence test**

```ts
const plan = triageEvidenceGroups([
  group({
    execution_scope: "tooling-only",
    candidates: [
      candidate("javascript.xray.unsafe-regex"),
      candidate("javascript.credential-to-network"),
    ],
  }),
]);
expect(plan.deterministicAssessments).toHaveLength(0);
expect(plan.contextualGroups).toHaveLength(1);
expect(plan.contextualGroups[0]?.candidates).toHaveLength(2);
expect(plan.decisions.map((item) => item.reason_code)).toEqual([
  "hard-dangerous-correlation",
  "hard-dangerous-correlation",
]);
```

- [ ] **Step 2: Run the test and observe the missing triage engine**

Run: `npm.cmd test -- tests/review-triage.test.ts`

Expected: FAIL because the module does not exist.

- [ ] **Step 3: Implement schemas, canonical case IDs, and hard escalators**

Hard escalators include credential-to-network, credential exfiltration, download-to-execution, decode-to-execution, install network hooks, persistence, dynamic execution plus a network/credential signal, runtime/installer environment serialization to a sink, and any unknown rule/scope. If one candidate proves a dangerous correlation inside a behavior case, keep the whole case together for contextual review.

- [ ] **Step 4: Run the single test green**

Run: `npm.cmd test -- tests/review-triage.test.ts -t "hard escalator"`

Expected: PASS.

- [ ] **Step 5: Add and implement scanner-policy table rows one at a time**

Use literal expected dispositions and reason codes for these rows:

```ts
[
  [
    "javascript.xray.unsafe-regex",
    "tooling-only",
    "expected_behavior",
    "javascript-unsafe-regex-inert",
  ],
  [
    "javascript.xray.unsafe-regex",
    "runtime",
    "minor_weakness",
    "javascript-unsafe-regex-runtime-low",
  ],
  [
    "javascript.xray.serialize-environment",
    "tooling-only",
    "expected_behavior",
    "javascript-xray-inert-tooling",
  ],
  [
    "javascript.xray.serialize-environment",
    "runtime",
    "contextual-review",
    "runtime-cross-boundary-signal",
  ],
  [
    "javascript.xray.shady-link",
    "test-documentation-data",
    "expected_behavior",
    "javascript-xray-inert-content",
  ],
  [
    "RUSTSEC-2024-0414:pkg:e12ed7daa8c1d8360f101be8",
    "runtime",
    "material_vulnerability",
    "osv-structured-advisory",
  ],
  ["unknown.future-rule", "tooling-only", "contextual-review", "unknown-rule"],
];
```

Expand this into the full six-scope matrix for every known X-Ray rule family and every owned TavernKeeper/OpenGrep rule. The abbreviated rows above anchor the intended semantics; each additional row must name the wrong branch it prevents. Unknown scanner rule IDs and every `unknown` scope row must end in contextual review.

OSV assessments use scanner severity and confidence but set `risk_exposure: "not_demonstrated"` unless structured evidence actually demonstrates exploitation, so merely having an advisory cannot create a yellow rating. Runtime `unsafe-regex` is always bounded to low recommended risk and can never create yellow by itself.

- [ ] **Step 6: Implement remaining scanner defaults conservatively**

Gitleaks is deterministic only for test/fixture content with a locally proven placeholder or invalid token shape; otherwise contextual. Zizmor uses explicit known-rule mappings and unknown rule IDs contextualize. Owned TavernKeeper/OpenGrep rules follow the rule catalog. Malcontent is deterministic only for an explicit high-confidence malicious signature mapping or a proven inert asset mapping; all other runtime binary capability findings contextualize. Encoded-literal is deterministic only when a decoded representation exists and the case contains no execution, network, persistence, credential, or unresolved signal.

- [ ] **Step 7: Prove total partition and deterministic assessment invariants**

Add a test asserting every candidate appears exactly once across deterministic assessments and contextual groups, case/reason counts reconcile, locations cite the original evidence, and every deterministic assessment parses with `ContextualAssessmentSchema`.

Run: `npm.cmd test -- tests/review-triage.test.ts tests/rule-descriptions.test.ts`

Expected: PASS.

- [ ] **Step 8: Commit**

```powershell
git add src/triage/review-triage.ts src/policy/rule-descriptions.ts tests/review-triage.test.ts tests/rule-descriptions.test.ts
git commit -m "feat: triage scanner evidence deterministically"
```

### Task 4: Policy-v5 report provenance and reconciliation

**Files:**

- Modify: `src/contracts/reports-v5.ts`
- Modify: `src/model/contextual-review-contract.ts`
- Modify: `tests/contextual-review-contract.test.ts`
- Modify: `tests/contracts.test.ts`
- Modify: `tests/fixtures/contracts/report.v5.valid.json`
- Modify: `tests/fixtures/contracts/index.v5.valid.json`

**Interfaces:**

- Produces: `PolicyV5AssessmentSchema`, extending current assessment fields with `assessment_source` and `triage_reason_code`.
- Produces: `ReviewTriageV5Schema` with policy version, candidate/case counts, sorted reason counts, configured budget, and actual model calls/tokens.
- Changes: `contextual_reviewer` becomes optional only for policy-v5 reports with zero contextual candidates.
- Keeps: policies 1 through 4 valid under their historical conditional schemas.

- [ ] **Step 1: Write a failing all-deterministic report contract test**

```ts
const report = policy5Report({
  contextual_reviewer: undefined,
  assessments: [deterministicAssessment],
  review_usage: {
    input_tokens: 0,
    output_tokens: 0,
    cache_read_tokens: 0,
    reasoning_tokens: 0,
  },
});
expect(ScanReportV5Schema.parse(report)).toEqual(report);
```

Also mutate `assessment_source`, triage totals, reason counts, and actual token totals independently and expect rejection.

- [ ] **Step 2: Run contract tests red**

Run: `npm.cmd test -- tests/contextual-review-contract.test.ts tests/contracts.test.ts`

Expected: FAIL because policy-v5 provenance is unsupported.

- [ ] **Step 3: Add policy-conditional assessment and triage schemas**

For policy 5 require every assessment source/reason, `review_triage.candidates.total === candidates.length`, deterministic plus contextual equals total, contextual reused does not exceed contextual, all reason counts sum to total, and actual model usage/calls equal `review_usage`/`review_batches`. Reject a missing reviewer when contextual candidates exist; reject a reviewer on an all-deterministic report only if the report claims a model call.

- [ ] **Step 4: Update historical fixture conditionals without rewriting old reports**

Keep policy 1-4 fixtures accepted exactly as declared. Add a policy-5 valid fixture with a deterministic assessment and zero model usage.

- [ ] **Step 5: Run contract tests**

Run: `npm.cmd test -- tests/contextual-review-contract.test.ts tests/contracts.test.ts`

Expected: PASS.

- [ ] **Step 6: Commit**

```powershell
git add src/contracts/reports-v5.ts src/model/contextual-review-contract.ts tests/contextual-review-contract.test.ts tests/contracts.test.ts tests/fixtures/contracts/report.v5.valid.json tests/fixtures/contracts/index.v5.valid.json
git commit -m "feat: publish policy v5 triage provenance"
```

### Task 5: Hard contextual-review preflight and cumulative budget

**Files:**

- Create: `src/model/contextual-review-budget.ts`
- Create: `tests/contextual-review-budget.test.ts`
- Modify: `src/model/contextual-review.ts`
- Modify: `tests/contextual-review.test.ts`

**Interfaces:**

- Produces: `planContextualReview(groups, reusableGroups, progress, policy): ContextualReviewPlan`.
- Produces: `ReviewBudgetLedger` with `assertBeforeProviderCall()` and `recordCompletion(usage)`.
- Consumes: fresh/reused group identity, resumed `review_units`, persisted `review_batches`, and persisted usage.
- Throws: `ModelRequestError("MODEL_REVIEW_BUDGET_EXCEEDED", "repository", safeMessage)` before a forbidden request.

- [ ] **Step 1: Write a failing preflight test using a real planner**

```ts
const requestCompletion = vi.fn();
await expect(
  reviewEvidenceGroups({
    ...reviewSpec(groupsWith13FreshCases),
    provider: { ...provider, requestCompletion },
  }),
).rejects.toMatchObject({ code: "MODEL_REVIEW_BUDGET_EXCEEDED" });
expect(requestCompletion).not.toHaveBeenCalled();
```

- [ ] **Step 2: Run the preflight test red**

Run: `npm.cmd test -- tests/contextual-review-budget.test.ts -t "before provider"`

Expected: FAIL because the provider is called or no budget error exists.

- [ ] **Step 3: Implement deterministic planning with reusable cases removed**

Reuse the same batch prompt and response-schema token estimator as execution. Count prior fresh `review_units` plus remaining fresh cases on resume. Sum persisted initial estimates plus planned fresh estimates. If cases exceed 12 or estimated input exceeds 200,000, throw before constructing a provider request.

- [ ] **Step 4: Run the preflight test green**

Run: `npm.cmd test -- tests/contextual-review-budget.test.ts -t "before provider"`

Expected: PASS.

- [ ] **Step 5: Add cumulative call/input/output tests one at a time**

Test that a seventh call is never made, a call after 250,000 input tokens is never made, a call after 40,000 output tokens is never made, JSON repair consumes a call, validation-repair splits consume calls, and resumed progress preserves all three totals. Each test asserts the real review function's rejected promise and exact provider call count, not merely the ledger implementation.

- [ ] **Step 6: Make batching use the shared planner and ledger**

Remove duplicate batch sizing from `contextual-review.ts`. Guard immediately before primary and JSON-repair provider requests. Record every completed response's usage before validation so malformed model output cannot escape the token ledger.

- [ ] **Step 7: Run review tests**

Run: `npm.cmd test -- tests/contextual-review-budget.test.ts tests/contextual-review.test.ts`

Expected: PASS.

- [ ] **Step 8: Commit**

```powershell
git add src/model/contextual-review-budget.ts src/model/contextual-review.ts tests/contextual-review-budget.test.ts tests/contextual-review.test.ts
git commit -m "feat: bound contextual review spend"
```

### Task 6: Orchestrate deterministic and contextual partitions

**Files:**

- Modify: `src/orchestrator/session.ts`
- Modify: `src/report/contextual-report.ts`
- Modify: `src/model/review-cache.ts`
- Modify: `tests/scan-session.test.ts`
- Modify: `tests/contextual-report.test.ts`
- Modify: `tests/review-cache.test.ts`

**Interfaces:**

- Consumes: `ReviewTriagePlan` and contextual-only `CompletedContextualReview`.
- Produces: `CompletedReviewV5` with merged assessments, contextual observations, `review_triage`, usage/batches, optional reviewer identity, and contextual-only `review_units`.
- Produces: `review.json` whose `review` is one `CompletedReviewV5`, bound to the session/evidence digest; the contextual-only intermediate is never published directly.
- Produces: complete policy-v5 reports by merging deterministic assessments and contextual-model assessments in candidate-ID order.
- Produces: empty review-cache entries for all-deterministic reports; only contextual-model units are reusable.

- [ ] **Step 1: Write a failing zero-provider session test**

```ts
const requestCompletion = vi.fn();
const reviewed = await reviewPreparedSession({
  ...preparedSessionWithOnlyOsvAndInertXray,
  provider: { ...provider, requestCompletion },
});
expect(requestCompletion).not.toHaveBeenCalled();
expect(reviewed.review.review_triage.candidates.deterministic).toBe(2);
expect(reviewed.review.assessments).toHaveLength(2);
```

- [ ] **Step 2: Run the session test red**

Run: `npm.cmd test -- tests/scan-session.test.ts -t "zero provider"`

Expected: FAIL because all evidence currently reaches the model.

- [ ] **Step 3: Partition before provider validation and persist the result**

Run triage after loading/validating evidence and before loading reuse. If `contextualGroups` is empty, do not validate endpoint credentials and do not call the provider. Synthesize zero contextual usage, then merge deterministic assessments. For contextual groups, preserve current review progress and reuse behavior.

- [ ] **Step 4: Run the zero-provider session test green**

Run: `npm.cmd test -- tests/scan-session.test.ts -t "zero provider"`

Expected: PASS.

- [ ] **Step 5: Add a mixed-partition report test**

Assert two deterministic candidates and one contextual candidate yield three assessments, one provider-reviewed group, one contextual review unit, one triage reason per candidate, and exact total coverage. Model assessments receive `assessment_source: "contextual-model"` and their candidate-specific escalation reason.

- [ ] **Step 6: Update cache boundaries**

`buildReviewCacheManifest` receives only contextual units. `loadReusableReviewGroups` ignores deterministic assessments and accepts policy-v5 reports with optional reviewer only when the manifest has zero entries. Preserve the rule that only low, not-demonstrated contextual responses are reusable.

- [ ] **Step 7: Run integration tests**

Run: `npm.cmd test -- tests/scan-session.test.ts tests/contextual-report.test.ts tests/review-cache.test.ts`

Expected: PASS.

- [ ] **Step 8: Commit**

```powershell
git add src/orchestrator/session.ts src/report/contextual-report.ts src/model/review-cache.ts tests/scan-session.test.ts tests/contextual-report.test.ts tests/review-cache.test.ts
git commit -m "feat: merge deterministic and model review"
```

### Task 7: Public technical-evidence presentation and generated schemas

**Files:**

- Modify: `src/publish/render-report.ts`
- Modify: `src/site/presentation.ts`
- Modify: `src/site/render-landing.ts`
- Modify: `scripts/generate-contract-schemas.ts`
- Modify: `schemas/scan-report.v5.schema.json`
- Modify: `schemas/report-index.v5.schema.json`
- Modify: `tests/report-render.test.ts`
- Modify: `tests/site-presentation.test.ts`
- Modify: `tests/report-sanitize.test.ts`

**Interfaces:**

- Public primary findings: all material/high items and low `minor_weakness` items.
- Collapsed technical evidence: deterministic `expected_behavior` assessments, with count, reason, scanner, execution scope, and source link.
- Public rating: derived from assessment invariants; deterministic unsafe-regex remains low and cannot create yellow.

- [ ] **Step 1: Write a failing renderer test**

```ts
const html = renderReportV5Html(policy5MixedReport);
expect(html).toContain("Deterministic technical evidence (2)");
expect(html).toContain("0 model calls");
expect(html).not.toContain("Minor cautions</h3>");
expect(html).toContain("No material or immediate-danger item was identified");
```

- [ ] **Step 2: Run renderer tests red**

Run: `npm.cmd test -- tests/report-render.test.ts tests/site-presentation.test.ts`

Expected: FAIL because deterministic evidence is rendered as contextual expected matches.

- [ ] **Step 3: Render provenance-aware sections**

Replace the generic expected-match section for policy 5 with a collapsed deterministic technical-evidence section. Keep contextual expected matches separately when present. Show reviewer metadata only when `contextual_reviewer` exists. Show triage counts and configured/actual budgets in technical metadata.

- [ ] **Step 4: Prove low deterministic findings stay green**

Add a `javascript.xray.unsafe-regex` runtime minor weakness with low risk and assert `deriveProjectAdvisory` returns `low`, while existing demonstrated material/high fixtures retain their existing ratings.

- [ ] **Step 5: Generate and validate JSON Schema**

Run: `npm.cmd run contracts:generate`

Then run: `npm.cmd test -- tests/report-render.test.ts tests/site-presentation.test.ts tests/report-sanitize.test.ts tests/contracts.test.ts`

Expected: PASS and generated schema files include policy-v5 conditional fields without invalidating policies 1-4.

- [ ] **Step 6: Commit**

```powershell
git add src/publish/render-report.ts src/site/presentation.ts src/site/render-landing.ts scripts/generate-contract-schemas.ts schemas/scan-report.v5.schema.json schemas/report-index.v5.schema.json tests/report-render.test.ts tests/site-presentation.test.ts tests/report-sanitize.test.ts tests/contracts.test.ts
git commit -m "feat: show deterministic technical evidence"
```

### Task 8: Workflow cutover and regression fixtures

**Files:**

- Modify: `.github/workflows/scan-and-publish.yml`
- Modify: `.github/workflows/targeted-scan.yml`
- Modify: `scripts/check-workflow-policy.mjs`
- Modify: `src/cli/review-target.ts`
- Modify: `tests/workflows.test.ts`
- Modify: `tests/e2e/scan-fixtures.test.ts`
- Create: `tests/fixtures/triage/recursion-candidates.json`
- Create: `tests/fixtures/triage/wandlight-candidates.json`
- Create: `tests/fixtures/triage/directive-candidates.json`

**Interfaces:**

- Workflows load `scanner-policy.v5.json` and `contextual-review.v5.json` but keep provider secrets scoped only to the contextual-review step.
- Regression fixture results expose total, deterministic, contextual, initial batch, and estimated-input counts without invoking a provider.

- [ ] **Step 1: Add failing workflow behavior assertions**

Parse the workflow YAML and assert the preparation step uses scanner policy v5, the contextual step uses review policy v5, provider secrets remain absent from scanner steps, and the timeout/failure handoff accepts `MODEL_REVIEW_BUDGET_EXCEEDED` as target-scoped.

- [ ] **Step 2: Run workflow tests red**

Run: `npm.cmd test -- tests/workflows.test.ts`

Expected: FAIL on v4 paths/current failure handling.

- [ ] **Step 3: Cut workflow inputs to v5 without changing queue scheduling**

Change the review CLI's default policy path to `config/contextual-review.v5.json`. Do not alter queue priority, batch size, parallelism, publication order, or wake behavior. Keep the current pause in operations state; this task changes code paths only.

- [ ] **Step 4: Add sanitized canary candidate fixtures**

Build fixtures only from public candidate metadata and execution-scope labels; include no source excerpts or secret-shaped values. Assert:

```ts
expect(recursion).toMatchObject({ total: 64, contextual: expect.any(Number) });
expect(recursion.contextual).toBeLessThanOrEqual(6);
expect(recursion.initialBatches).toBeLessThanOrEqual(2);
expect(wandlight.contextual).toBeLessThanOrEqual(1);
expect(directive.deterministic / directive.total).toBeGreaterThanOrEqual(0.8);
```

- [ ] **Step 5: Run workflow and fixture tests**

Run: `npm.cmd test -- tests/workflows.test.ts tests/e2e/scan-fixtures.test.ts tests/review-triage.test.ts tests/contextual-review-budget.test.ts`

Expected: PASS.

- [ ] **Step 6: Commit**

```powershell
git add .github/workflows/scan-and-publish.yml .github/workflows/targeted-scan.yml scripts/check-workflow-policy.mjs src/cli/review-target.ts tests/workflows.test.ts tests/e2e/scan-fixtures.test.ts tests/fixtures/triage
git commit -m "feat: cut scan workflow to policy v5"
```

### Task 9: Tavernary strict policy-v5 reader before publication

**Files (in a fresh Tavernary worktree based on current `origin/main`):**

- Modify: `data/schemas/tavernkeeper-scan-report.v5.schema.json`
- Modify: `data/schemas/tavernkeeper-report-index.v5.schema.json`
- Modify: `scripts/security/tavernkeeper-reports.mjs`
- Modify: `scripts/security/tavernkeeper-reports.d.mts`
- Modify: `tests/unit/tavernkeeper-reports.test.ts`
- Modify: `tests/fixtures/tavernkeeper/scan-report.v5.valid.json`
- Modify: `tests/fixtures/tavernkeeper/report-index.v5.valid.json`

**Interfaces:**

- Consumes: the exact generated TavernKeeper policy-v5 schemas from Task 7.
- Accepts: optional `contextual_reviewer` only when policy-v5 triage permits it, policy-v5 assessment provenance, `review_triage`, metadata-only evidence limitations, and JavaScript coverage fields.
- Rejects: triage/count/source mismatches before storing or synthesizing a report.

- [ ] **Step 1: Create an isolated Tavernary worktree without touching its dirty root**

```powershell
git -c safe.directory=F:/git/Tavernary -C F:\git\Tavernary fetch origin main
git -c safe.directory=F:/git/Tavernary -C F:\git\Tavernary worktree add F:\git\Tavernary\.worktrees\tavernkeeper-policy-v5-reader -b codex/tavernkeeper-policy-v5-reader origin/main
```

- [ ] **Step 2: Write a failing importer acceptance/rejection test**

Use a real policy-v5 JSON fixture. Assert `validateScanReport` accepts the exact body/index pair, then separately corrupt `assessment_source`, triage totals, reason counts, and zero-call reviewer conditions and assert rejection.

- [ ] **Step 3: Run focused Tavernary tests red**

Run: `npm.cmd test -- tests/unit/tavernkeeper-reports.test.ts`

Expected: FAIL under the copied old schema/reader.

- [ ] **Step 4: Copy generated schemas and implement semantic checks**

Copy the two generated files byte-for-byte from TavernKeeper. Extend `assertReportCoverage` to reconcile `review_triage` and review usage. Update TypeScript declarations with assessment source, reason code, execution scope, optional reviewer, and triage telemetry. Do not loosen AJV strict shape checks.

- [ ] **Step 5: Run focused and full Tavernary verification**

Run: `npm.cmd test -- tests/unit/tavernkeeper-reports.test.ts`

Then run the repository's documented full `npm.cmd test`, typecheck, catalog build, and static export checks.

Expected: all pass.

- [ ] **Step 6: Commit, push, open PR, and merge before TavernKeeper publication**

```powershell
git add data/schemas/tavernkeeper-scan-report.v5.schema.json data/schemas/tavernkeeper-report-index.v5.schema.json scripts/security/tavernkeeper-reports.mjs scripts/security/tavernkeeper-reports.d.mts tests/unit/tavernkeeper-reports.test.ts tests/fixtures/tavernkeeper/scan-report.v5.valid.json tests/fixtures/tavernkeeper/report-index.v5.valid.json
git commit -m "feat: accept TavernKeeper policy v5 reports"
git push origin codex/tavernkeeper-policy-v5-reader
```

Use `gh` to open the PR, wait for required checks, merge it, and verify the merge SHA on `origin/main` before continuing.

### Task 10: Full TavernKeeper verification and protected canary rollout

**Files:**

- Modify only after code merges: `operations/state.json` and the exact canary report/preferred-index artifacts required by the existing reset procedure.

**Interfaces:**

- Gate transition: `POLICY_V4_CANARY_GATE` to `POLICY_V5_CANARY_GATE` while still paused.
- Canary order: Wandlight plus Recursion as the only two staff targets, then Directive.
- Resume condition: all scanner coverage, triage counts, token ledgers, ratings, publication, and Tavernary imports verified.

- [ ] **Step 1: Run fresh TavernKeeper verification**

Run: `npm.cmd run check`

Expected: format, typecheck, all unit/integration tests, and workflow policy checks pass from a clean tree.

- [ ] **Step 2: Review the complete branch diff and generated artifacts**

Run: `git diff origin/main...HEAD --check`

Run: `git status --short`

Expected: no whitespace errors and only intentional committed changes.

- [ ] **Step 3: Push TavernKeeper and merge through required checks**

```powershell
git push origin codex/deterministic-review-triage
```

Open a PR with `gh`, wait for all required checks, merge, and verify the remote main SHA. Do not alter the production pause before the merge.

- [ ] **Step 4: Change only the pause reason to policy v5**

Use the existing protected operations-state transaction to set `POLICY_V5_CANARY_GATE`, keeping `staff_requested` empty and all ordinary queue claims inert. Verify active scans are zero before and after the state change.

- [ ] **Step 5: Reset and queue only Wandlight and Recursion**

Apply the documented clean canary reset to repository IDs 1254077407 and 1285208664. Prove their public report/preferred-index entries and Tavernary imported summaries are absent before queuing. Queue exactly those two staff targets and confirm two parallel lanes claim no other repository.

- [ ] **Step 6: Verify canary acceptance facts**

For each report verify all eight tools, complete JavaScript coverage, every candidate represented once, triage reason totals, provider call count, input/output/cache/reasoning totals, independent publication, and exact Tavernary import. Recursion must use at most 200,000 input and 40,000 output tokens, at most 6 contextual candidates and 2 initial batches, preserve its low regex weakness, and remain non-yellow absent a material finding. Wandlight must have at most 1 contextual candidate.

- [ ] **Step 7: Run Directive oversized canary**

Reset and queue only Directive. Accept either a completed report with at least 80 percent deterministic triage inside all budgets, or `MODEL_REVIEW_BUDGET_EXCEEDED` before the first provider call. Any provider use followed by a preflight budget failure is a canary failure.

- [ ] **Step 8: Resume normal scanning only after all canaries pass**

Clear the v5 canary gate using the existing state transaction. Confirm two lanes, per-target publication, and queue priority remain new submissions, updated projects, then the frozen 20-plus-20 cohort. Confirm no catalog-wide policy-v5 entries were added.

- [ ] **Step 9: Record final operational evidence**

Capture merge SHAs, workflow run IDs, report IDs, scanner coverage, triage counts, model usage, Tavernary import deployment SHA, queue counts, and the first normal two-lane claim. This evidence is required before declaring the feature complete.
