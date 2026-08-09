# Advisory Color Calibration Implementation Plan

> **For Codex:** Use `superpowers:executing-plans` and
> `superpowers:subagent-driven-development` to execute this plan task by task.

**Goal:** Make teal, yellow, and red follow the demonstrated-risk contract in
TavernKeeper and Tavernary, then deterministically recolor existing summaries
without rescanning repositories or calling Luna.

**Architecture:** TavernKeeper adds a strict exposure field to new contextual
reviews, validates advisory severity structurally, retains bounded OSV package
identity, and separates coverage limitations from risk. Tavernary advances its
synthesis policy, applies the same deterministic classifier to legacy reports,
and migrates unchanged summaries without model use.

**Tech stack:** TypeScript, Node.js ESM, Zod, Vitest, GitHub Actions, GitHub CLI.

---

## Task 1: Add the exposure-aware TavernKeeper review contract

**Files:**

- Modify: `src/model/contextual-review-contract.ts`
- Modify: `src/model/contextual-prompt.ts`
- Modify: `src/model/contextual-review.ts`
- Modify: `src/model/openai-compatible-client.ts`
- Modify: `src/contracts/reports-v5.ts`
- Test: `tests/contextual-review-contract.test.ts`
- Test: `tests/contextual-prompt.test.ts`
- Test: `tests/contextual-review.test.ts`
- Test: `tests/provider-compatibility.test.ts`

### Step 1: Write failing contract tests

Add fixtures proving:

- material risk without `risk_exposure: "demonstrated"` is rejected;
- demonstrated/high-confidence/medium-or-greater/plausible-or-greater material
  risk is accepted;
- the critical/readily/high and credible-malicious branches require
  demonstrated exposure;
- non-demonstrated uncertainty is accepted only at low risk; and
- old published assessments without the field still parse under old report
  policy versions.

Run:

```powershell
npm.cmd test -- tests/contextual-review-contract.test.ts
```

Expected: FAIL for the missing exposure contract.

### Step 2: Implement the schema and version transition

Add `RiskExposureSchema` with `not_demonstrated` and `demonstrated`, require it
in new model assessment and observation objects, and enforce the public color
predicate. Advance contextual policy, prompt, and assessment schema versions
together. Retain explicit legacy published schemas so immutable policy-1 and
policy-2 reports continue to validate.

Add `assessment_risk_exposure` diagnostics and repair guidance. Update progress
and completed-review schemas and fixtures to policy 3.

### Step 3: Update the prompt

Define demonstrated exposure precisely. State that advisory presence,
same-file correlation, metadata-only evidence, and incomplete coverage are not
demonstrated exposure. Replace the final-attempt material-uncertainty instruction
with non-demonstrated, low-risk output.

### Step 4: Run focused tests

```powershell
npm.cmd test -- tests/contextual-review-contract.test.ts tests/contextual-prompt.test.ts tests/contextual-review.test.ts tests/provider-compatibility.test.ts
npm.cmd run typecheck
```

Expected: PASS.

### Step 5: Commit

```powershell
git add src/model/contextual-review-contract.ts src/model/contextual-prompt.ts src/model/contextual-review.ts src/model/openai-compatible-client.ts src/contracts/reports-v5.ts tests/contextual-review-contract.test.ts tests/contextual-prompt.test.ts tests/contextual-review.test.ts tests/provider-compatibility.test.ts
git commit -m "fix(review): require demonstrated yellow risk"
```

## Task 2: Preserve bounded OSV package identity

**Files:**

- Modify: `src/scanners/osv.ts`
- Test: `tests/conditional-scanners.test.ts`

### Step 1: Write the failing adapter test

Assert that the normalized finding retains the sanitized ecosystem, package
name, and resolved version already present in OSV JSON, while excluding raw
advisory prose and URLs. Add malformed and overlong identity cases.

Run:

```powershell
npm.cmd test -- tests/conditional-scanners.test.ts
```

Expected: FAIL because current output says package details were removed.

### Step 2: Implement bounded normalization

Parse only bounded strings for `package.name`, `package.version`, and
`package.ecosystem`. Put them in the fixed candidate title/explanation after
safe normalization. Reject malformed structured results rather than silently
dropping identity. Do not ingest advisory detail text or references.

### Step 3: Verify and commit

```powershell
npm.cmd test -- tests/conditional-scanners.test.ts
npm.cmd run typecheck
git add src/scanners/osv.ts tests/conditional-scanners.test.ts
git commit -m "fix(osv): retain bounded package identity"
```

Expected: PASS.

## Task 3: Separate TavernKeeper coverage from advisory color

**Files:**

- Modify: `src/site/presentation.ts`
- Modify: `src/publish/render-report.ts`
- Modify: `docs/SCANNING.md`
- Modify: `docs/SECURITY_MODEL.md` if it describes risk floors
- Test: `tests/site-presentation.test.ts`
- Test: `tests/contextual-report.test.ts`
- Test: `tests/site-build.test.ts`

### Step 1: Write failing presentation tests

Prove that incomplete JavaScript and metadata-only evidence remain teal when no
qualifying item exists. Prove strict yellow and red fixtures, including the
legacy imported-template execution example and dependency/correlation
downgrades.

Run:

```powershell
npm.cmd test -- tests/site-presentation.test.ts tests/contextual-report.test.ts
```

Expected: FAIL because coverage currently creates a material floor.

### Step 2: Implement calibrated derivation

Remove coverage promotion. For new items, use `risk_exposure` plus the strict
tuple. For legacy items, apply the documented tuple conservatively. Preserve
the existing red basis, requiring demonstrated exposure for new policy-3
items. Keep limitations and unresolved coverage rendering unchanged.

Update public documentation to define all three colors and state that coverage
limitations never alter them.

### Step 3: Verify and commit

```powershell
npm.cmd test -- tests/site-presentation.test.ts tests/contextual-report.test.ts tests/site-build.test.ts
npm.cmd run typecheck
git add src/site/presentation.ts src/publish/render-report.ts docs/SCANNING.md docs/SECURITY_MODEL.md tests/site-presentation.test.ts tests/contextual-report.test.ts tests/site-build.test.ts
git commit -m "fix(site): separate coverage from advisory risk"
```

Expected: PASS. Omit `docs/SECURITY_MODEL.md` from staging if no edit is
required.

## Task 4: Verify TavernKeeper as a complete unit

Run:

```powershell
npm.cmd run check
npm.cmd run build
git diff --check
git status --short
```

Expected: all required checks pass and only intentional ignored SDD artifacts
remain. Request an independent spec and code review before publishing.

## Task 5: Create a clean Tavernary implementation checkout

The existing `F:\git\Tavernary` checkout contains unrelated user changes and
must not be touched.

```powershell
gh repo clone MentallyQuill/Tavernary F:\git\TavernKeeper\.worktrees\tavernary-yellow-calibration -- --branch main
git switch -c codex/advisory-color-calibration
```

Verify the clone's `HEAD` equals GitHub `main`, its worktree is clean, and the
three user-modified files in `F:\git\Tavernary` remain unchanged.

## Task 6: Implement Tavernary synthesis policy 5

**Files in the clean Tavernary checkout:**

- Modify: `scripts/security/tavernkeeper-assessment-contract.mjs`
- Modify: `scripts/security/tavernkeeper-synthesis.mjs`
- Modify: `scripts/security/tavernkeeper-reports.mjs`
- Modify: adjacent `.d.mts` declarations where exported shapes change
- Test: the focused assessment-contract and report-validation unit tests found
  by `rg -n "deriveReportAdvisory|assessment_source|synthesis_policy" tests`

### Step 1: Write failing classifier tests

Cover:

- coverage-only and metadata-only teal;
- legacy dependency and broad-correlation teal;
- test/fixture/documentation/tooling findings teal;
- legacy shipped-code execution yellow;
- new demonstrated material yellow;
- new non-demonstrated material-looking evidence teal; and
- malicious and critical/readily exploitable red.

Expected counts must classify downgraded non-expected items as minor cautions,
not material concerns.

### Step 2: Implement the shared deterministic classifier

Advance synthesis policy to 5. Derive advisory and calibrated counts from the
report plus its candidates. New `risk_exposure` is authoritative. Legacy
findings use the conservative tuple and shipped-file-role checks. Remove all
coverage floors. Allow `assessment_source: "deterministic_regrade"`.

Update Luna synthesis requirements to use calibrated counts and the exact
teal/yellow/red contract.

### Step 3: Verify and commit

Run the focused unit tests and typecheck discovered from `package.json`, then:

```powershell
git add scripts/security tests
git commit -m "fix(security): calibrate advisory colors"
```

## Task 7: Add Tavernary's no-model legacy migration

**Files in the clean Tavernary checkout:**

- Modify: `scripts/security/import-tavernkeeper-reports.mjs`
- Modify: `scripts/security/tavernkeeper-import-state.mjs` if policy-state
  validation changes
- Modify: adjacent `.d.mts` declarations
- Test: importer/reconciliation unit tests found by
  `rg -n "reconcileTavernKeeperReports|deterministic_fallback" tests`

### Step 1: Write failing migration tests

Use a synthesis spy that throws if called. Prove:

- unchanged low policy-4 summaries upgrade directly to policy 5;
- unchanged non-low summaries fetch immutable report JSON and receive
  `deterministic_regrade` without synthesis;
- new contextual-policy-3 reports still use Luna synthesis;
- new legacy-policy reports use deterministic regrade; and
- repeated reconciliation is idempotent.

### Step 2: Implement bounded migration

Split same-report legacy migrations from new or changed reports. Directly
migrate unchanged low summaries. Fetch and deterministically regrade legacy
non-low reports with bounded work. Never initialize the provider on a legacy
migration-only run. Preserve quarantine semantics for actual model synthesis.

### Step 3: Verify and commit

Run focused importer tests and typecheck, then:

```powershell
git add scripts/security tests
git commit -m "fix(security): regrade legacy reports offline"
```

## Task 8: Full verification, publication, and live proof

1. Run Tavernary's full repository check and production build.
2. Independently review both repository diffs against the design.
3. Push both branches and open focused pull requests.
4. Merge TavernKeeper first, then Tavernary.
5. Verify exact merged SHAs in required Actions and Pages deployments.
6. Run Tavernary reconciliation until every preferred report uses synthesis
   policy 5. Record provider-call count and prove migration calls are zero.
7. Inspect hydrated Tavernary cards and linked TavernKeeper reports for:
   coverage-only teal, legacy dependency teal, imported-template yellow, and
   unchanged red semantics.
8. Keep the emergency stop active until the one-time campaign implementation
   and incremental queue migration are also verified.

Do not dispatch a catalog rescan during this task.
