# Report Consistency and Yellow Rescan Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make landing and detail report colors use one evidence-derived advisory and create an auditable policy-v5 campaign for the 13 reports that are yellow at dispatch time.

**Architecture:** Export one report-level advisory derivation boundary from the report renderer and make the Pages builder supply its result to the landing renderer. Extend the existing policy-rescan CLI and protected workflow with a validated `yellow` scope that snapshots current yellow repository IDs into the durable campaign.

**Tech Stack:** TypeScript, Zod, Vitest, GitHub Actions YAML, Node.js 24.

## Global Constraints

- Preserve `reports/index.json` as the immutable projection of original report counters.
- Active scans use scanner policy 5, contextual-review policy 5, prompt `contextual-review-v7`, and schema `contextual-assessment-v2`.
- The approved yellow campaign snapshots exactly the entries yellow when the campaign is created.
- Preserve protected staff authorization, Publisher App token isolation, bounded retries, and the durable reconciliation queue.

---

### Task 1: Share report advisory derivation with the landing build

**Files:**
- Modify: `src/publish/render-report.ts`
- Modify: `src/site/render-landing.ts`
- Modify: `src/site/build-site.ts`
- Test: `tests/site-build.test.ts`
- Test: `tests/favicon.test.ts`

**Interfaces:**
- Produces: `deriveReportAdvisory(report: ScanReportV5): ProjectAdvisory`.
- Consumes: `renderLandingHtml(index: ReportIndexV5, advisories: ReadonlyMap<string, ProjectAdvisory>): string`.

- [ ] **Step 1: Write the failing site-build regression**

Create a valid report whose evidence derives `low`, override only its projected index `recommended_risk` counts to `{ low: 0, material: 1, high: 0 }`, build the site, and assert both landing and detail HTML contain `risk-low` and no material summary.

- [ ] **Step 2: Run the focused test and verify RED**

Run: `npm.cmd test -- tests/site-build.test.ts`

Expected: FAIL because the landing page still renders the index as material while the detail page renders the report evidence as low.

- [ ] **Step 3: Implement the shared derivation and required advisory map**

Export the existing report-level candidate/assessment/observation composition from `render-report.ts`. Load preferred reports before rendering in `build-site.ts`, derive a literal `Map<report_id, ProjectAdvisory>`, and require each landing card to receive its matching advisory.

- [ ] **Step 4: Update direct renderer tests and verify GREEN**

Update direct `renderLandingHtml` callers to pass an advisory map. Run:

`npm.cmd test -- tests/site-build.test.ts tests/favicon.test.ts tests/site-presentation.test.ts tests/contextual-report.test.ts`

Expected: PASS.

- [ ] **Step 5: Commit the site consistency change**

Commit message: `fix(site): unify report advisory rendering`

### Task 2: Add a frozen yellow policy-rescan scope

**Files:**
- Modify: `src/cli/policy-rescan.ts`
- Modify: `.github/workflows/policy-rescan.yml`
- Create: `tests/policy-rescan.test.ts`
- Modify: `tests/workflows.test.ts`

**Interfaces:**
- Produces: `selectPolicyRescanRepositoryIds({ scope, manifest, index }): number[]`.
- Consumes environment variable `TAVERNKEEPER_POLICY_RESCAN_SCOPE` with exact values `all` or `yellow`.

- [ ] **Step 1: Write failing CLI selection tests**

Use complete V5 index and target-manifest fixtures. Assert `all` preserves manifest order, `yellow` returns only manifest repositories whose preferred index reports have material/high counts, removed index repositories are excluded, unsupported scope throws, and an empty yellow selection throws.

- [ ] **Step 2: Run the CLI tests and verify RED**

Run: `npm.cmd test -- tests/policy-rescan.test.ts`

Expected: FAIL because the selection interface does not exist.

- [ ] **Step 3: Implement minimal validated selection and campaign creation**

Parse the scope with Zod, parse `reports/index.json` with `parseReportIndexV5`, snapshot the selected IDs into the new policy campaign, and include `scope` and `repositories` in CLI output. Keep `all` as the default.

- [ ] **Step 4: Add and verify workflow input coverage**

Add a protected workflow choice input with options `[all, yellow]`, default `all`, and pass it only as `TAVERNKEEPER_POLICY_RESCAN_SCOPE` to the campaign step. Assert the structure in `tests/workflows.test.ts`.

Run: `npm.cmd test -- tests/policy-rescan.test.ts tests/workflows.test.ts`

Expected: PASS.

- [ ] **Step 5: Commit the campaign change**

Commit message: `feat(scans): target yellow policy rescans`

### Task 3: Verify, review, publish, and execute

**Files:**
- Verify all modified source, test, workflow, and documentation files.

- [ ] **Step 1: Run local verification**

Run: `npm.cmd run check`, `npm.cmd run build`, and `npm.cmd run test:e2e`.

Expected: formatting, type checking, 794+ unit tests, workflow policy, build, and hostile fixtures all pass.

- [ ] **Step 2: Review the final diff**

Confirm there are no changes to generated reports, operations state, credentials, unrelated code, or the user-owned primary/nested checkouts.

- [ ] **Step 3: Publish through a reviewed branch**

Push `codex/report-consistency-yellow-rescan`, open a ready pull request, wait for required checks, merge to `main`, and verify the merge SHA.

- [ ] **Step 4: Dispatch the frozen yellow campaign**

Run: `gh workflow run policy-rescan.yml --ref main -f scope=yellow`.

Verify the campaign commit contains 13 unique approved repository IDs and scanner policy version `5` before allowing ordinary reconciliation to continue.

- [ ] **Step 5: Monitor publication and deployment**

Follow the policy workflow, reconciliation child scans, report publications, CI, and Pages deployment. Verify each target's preferred report uses scanner/contextual policy 5 and assessment schema 2.

- [ ] **Step 6: Verify the public outcome**

Compare deployed `reports/index.json`, the reports landing card, and each corresponding detail page. VectHare and every other target must have consistent landing/detail display risk, with any remaining yellow status backed by the new policy-5 report.
