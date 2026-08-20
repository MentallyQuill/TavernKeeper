# Contextual Review Opportunity Analyzer Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a strict, reproducible Policy 5 corpus analyzer, promote the bounded Zizmor `artipacked` condition to existing deterministic structured-weakness triage, measure the historical reduction honestly, and restart scanning through one gated canary.

**Architecture:** A pure analysis service accepts the preferred V5 index plus an injected report loader, validates every selected report, joins candidates to contextual-model assessments, and returns a strict versioned result. A pure renderer and thin filesystem CLI provide stable JSON or Markdown. The rule change extends the existing pinned Zizmor allowlist without suppressing evidence or weakening group-wide hard escalation.

**Tech Stack:** TypeScript 6, Node 24, Zod 4, Vitest 4

**Spec:** `docs/superpowers/specs/2026-08-20-contextual-review-opportunity-analyzer-design.md`

## Global Constraints

- Keep model-cost maintenance active throughout development, PR review, and merge.
- Analyze only preferred entries in `reports/index.json`; never walk report history.
- Fail on missing, malformed, or identity-mismatched selected reports.
- Count only `assessment_source: "contextual-model"` assessments as opportunities.
- Never infer executable rules from model prose or claim exact per-rule token/call savings.
- Keep findings visible. `artipacked` becomes deterministic `structured-weakness`; it is not suppressed or declared safe.
- Preserve contextual fallback for unknown rules and for every candidate in a hard-escalated evidence group.
- Use one staff-authorized canary while maintenance remains active; reopen the scheduler only after the canary passes.

---

## Task 1: Pure corpus analysis contract and service

**Files:**

- Create: `src/analysis/review-opportunities.ts`
- Create: `tests/review-opportunities.test.ts`
- Reuse: `tests/helpers/v5-report.ts`

- [ ] Write the failing tests first. Build two Policy 5 fixture reports and a preferred V5 index derived from their identities. Cover:

  1. preferred entries load once and other policy versions are counted as skipped;
  2. only contextual-model assessments are grouped;
  3. material/high/demonstrated outcomes remain in counts;
  4. distinct repositories and bounded references are exact;
  5. report usage is deduplicated within each opportunity and explicitly non-additive;
  6. contextual reuse is surfaced as an unmapped limitation;
  7. malformed and identity-mismatched selected reports reject;
  8. input order does not affect output order.

  The test index uses the same fields as each validated fixture report:

  ```ts
  function indexEntry(report: ScanReportV5): ReportIndexEntryV5 {
    return ReportIndexEntryV5Schema.parse({
      report_id: report.report_id,
      report_digest: report.report_digest,
      report_version: report.report_version,
      supersedes_report_id: report.supersedes_report_id,
      scanner_version: report.scanner_version,
      scanner_policy_version: report.scanner_policy_version,
      rule_catalog_version: report.rule_catalog_version,
      package_schema_version: report.package_schema_version,
      contextual_review_policy_version: report.contextual_review_policy_version,
      ecosystem_context_version: report.ecosystem_context_version,
      prompt_version: report.prompt_version,
      assessment_schema_version: report.assessment_schema_version,
      source_id: report.source_id,
      provider: report.provider,
      repository_id: report.repository_id,
      repository: report.repository,
      target_sha: report.target_sha,
      completed_at: report.completed_at,
      assessment_method: report.assessment_method,
      counts: report.counts,
      coverage: {
        history_commits: report.history.commits,
        inventory_files: report.coverage.inventory.files,
        inventory_bytes: report.coverage.inventory.bytes,
        tools_completed: report.coverage.tools.filter(
          ({ status }) => status === "completed",
        ).length,
        tools_not_applicable: report.coverage.tools.filter(
          ({ status }) => status === "not-applicable",
        ).length,
        evidence_validated:
          report.coverage.evidence_validation.validated_candidates,
        metadata_only_candidates:
          report.coverage.evidence_validation.status ===
          "completed-with-limitations"
            ? report.coverage.evidence_validation.metadata_only_candidates
            : 0,
        review_required: report.review_coverage.required,
        review_completed: report.review_coverage.completed,
        javascript_analysis_status: "complete",
      },
      report_url:
        `https://mentallyquill.github.io/TavernKeeper/reports/github/${report.repository_id}/` +
        `${report.target_sha}/${report.scanner_policy_version}/${report.report_id}/`,
      history_url: `https://mentallyquill.github.io/TavernKeeper/reports/github/${report.repository_id}/history/`,
    });
  }
  ```

- [ ] Run the focused test and confirm RED because the module does not exist:

  ```powershell
  npm.cmd test -- tests/review-opportunities.test.ts
  ```

- [ ] Implement strict versioned schemas and exported inferred types in `src/analysis/review-opportunities.ts`. The public result has this shape:

  ```ts
  export const ReviewOpportunityAnalysisSchema = z.strictObject({
    schema_version: z.literal(1),
    contextual_policy_version: z.literal("5"),
    attribution: z.strictObject({
      candidate_counts: z.literal("exact"),
      corpus_usage: z.literal("exact"),
      associated_usage: z.literal("overlapping-non-additive"),
      per_rule_savings: z.literal("not-attributable"),
    }),
    corpus: z.strictObject({
      indexed_reports: CountSchema,
      loaded_reports: CountSchema,
      skipped_policy_reports: CountSchema,
      contextual_candidates: CountSchema,
      provider_calls: CountSchema,
      usage: UsageSchema,
      reports_with_unmapped_contextual_reuse: CountSchema,
    }),
    opportunities: z.array(ReviewOpportunitySchema),
  });
  ```

  Each opportunity includes the exact key fields, candidate and repository counts, disposition/exposure/risk counts, bounded references, and an `associated_reports` envelope containing deduplicated report count, provider calls, and usage. The envelope always carries `attribution: "overlapping-non-additive"`.

- [ ] Implement:

  ```ts
  export async function analyzeReviewOpportunities(input: {
    index: unknown;
    loadReport: (entry: ReportIndexEntryV5) => Promise<unknown>;
    contextualPolicyVersion?: "5";
    maxReferencesPerOpportunity?: number;
  }): Promise<ReviewOpportunityAnalysis>;
  ```

  Parse `input.index` with `ReportIndexV5Schema`. Skip entries whose scanner/contextual policy is not exactly `5`. Parse every selected loader result with `ScanReportV5Schema` and compare `report_id`, `report_digest`, `repository_id`, `repository`, `source_id`, `target_sha`, `scanner_version`, `scanner_policy_version`, `rule_catalog_version`, `contextual_review_policy_version`, `prompt_version`, and `assessment_schema_version` against the index entry.

  Join each contextual-model assessment to the candidate with the same `candidate_id`. Throw if no candidate exists. Group by a JSON encoding of:

  ```ts
  {
    origin,
    rule_id,
    scanner_version,
    execution_scope: candidate.execution_scope ?? "unknown",
    file_role,
    scanner_confidence,
    triage_reason_code,
  }
  ```

  Aggregate report usage once for corpus totals. For each opportunity, deduplicate associated usage by `report_id`. Sort references by repository, target SHA, candidate ID, then path; cap after sorting. Sort opportunities by descending candidate count, descending repository count, then lexicographic stable-key fields. Parse the final object with `ReviewOpportunityAnalysisSchema` before returning it.

- [ ] Run the focused test until GREEN:

  ```powershell
  npm.cmd test -- tests/review-opportunities.test.ts
  ```

- [ ] Refactor only after green: use small accumulator helpers, a single identity verifier, and no filesystem imports in the pure service.

---

## Task 2: Stable renderers and filesystem CLI

**Files:**

- Create: `src/analysis/render-review-opportunities.ts`
- Create: `src/cli/review-opportunities.ts`
- Create: `tests/review-opportunities-cli.test.ts`
- Modify: `package.json`

- [ ] Write failing renderer/CLI tests first. Assert:

  - canonical JSON is `JSON.stringify(analysis, null, 2) + "\n"`;
  - Markdown includes corpus totals, outcome counterexamples, representative references, and the overlapping/non-additive attribution warning next to associated usage;
  - invalid or missing `--format` values fail;
  - the CLI loads exactly `reports/index.json` and the identity-derived preferred report paths;
  - JSON and Markdown output are byte-identical across two runs.

- [ ] Run RED:

  ```powershell
  npm.cmd test -- tests/review-opportunities-cli.test.ts
  ```

- [ ] Implement pure renderers:

  ```ts
  export function renderReviewOpportunitiesJson(
    analysis: ReviewOpportunityAnalysis,
  ): string;

  export function renderReviewOpportunitiesMarkdown(
    analysis: ReviewOpportunityAnalysis,
  ): string;
  ```

  Markdown must say that candidate/project frequencies are exact, corpus usage is exact, and opportunity-associated calls/tokens overlap and cannot be summed or interpreted as avoided spend.

- [ ] Implement a testable CLI entry point:

  ```ts
  export async function reviewOpportunitiesMain(input: {
    cwd: string;
    args: readonly string[];
  }): Promise<string>;
  ```

  Parse exactly `--format json` or `--format markdown`. Read `reports/index.json` using `readJsonFile`; load each selected report from:

  ```ts
  join(
    input.cwd,
    "reports",
    "github",
    String(entry.repository_id),
    entry.target_sha,
    entry.scanner_policy_version,
    entry.report_id,
    "report.json",
  );
  ```

  Direct execution writes the returned string to stdout and uses `safeCliErrorRecord` for body-free stderr failures.

- [ ] Add the package script:

  ```json
  "review-opportunities": "tsx src/cli/review-opportunities.ts"
  ```

- [ ] Run focused tests and a real-corpus smoke:

  ```powershell
  npm.cmd test -- tests/review-opportunities-cli.test.ts
  npm.cmd run review-opportunities -- --format json
  npm.cmd run review-opportunities -- --format markdown
  ```

---

## Task 3: Promote only `zizmor:artipacked`

**Files:**

- Modify: `tests/review-triage.test.ts`
- Modify: `src/triage/review-triage.ts`

- [ ] Add three focused tests before implementation:

  1. `artipacked` in an automation group produces destination `deterministic`, reason `zizmor-known-workflow-rule`, assessment source `deterministic-policy`, and the existing structured-weakness/material-vulnerability result with no demonstrated exposure and low recommended risk;
  2. `future-zizmor-rule` remains contextual with `unknown-rule`;
  3. one group containing `artipacked` plus `javascript.credential-to-network` routes every decision contextually through the hard-escalator reason.

- [ ] Run the focused test and confirm only the new `artipacked` expectation is RED:

  ```powershell
  npm.cmd test -- tests/review-triage.test.ts
  ```

- [ ] Add only `"artipacked"` to `knownZizmorRules`. Do not add text matching, prose parsing, or generic Zizmor fallbacks.

- [ ] Run focused tests until GREEN:

  ```powershell
  npm.cmd test -- tests/review-triage.test.ts
  ```

---

## Task 4: Backtest and operator documentation

**Files:**

- Create: `docs/operations/contextual-review-opportunity-baseline-2026-08-20.md`

- [ ] Run the finished analyzer against the checked-in preferred corpus and capture both formats outside tracked paths:

  ```powershell
  npm.cmd run review-opportunities -- --format json
  npm.cmd run review-opportunities -- --format markdown
  ```

- [ ] Record the exact corpus totals and the full `artipacked` key variants in the baseline document. State:

  - exact candidates and distinct repositories historically affected;
  - disposition, exposure, and recommended-risk distributions, including any counterexample;
  - exact corpus provider/token totals;
  - that associated usage is overlapping and no avoided-call/token number is claimed;
  - that the executable promotion is justified by Zizmor's structured rule identity and existing conservative classification path, not by historical benign frequency.

- [ ] Re-run the analyzer and compare the rendered output to the recorded numbers before committing documentation.

---

## Task 5: Repository verification and independent review

**Files:** all changed files

- [ ] Run fresh focused and full verification:

  ```powershell
  npm.cmd test -- tests/review-opportunities.test.ts tests/review-opportunities-cli.test.ts tests/review-triage.test.ts
  npm.cmd run check
  npm.cmd run build
  git diff --check
  ```

- [ ] Review the complete diff for schema strictness, fail-closed behavior, deterministic ordering, attribution honesty, path containment, and preservation of hard escalation.

- [ ] Request independent code review. Address valid findings with a new failing test first, then rerun the full gate.

- [ ] Commit the implementation with a terse conventional commit and push `codex/contextual-opportunity-analyzer`.

- [ ] Open the PR with the measured corpus results and attribution boundary. Wait for required CI, review all failures, and merge only a green exact head SHA through the protected branch.

---

## Task 6: Gated scanning restart

**Files:** operational state and GitHub Actions only; no source edits unless the canary exposes a defect

- [ ] Confirm merged `main`, maintenance still active, and `active_scans: 0`.

- [ ] Run the repository-free provider protocol check using the configured `TAVERNKEEPER_MODEL`; require a valid response and usage accounting before spending on a repository.

- [ ] While maintenance remains active, issue exactly one staff authorization for the smallest known Policy 5 target that exercises contextual review. Dispatch one scan and verify the authorization is consumed.

- [ ] Require one completed, published report with bounded provider calls, no uncontrolled retry, and valid batch/usage totals. If it fails, leave maintenance active and diagnose without authorizing another target.

- [ ] On success only, clear model-cost maintenance, verify the scheduler observes configured capacity, and confirm it does not bulk-claim beyond that capacity.

- [ ] Publish links to the merged PR, CI, provider check, canary run/report, and the final maintenance/scheduler state in the handoff.
