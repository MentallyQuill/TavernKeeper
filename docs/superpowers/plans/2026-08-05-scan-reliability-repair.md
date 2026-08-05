# Scan Reliability Repair Implementation Plan

**Goal:** Stop publisher replay, report bounded OpenGrep coverage honestly, and prevent late contextual-review failures from restarting completed work.

**Architecture:** Preserve strict report integrity while moving recoverable limitations into typed coverage metadata. Keep recovery local to existing batch, session, and queue boundaries.

**Tech stack:** TypeScript, Zod, Vitest, GitHub Actions, Node.js 24.

## Task 1: Publisher ordering regression

**Files:** `tests/retry.test.ts`, `tests/artifact-batch.test.ts`, `src/operations/retry.ts`

1. Add a failing unit test that records the same shared fingerprint newest-first and oldest-second.
2. Add an artifact-batch regression with two same-fingerprint failures whose transition timestamps oppose request order.
3. Confirm the tests fail on the automatic-hold timestamp invariant.
4. Calculate first/last timestamps with min/max and schedule the next probe from the latest timestamp.
5. Run the two focused test files.

## Task 2: Phase-aware sanitized fallbacks

**Files:** `tests/cli-io.test.ts`, `tests/failure.test.ts`, `src/operations/failure.ts`, `src/cli/io.ts`, `src/cli/prepare-target.ts`, `src/cli/review-target.ts`, `src/cli/finalize-target.ts`, `src/cli/publish.ts`

1. Add failing tests for an untyped error with an explicit target/contextual-model fallback and for typed failures remaining authoritative.
2. Extend failure classification and CLI execution with an optional bounded fallback.
3. Assign phase-specific fallbacks at the four scan pipeline entry points.
4. Run CLI and failure-classification tests.

## Task 3: Limited OpenGrep coverage contract

**Files:** `tests/opengrep.test.ts`, `tests/conditional-scanners.test.ts`, `tests/scan-package.test.ts`, `tests/contracts.test.ts`, `src/scanners/types.ts`, `src/scanners/opengrep.ts`, `src/orchestrator/scan-handler.ts`, `src/contracts/reports.ts`, `src/contracts/scan-package.ts`

1. Change syntax and rule-timeout tests to require preserved findings, `completed-with-limitations`, and bounded limitation codes.
2. Add rejection cases for wrong code/level/type and mixed unknown diagnostics.
3. Extend scanner-run and tool schemas with optional bounded limitations.
4. Return limited coverage only for exact recognized OpenGrep diagnostic forms.
5. Validate that only OpenGrep may report these limitations and that limited tools count as completed finding origins.
6. Run scanner, package, contract, and conditional-scanner tests.

## Task 4: Report limitations

**Files:** `tests/contextual-report.test.ts`, `tests/report-render.test.ts`, `tests/report-sanitize.test.ts`, `src/report/contextual-report.ts`, `src/publish/render-report.ts`, `src/orchestrator/session.ts`

1. Add failing tests proving tool limitations survive session/package/report construction and render as fixed public prose.
2. Preserve limitation metadata in prepared sessions and Scan Packages.
3. Derive fixed, deduplicated report limitation text from typed tool limitation codes.
4. Render the expanded tool status and limitations through existing escaped report paths.
5. Run report, sanitizer, render, and session tests.

## Task 5: Contextual-review progress and retry

**Files:** `tests/contextual-review.test.ts`, `tests/contextual-prompt.test.ts`, `tests/scan-session.test.ts`, `tests/workflows.test.ts`, `src/model/contextual-review.ts`, `src/model/contextual-prompt.ts`, `src/orchestrator/session.ts`, `src/cli/review-target.ts`, `.github/workflows/scan-and-publish.yml`

1. Add failing tests for repeated same-diagnostic repair attempts, provider retry behavior, resuming a completed group prefix, and rejecting invalid progress.
2. Add field-specific repair guidance for every bounded model-response diagnostic.
3. Define and validate a sanitized contextual-review progress contract.
4. Seed review aggregation from progress and emit a new checkpoint after every completed group.
5. Atomically load/write the session-bound progress bundle and remove it after completion.
6. Add one workflow-level command retry gated only by a sanitized `MODEL_PROVIDER` record.
7. Run contextual, session, provider, and workflow tests.

## Task 6: Final verification

**Files:** all changed files

1. Run formatting and lint checks required by the repository.
2. Run the full Vitest suite.
3. Run type checking and production build.
4. Inspect `git diff --check`, the complete diff, and `git status --short` while preserving the unrelated nested `TavernKeeper/` directory.
5. Re-check the live GitHub provider status and recent workflow state without mutating production operations data.
