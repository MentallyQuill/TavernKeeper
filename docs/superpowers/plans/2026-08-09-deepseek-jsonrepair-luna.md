# DeepSeek JSON Repair with Luna Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Repair a final evidence-binding defect in an otherwise complete DeepSeek V4 Flash contextual response with one minimal GPT-5.6 Luna patch request, without allowing Luna to review source, create findings, change security judgments, or write summaries.

**Architecture:** DeepSeek remains the sole contextual reviewer. After its three existing immediate attempts, TavernKeeper may send Luna only compact failed hash bindings or locally proven invalid observation indices plus the sanitized diagnostic. Luna returns a small binding patch; TavernKeeper applies it to the original response without exposing or permitting changes to substantive fields, then runs the ordinary authoritative evidence validator before accepting it.

**Tech Stack:** TypeScript 6, Node.js 24, Zod 4, Vitest, GitHub Actions, OpenAI-compatible Chat Completions.

## Global Constraints

- Use exactly `JSONREPAIR_API_ENDPOINT`, `JSONREPAIR_API_KEY`, and `JSONREPAIR_MODEL` for the repair provider.
- Luna receives no repository name, file path, line number, project purpose, source text, imports, scanner findings, or expansion context.
- Luna is invoked at most once and only after DeepSeek exhausts all immediate attempts with a parsed completed response whose final failure diagnostic is `assessment_evidence_ids`, `observation_evidence_ids`, or `observation_locations`.
- Luna may replace only assessment evidence IDs or drop an unsupported optional observation; it cannot relocate or rewrite an observation. Every disposition, impact, exploitability, confidence, exposure, risk, title, explanation, action, candidate ID, and surviving observation order remains unchanged.
- A malformed, truncated, schema-invalid, provider-failed, semantically invalid, or context-incomplete DeepSeek response never invokes Luna.
- A repair-provider error or invalid patch preserves the original DeepSeek failure instead of creating a primary-provider hold.
- The patch response is strict JSON Schema, uses at most 2,048 requested output tokens and 16 KiB, and is never logged or persisted separately.
- Primary and repair usage are included in bounded aggregate usage; repair completion IDs are namespaced before checkpoint persistence.
- Only the contextual-review step sees both provider credential sets. The protected provider-check workflow tests Luna with synthetic non-repository JSON in a separate credential-scoped step.

---

### Task 1: Bounded JSON binding patcher

**Files:**

- Create: `src/model/json-repair.ts`
- Create: `tests/json-repair.test.ts`

**Interfaces:**

- Consumes: `EvidenceContextGroup`, a parsed completed `ContextualReviewResponse`, a repairable `ModelResponseDiagnostic`, and a `JsonRepairProvider`.
- Produces: `repairCompletedReviewBindings(input): Promise<JsonRepairResult>` where the result contains the patched completed response, provider usage, and a completion ID.

- [x] **Step 1: Write failing tests for the small patch protocol**

Add tests proving one strict request contains only failed bindings, the diagnostic, and the allowlist needed for that diagnostic; excludes repository/source/context/finding/narrative material; requests no more than 2,048 output tokens and 16 KiB; and accepts only an assessment evidence-ID replacement or optional-observation drop.

- [x] **Step 2: Run the repair tests and verify RED**

Run: `npm.cmd test -- tests/json-repair.test.ts`

Expected: FAIL because `src/model/json-repair.ts` does not exist.

- [x] **Step 3: Implement the minimal patch protocol**

Create strict Zod schemas for assessment evidence-ID replacements and observation drop operations. Build a compact untrusted-data prompt, call `requestTextCompletion` once with `reasoning_effort: none` selected by the existing GPT-5.6 client path, parse the patch, apply it to a clone of the original response, and reject duplicate/out-of-range patch indices.

- [x] **Step 4: Add semantic-immutability and fail-closed tests**

Test that Luna cannot change assessment or observation judgments/narratives, cannot invent bindings or locations, cannot return prose/schema drift, and cannot trigger a second call.

- [x] **Step 5: Run the repair tests and verify GREEN**

Run: `npm.cmd test -- tests/json-repair.test.ts`

Expected: PASS.

### Task 2: Contextual-review integration and configuration

**Files:**

- Modify: `src/model/contextual-review.ts`
- Modify: `src/orchestrator/session.ts`
- Modify: `src/cli/review-target.ts`
- Modify: `tests/contextual-review.test.ts`
- Modify: `tests/scan-session.test.ts`
- Modify: `tests/cli.test.ts`

**Interfaces:**

- Consumes: `JsonRepairProvider` and `repairCompletedReviewBindings` from Task 1.
- Produces: optional `jsonRepairProvider` fields on review/session specs, populated by the three required `JSONREPAIR_*` environment settings in production.

- [x] **Step 1: Write failing routing tests**

Prove Luna runs once only after the third DeepSeek evidence-binding failure; is skipped for successful, provider, malformed JSON, schema, semantic, and context failures; adds repair usage/completion identity; and returns the original DeepSeek error when repair fails.

- [x] **Step 2: Run focused tests and verify RED**

Run: `npm.cmd test -- tests/contextual-review.test.ts tests/scan-session.test.ts tests/cli.test.ts`

Expected: FAIL because the review and CLI specs do not accept `jsonRepairProvider`.

- [x] **Step 3: Implement minimal orchestration**

Retain the final parsed completed response and its authoritative validation error. After the DeepSeek loop ends, invoke the Task 1 patcher only for its allowlisted evidence-binding diagnostics, add repair usage and the namespaced completion ID, re-run `validateCompletedGroupReview`, and otherwise rethrow the original error.

- [x] **Step 4: Wire the exact environment contract**

Pass a `jsonRepairProvider` from `reviewConfiguredTarget` through `reviewPreparedSession` to `reviewEvidenceGroups` using `JSONREPAIR_API_ENDPOINT`, `JSONREPAIR_API_KEY`, and `JSONREPAIR_MODEL`. Keep non-model phases free of both provider credential sets.

- [x] **Step 5: Run focused tests and verify GREEN**

Run: `npm.cmd test -- tests/json-repair.test.ts tests/contextual-review.test.ts tests/scan-session.test.ts tests/cli.test.ts`

Expected: PASS.

### Task 3: GitHub secret isolation, provider proof, and operations contract

**Files:**

- Create: `src/cli/jsonrepair-check.ts`
- Modify: `package.json`
- Modify: `.github/workflows/scan-and-publish.yml`
- Modify: `.github/workflows/provider-check.yml`
- Modify: `scripts/check-workflow-policy.mjs`
- Modify: `tests/provider-credential-contract.test.ts`
- Modify: `tests/workflows.test.ts`
- Modify: `docs/operations.md`

**Interfaces:**

- Consumes: the Task 1 patcher and exact repository secret names.
- Produces: `npm run jsonrepair:check`, a synthetic non-publishing repair-provider compatibility check, and workflow-policy enforcement of the credential boundary.

- [x] **Step 1: Write failing workflow and CLI contract tests**

Require all three repair secrets only in the scan contextual-review step and the dedicated repair-check step. Prove the synthetic check contains no repository acquisition, scanner, finalization, publication, candidate, or report operation.

- [x] **Step 2: Run workflow tests and verify RED**

Run: `npm.cmd test -- tests/provider-credential-contract.test.ts tests/workflows.test.ts`

Expected: FAIL because the new secret contract and repair check are absent.

- [x] **Step 3: Implement the workflow and compatibility check**

Add the repair secrets to the contextual-review environment, create the synthetic repair-check CLI/script, add a separately credentialed provider-check step, and extend the workflow-policy secret allowlist and placement checks.

- [x] **Step 4: Update operations documentation**

Document the three repair secrets, the one-call patch-only boundary, excluded source/summary behavior, and the rule that repair failure preserves the primary target-local failure. Replace the obsolete blanket prohibition on automatic model fallback with a precise prohibition on alternate review or summary generation.

- [x] **Step 5: Verify the complete branch**

Run: `npm.cmd run check`

Run: `npm.cmd run build`

Run: `git diff --check`

Expected: all commands exit 0.

### Task 4: Protected release and live proof

**Files:**

- No new production files; use the reviewed branch and GitHub workflows.

**Interfaces:**

- Consumes: a clean, fully verified feature branch.
- Produces: a protected-main merge, a passing provider check for both providers, and an observed production scan that either does not invoke Luna or repairs one real failed DeepSeek response without performing a new review.

- [x] **Step 1: Review the diff against every global constraint**

Confirm Luna has no source/evidence context, no alternate-review route, one call, small output limits, semantic immutability, strict revalidation, separated secrets, and no repair payload persistence.

- [ ] **Step 2: Commit and push the verified branch**

Run focused verification again immediately before committing, push `codex/deepseek-jsonrepair-luna`, and open the protected integration path used by the repository.

- [ ] **Step 3: Merge and dispatch the protected provider check**

After required checks pass, merge through protected `main`, verify the exact remote main SHA, dispatch `provider-check.yml`, authorize its existing staff gate, and require both primary and synthetic JSON-repair steps to pass.

- [ ] **Step 4: Observe production scanning**

Watch new/updated-only scanning. Confirm ordinary successful DeepSeek groups use zero Luna calls. If a repairable DeepSeek evidence-binding failure occurs, confirm one Luna patch call, deterministic validation, report publication, queue advancement, and no scan or summary fallback.
