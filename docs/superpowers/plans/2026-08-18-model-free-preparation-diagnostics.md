# Model-Free Preparation Diagnostics Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [x]`) syntax for tracking.

**Goal:** Identify deterministic target-preparation failures without exposing repository data or invoking contextual model providers.

**Architecture:** `prepareTargetSession` wraps previously untyped internal boundaries with a bounded stage descriptor while preserving existing typed failures. An owner-only manual workflow accepts an exact public scan request, runs only deterministic preparation, deletes repository/session material, and uploads a one-day sanitized result containing either `prepared` or a public `FailureDescriptor`.

**Tech Stack:** TypeScript 6, Zod 4, Vitest 4, GitHub Actions YAML, Node.js 24

**Spec:** `docs/2026-08-18-single-scan-authorization-retry-incident.md`

## Global Constraints

- The diagnostic workflow must reference no model, JSON-repair, artifact-encryption, or Publisher credential.
- It must not mutate `operations/state.json`, publish reports, dispatch reconciliation, or create active scan leases.
- Diagnostics may contain only enumerated stage names and existing bounded failure fields.
- Raw exception messages, stack traces, repository paths, and source contents must not persist or upload.
- Prepared session and checkout directories must be removed before artifact upload.

---

### Task 1: Type unknown preparation-stage failures

**Files:**

- Modify: `tests/scan-session.test.ts`
- Modify: `tests/failure.test.ts`
- Modify: `src/orchestrator/session.ts`
- Modify: `src/operations/failure.ts`

**Interfaces:**

- Produces: `PreparationStageError` with code `PREPARATION_FAILED`, repository scope, bounded component, and one of the `preparation_*` diagnostics

- [x] **Step 1: Write the failing session regression tests**

Use real `prepareTargetSession` orchestration with controlled dependencies. Make `structuralScan`, prepared-session validation, `extractHistorical`, `executionScopes`, `buildEvidence`, and persistence fail one at a time with raw errors containing a fake path. Classify each rejection and assert only its enumerated stage descriptor remains.

- [x] **Step 2: Run scan-session tests and verify RED**

Run: `npm.cmd test -- tests/scan-session.test.ts tests/failure.test.ts`

Expected: FAIL because raw errors collapse to the CLI fallback.

- [x] **Step 3: Add bounded diagnostic enum values**

Extend `SafeFailureDiagnostics` with:

```ts
"preparation_structural",
"preparation_scanner_contract",
"preparation_historical",
"preparation_execution_scope",
"preparation_evidence",
"preparation_persistence",
```

Add `PREPARATION_FAILED` to target-system codes.

- [x] **Step 4: Wrap only unknown errors**

Add a `PreparationStageError` and a `runPreparationStage` helper. If `classifyFailure(error)` would retain a non-fallback bounded code, rethrow the original error; otherwise throw the stage error. Apply it at the six preparation boundaries without changing successful data flow.

- [x] **Step 5: Run session and failure tests and verify GREEN**

Run: `npm.cmd test -- tests/scan-session.test.ts tests/failure.test.ts tests/cli-io.test.ts`

Expected: all tests pass and raw fake paths are absent from classified output.

### Task 2: Add an owner-only preparation probe

**Files:**

- Create: `.github/workflows/prepare-diagnostic.yml`
- Modify: `tests/workflows.test.ts`
- Modify: `scripts/check-workflow-policy.mjs`
- Modify: `docs/operations.md`

**Interfaces:**

- Consumes: required `workflow_dispatch.inputs.request_json` string containing a valid `ScanRequest`
- Produces: artifact `preparation-diagnostic-${repository_id}/result.json` retained for one day

- [x] **Step 1: Write the failing workflow behavior test**

Load `prepare-diagnostic.yml` and assert one owner-and-main guarded job, read-only contents permission, bounded timeout, pinned checkout/setup/upload actions, no environment, no secrets, no model commands, no state/report writes, and cleanup before upload.

- [x] **Step 2: Run workflow tests and verify RED**

Run: `npm.cmd test -- tests/workflows.test.ts`

Expected: FAIL because the workflow file does not exist.

- [x] **Step 3: Create the deterministic workflow**

Validate the request through `prepare-target`, initialize `result.json` to a sanitized bootstrap failure, replace it with `{ "status": "prepared" }` on success or `{ "status": "failed", "failure": <FailureDescriptor> }` on failure, delete checkout/session/phase files, then upload only `result.json` for one day.

- [x] **Step 4: Extend workflow policy**

Add the workflow to trigger and permission allowlists and add explicit checks for owner/main authorization, absence of secrets and model commands, exact upload path, one-day retention, cleanup ordering, and no mutation/dispatch commands.

- [x] **Step 5: Document dispatch and interpretation**

Document the exact `gh workflow run prepare-diagnostic.yml --ref main -f request_json='<json>'` interface and state that `status=prepared` authorizes no subsequent scan.

- [x] **Step 6: Run workflow verification**

Run: `npm.cmd test -- tests/workflows.test.ts`

Run: `npm.cmd run workflows:check`

Expected: all tests pass and policy reports success for the expanded workflow set.

### Task 3: Complete repository verification

**Files:**

- Verify all files changed by Tasks 1–2

**Interfaces:**

- Produces: a branch ready for protected-main review and live model-free diagnosis

- [x] **Step 1: Run formatting**

Run: `npm.cmd run format`

- [x] **Step 2: Run the full gate**

Run: `npm.cmd run check`

Expected: formatting, typecheck, full Vitest suite, and workflow policy all pass.

- [x] **Step 3: Inspect final scope**

Run: `git diff --check`

Run: `git status --short`

Expected: only the incident report, these plans, authorization repair, preparation diagnostics, workflow policy, tests, and operational documentation are changed.
