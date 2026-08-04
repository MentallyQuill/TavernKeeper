# Tavernary Report Import Quarantine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Quarantine one invalid Tavernary synthesis without publishing it or blocking later valid TavernKeeper reports.

**Architecture:** Make synthesis candidate-ID-only with typed structured repair, classify terminal synthesis failures, and persist exact-report quarantine state beside the assessment snapshot. The importer keeps its existing snapshot-returning API while an internal detailed result drives the workflow and operational incidents.

**Tech Stack:** JavaScript ESM, TypeScript declarations, Node.js 24, Vitest 4, GitHub Actions, JSON files committed through protected main.

## Global Constraints

- Candidate IDs are the only valid synthesis citation IDs.
- Validation, evidence floors, and count checks remain fail-closed.
- Quarantined reports are absent from preferred Tavernary summaries.
- Successful reports in the same batch still publish.
- Provider, authentication, source-integrity, and report-validation failures remain batch failures.
- Store no generated prose, provider bodies, credentials, URLs, or source content in import state or issues.
- A synthesis request may run at most three times and only when the request changes.
- Keep Technical Report V5 unchanged.
- Preserve the public `importTavernKeeperReports()` snapshot return contract.

---

### Task 1: Make validation repair structured and candidate-only

**Files in the Tavernary worktree:**

- Modify: `scripts/security/tavernkeeper-assessment-contract.mjs`
- Modify: `scripts/security/tavernkeeper-assessment-contract.d.mts`
- Modify: `scripts/security/tavernkeeper-synthesis-provider.mjs`
- Test: `tests/unit/tavernkeeper-synthesis.test.ts`

**Interfaces:**

- Produces `TavernaryAssessmentValidationError` with a bounded diagnostic and
  repair payload.
- Synthesis input exposes `allowed_candidate_ids` and `required_counts` but no
  `observation_id`.

- [ ] **Step 1: Write RED contract tests**

Assert an unknown citation throws an error with:

```ts
{
  diagnostic: "unknown_candidate_ids",
  repair: {
    rejected_candidate_ids: [unknownId],
    allowed_candidate_ids: [knownId],
    required_counts: {
      minor_cautions: 0,
      material_concerns: 0,
      high_danger: 0,
    },
  },
}
```

Assert count mismatch uses `diagnostic: "count_mismatch"` and exact required
counts. Add corresponding cases for missing citations, chain IDs, evidence
floor, and unsupported escalation.

- [ ] **Step 2: Write RED provider-projection tests**

Capture the structured provider request. Assert:

- `allowed_candidate_ids` equals candidate IDs;
- observations omit `observation_id`;
- instructions say observation IDs are never valid citations; and
- `required_counts` equals the validator's deterministic projection.

- [ ] **Step 3: Run synthesis tests and confirm RED**

```powershell
npm.cmd test -- tests/unit/tavernkeeper-synthesis.test.ts
```

- [ ] **Step 4: Implement typed validation errors**

Export:

```js
export class TavernaryAssessmentValidationError extends Error {
  constructor(diagnostic, repair) {
    super(`Tavernary assessment failed ${diagnostic}`);
    this.name = "TavernaryAssessmentValidationError";
    this.diagnostic = diagnostic;
    this.repair = repair;
  }
}
```

Build every repair payload from validated 64-hex IDs and deterministic counts.
Do not attach the rejected assessment.

- [ ] **Step 5: Implement candidate-only projection**

Remove `observation_id` from synthesis input, add allowed IDs and required
counts, and make the instruction explicit. Export a count helper from the
assessment contract so provider input and validator share one implementation.

- [ ] **Step 6: Run synthesis tests and confirm GREEN**

```powershell
npm.cmd test -- tests/unit/tavernkeeper-synthesis.test.ts
npm.cmd run typecheck
```

- [ ] **Step 7: Commit Task 1**

```powershell
git add scripts/security/tavernkeeper-assessment-contract.mjs scripts/security/tavernkeeper-assessment-contract.d.mts scripts/security/tavernkeeper-synthesis-provider.mjs tests/unit/tavernkeeper-synthesis.test.ts
git commit -m "fix(security): constrain synthesis citations"
```

---

### Task 2: Preserve typed synthesis failure classes

**Files:**

- Modify: `scripts/security/tavernkeeper-synthesis.mjs`
- Modify: `scripts/security/tavernkeeper-synthesis.d.mts`
- Modify: `scripts/security/tavernkeeper-synthesis-provider.mjs`
- Test: `tests/unit/tavernkeeper-synthesis.test.ts`

**Interfaces:**

- Produces `TavernKeeperSynthesisError` with kind `invalid-output`,
  `provider-transient`, or `provider-security` and a safe diagnostic.
- Provider `generate()` accepts a structured repair object.

- [ ] **Step 1: Write RED retry/failure tests**

Cover:

- first invalid output then valid output sends structured repair and succeeds;
- identical validation repair stops after two requests;
- three differing invalid repairs throw `invalid-output`;
- timeout/rate/network/server errors throw `provider-transient`;
- authentication/request/model mismatch errors throw `provider-security`; and
- no terminal error exposes generated output.

- [ ] **Step 2: Run synthesis tests and confirm RED**

```powershell
npm.cmd test -- tests/unit/tavernkeeper-synthesis.test.ts
```

- [ ] **Step 3: Implement typed failure wrapping**

Import `EnrichmentProviderError`. Classify its safe code with explicit sets:

```js
const transientProviderCodes = new Set([
  "provider-timeout",
  "provider-rate-limited",
  "provider-server-error",
  "provider-network-error",
]);
```

Treat `provider-response-invalid` as invalid output. Treat remaining provider
codes as provider security/configuration. Preserve only safe codes and
assessment diagnostics.

Serialize repair payloads before calls. If the next payload equals the previous
payload, stop and throw without another provider request.

- [ ] **Step 4: Run synthesis tests and confirm GREEN**

```powershell
npm.cmd test -- tests/unit/tavernkeeper-synthesis.test.ts
npm.cmd run typecheck
```

- [ ] **Step 5: Commit Task 2**

```powershell
git add scripts/security/tavernkeeper-synthesis.mjs scripts/security/tavernkeeper-synthesis.d.mts scripts/security/tavernkeeper-synthesis-provider.mjs tests/unit/tavernkeeper-synthesis.test.ts
git commit -m "fix(security): classify synthesis failures"
```

---

### Task 3: Persist exact-report quarantine state

**Files:**

- Create: `scripts/security/tavernkeeper-import-state.mjs`
- Create: `scripts/security/tavernkeeper-import-state.d.mts`
- Create: `data/security/tavernkeeper-import-state.json`
- Modify: `scripts/security/import-tavernkeeper-reports.mjs`
- Modify: `scripts/security/import-tavernkeeper-reports.d.mts`
- Test: `tests/unit/tavernkeeper-import-state.test.ts`
- Test: `tests/unit/tavernkeeper-reports.test.ts`

**Interfaces:**

- `validateTavernKeeperImportState(value)` validates schema V1.
- `importTavernKeeperReportsDetailed(options)` returns
  `{ snapshot, importState, result }`.
- Existing `importTavernKeeperReports(options)` returns only `snapshot`.

- [ ] **Step 1: Write RED state tests**

Validate an empty state and one strict quarantine. Reject duplicate
`[report_digest,synthesis_policy_version]`, raw message fields, unsorted rows,
invalid hashes, and invalid timestamps.

Use this initial file:

```json
{
  "schema_version": 1,
  "updated_at": "1970-01-01T00:00:00.000Z",
  "quarantines": []
}
```

- [ ] **Step 2: Write RED per-report isolation tests**

Create an index containing two new reports. Make the first synthesis throw
`TavernKeeperSynthesisError("invalid-output", ...)` and the second succeed.
Assert:

- the first digest is in import state;
- the second report is assessed and preferred;
- the first report is not preferred;
- a subsequent run skips the quarantined digest without calling synthesis;
- changing digest or policy makes it eligible; and
- provider-transient failure rejects and preserves both prior files.

- [ ] **Step 3: Run import tests and confirm RED**

```powershell
npm.cmd test -- tests/unit/tavernkeeper-import-state.test.ts tests/unit/tavernkeeper-reports.test.ts
```

- [ ] **Step 4: Implement strict state helpers**

Provide read, validate, canonicalize, and atomic-write helpers. Quarantine rows
contain only the fields approved in the design. Compute incident identity from
`["tavernary-synthesis", report_digest, synthesis_policy_version]`.

- [ ] **Step 5: Implement detailed import flow**

Keep the public wrapper:

```js
export async function importTavernKeeperReports(options = {}) {
  return (await importTavernKeeperReportsDetailed(options)).snapshot;
}
```

The detailed loop skips current-policy quarantines, catches only typed
`invalid-output`, continues after recording it, and rethrows every other error.
Build `preferred_report_ids` only from current entries that already exist or
synthesized successfully. Validate snapshot and state completely before atomic
writes.

- [ ] **Step 6: Run import tests and confirm GREEN**

```powershell
npm.cmd test -- tests/unit/tavernkeeper-import-state.test.ts tests/unit/tavernkeeper-reports.test.ts
npm.cmd run typecheck
```

- [ ] **Step 7: Commit Task 3**

```powershell
git add scripts/security/tavernkeeper-import-state.mjs scripts/security/tavernkeeper-import-state.d.mts data/security/tavernkeeper-import-state.json scripts/security/import-tavernkeeper-reports.mjs scripts/security/import-tavernkeeper-reports.d.mts tests/unit/tavernkeeper-import-state.test.ts tests/unit/tavernkeeper-reports.test.ts
git commit -m "fix(security): isolate report synthesis"
```

---

### Task 4: Publish quarantine state and operational incidents

**Files:**

- Modify: `.github/workflows/import-tavernkeeper-reports.yml`
- Modify: `scripts/security/import-tavernkeeper-reports.mjs`
- Modify: `package.json`
- Test: `tests/unit/tavernkeeper-publication.test.ts`
- Test: `tests/unit/tavernkeeper-reports.test.ts`

**Interfaces:**

- Workflow accepts optional `retry_report_digest`.
- CLI emits one sanitized JSON result for workflow incident reconciliation.

- [ ] **Step 1: Write RED workflow tests**

Parse the workflow and assert:

- `issues: write` is present;
- dispatch input is optional and constrained before use;
- both summary and import-state JSON files are staged;
- incident lookup uses report incident key, not diagnostic alone;
- report-local quarantine does not fail the import step; and
- exact committed SHA deployment remains mandatory.

- [ ] **Step 2: Run workflow tests and confirm RED**

```powershell
npm.cmd test -- tests/unit/tavernkeeper-publication.test.ts tests/unit/tavernkeeper-reports.test.ts
```

- [ ] **Step 3: Emit sanitized import results**

Main prints only:

```json
{
  "imported": 1,
  "retained": 10,
  "quarantined": 1,
  "created_or_updated": [{ "incident_key": "...", "report_digest": "..." }],
  "resolved": []
}
```

Include the approved safe identity/diagnostic fields needed by the issue body.
Read `TAVERNARY_RETRY_REPORT_DIGEST` only after strict 64-hex validation.

- [ ] **Step 4: Update protected workflow**

Capture the JSON result, append a human-readable job summary, commit both data
files, and reconcile one issue per incident key. Close only keys listed as
resolved. Keep provider and trusted-input failures as nonzero workflow exits.

- [ ] **Step 5: Run workflow tests and confirm GREEN**

```powershell
npm.cmd test -- tests/unit/tavernkeeper-publication.test.ts tests/unit/tavernkeeper-reports.test.ts
npm.cmd run typecheck
```

- [ ] **Step 6: Commit Task 4**

```powershell
git add .github/workflows/import-tavernkeeper-reports.yml scripts/security/import-tavernkeeper-reports.mjs package.json tests/unit/tavernkeeper-publication.test.ts tests/unit/tavernkeeper-reports.test.ts
git commit -m "fix(ci): publish isolated import outcomes"
```

---

### Task 5: Verify Tavernary completely

**Files:**

- Modify: `docs/tavernkeeper-integration.md`

**Interfaces:**

- Documents candidate-only synthesis, quarantine state, operator retry, and
  batch-level provider failures.

- [ ] **Step 1: Update integration documentation**

Document exact state-file fields, preferred-summary semantics, incident
identity, optional manual retry input, and the distinction between report-local
invalid output and batch-level provider/integrity failures.

- [ ] **Step 2: Run focused verification**

```powershell
npm.cmd test -- tests/unit/tavernkeeper-synthesis.test.ts tests/unit/tavernkeeper-import-state.test.ts tests/unit/tavernkeeper-reports.test.ts tests/unit/tavernkeeper-publication.test.ts
npm.cmd run security:validate-reports
npm.cmd run catalog:build
npm.cmd run typecheck
```

- [ ] **Step 3: Run complete Tavernary gate**

```powershell
npm.cmd run check
git diff --check
```

Expected: all commands exit 0.

- [ ] **Step 4: Review exact branch scope**

```powershell
git status --short
git diff main...HEAD --stat
git log --oneline main..HEAD
```

Expected: only the planned Tavernary synthesis/import files, state, workflow,
tests, and documentation.

- [ ] **Step 5: Commit Task 5**

```powershell
git add docs/tavernkeeper-integration.md
git commit -m "docs: explain synthesis quarantine"
```
