# Contextual Review Reuse Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Reuse prior model assessments only for identical current evidence units whose validated outcome is entirely low/not-demonstrated, while rerunning every scanner and reviewing only cache misses.

**Architecture:** Compute a canonical review-input digest independent of commit-only identifiers, publish a bounded cache manifest that points to an immutable V5 report, validate prior output against current evidence, and inject cache hits into the ordinary review loop. Publication updates report, history, state, and cache atomically.

**Tech Stack:** TypeScript, Node.js crypto/fs, Zod, Vitest, existing V5 report and contextual-review validators.

## Global Constraints

- Every deterministic scanner runs on every target SHA.
- Existing policy-3 reports never seed policy-4 reuse.
- Only low/not-demonstrated assessments and observations are reusable.
- Cache corruption or mismatch is a miss, never a scan failure or low conclusion.
- Provider prompt-cache tokens and TavernKeeper assessment reuse remain separate accounting.
- No raw repository evidence or duplicate narrative is stored in the cache manifest.

---

### Task 1: Define stable review-input and cache contracts

**Files:**

- Create: `src/model/review-cache.ts`
- Modify: `src/model/contextual-prompt.ts`
- Test: `tests/review-cache.test.ts`
- Modify: `tests/contextual-prompt.test.ts`

**Interfaces:**

- Produces: `reviewInputDigest(group, identity): string`.
- Produces: `ReviewCacheManifestSchema`, `loadReusableReviewGroups(...)`, and `reviewCachePath(...)`.
- Consumes: V5 immutable report validation and current evidence-group validation.

- [ ] **Step 1: Write failing digest tests**

Assert equal digests across changes limited to target SHA, evidence SHA, group
ID, source byte count, and unseen full-file hash. Assert digest changes for
repository/path/file role, candidates, displayed/expanded source, imports,
representations, purpose, ecosystem, scanner/toolchain versions,
policy/prompt/schema, provider origin, or model.

- [ ] **Step 2: Run digest tests and verify red**

Run: `npm.cmd test -- tests/review-cache.test.ts tests/contextual-prompt.test.ts`

Expected: FAIL because stable review identity does not exist and the prompt
still exposes volatile commit/hash fields.

- [ ] **Step 3: Implement canonical input and prompt projection**

Create one canonical projection used by both the digest and user prompt. Keep
meaningful evidence, candidate IDs, source windows, all expansions, purpose,
and context versions; omit volatile commit/group/full-file metadata. Hash the
projection plus scanner/toolchain, policy, and reviewer identity with SHA-256.

- [ ] **Step 4: Write failing cache-validation tests**

Cover missing/malformed manifests, wrong repository/report/policy/model,
candidate mismatch, changed digest, material/high/demonstrated output,
observation mismatch, and a valid low/not-demonstrated cache hit replayed
through `validateCompletedGroupReview`.

- [ ] **Step 5: Implement bounded cache loading**

Parse the manifest, locate and sanitize its immutable referenced V5 report,
extract only mapped assessments/observations, strip published location/path
wrappers to the model-progress shape, and validate against current groups.
Return an empty hit map for every cache-local failure.

- [ ] **Step 6: Run cache tests and verify green**

Run: `npm.cmd test -- tests/review-cache.test.ts tests/contextual-prompt.test.ts`

Expected: PASS.

### Task 2: Mix cache hits with fresh model review and durable progress

**Files:**

- Modify: `src/model/contextual-review.ts`
- Modify: `src/orchestrator/session.ts`
- Modify: `src/cli/review-target.ts`
- Test: `tests/contextual-review.test.ts`
- Test: `tests/scan-session.test.ts`
- Test: `tests/cli.test.ts`

**Interfaces:**

- Consumes: reusable group map and review-input digests from Task 1.
- Produces: review-bundle unit provenance for finalization.

- [ ] **Step 1: Write failing mixed-review tests**

Provide two groups with one valid reused response. Assert the model is called
only for the miss, coverage is complete, usage counts only the fresh request,
progress can resume, and provenance marks the reused unit's originating report.

- [ ] **Step 2: Run review/session tests and verify red**

Run: `npm.cmd test -- tests/contextual-review.test.ts tests/scan-session.test.ts tests/cli.test.ts`

Expected: FAIL because every group calls the provider and review bundles have
no unit provenance.

- [ ] **Step 3: Implement reusable group injection**

Add an optional reusable-group map to `reviewEvidenceGroups`. For each group,
authoritatively validate and append a reusable response or call the existing
model path. Persist both through the same ordered progress checkpoint. Do not
add provider usage or completion IDs for reuse.

- [ ] **Step 4: Load cache and persist review-unit provenance**

Have `reviewPreparedSession` load the repository cache from trusted checkout
root, compute current digests, pass hits to review, and write a versioned review
bundle containing each group ID, digest, candidate IDs, reused flag, and
originating report ID.

- [ ] **Step 5: Run mixed-review tests and verify green**

Run: `npm.cmd test -- tests/contextual-review.test.ts tests/scan-session.test.ts tests/cli.test.ts`

Expected: PASS.

### Task 3: Publish auditable cache provenance atomically

**Files:**

- Modify: `src/contracts/reports-v5.ts`
- Modify: `src/report/contextual-report.ts`
- Modify: `src/orchestrator/session.ts`
- Modify: `src/publish/artifact-batch.ts`
- Modify: `src/publish/publisher.ts`
- Modify: `src/publish/render-report.ts`
- Generate: `schemas/scan-report.v5.schema.json`
- Test: `tests/contextual-report.test.ts`
- Test: `tests/scan-session.test.ts`
- Test: `tests/artifact-batch.test.ts`
- Test: `tests/publisher.test.ts`
- Test: `tests/report-render.test.ts`

**Interfaces:**

- Produces: optional V5 `review_reuse` aggregate and a candidate `review_cache` manifest.
- Produces: atomic replacement of `reports/github/<id>/review-cache.json`.

- [ ] **Step 1: Write failing report/finalization tests**

Require fresh/reused group and candidate counts, sorted unique source report
IDs, complete count arithmetic, report-identity coverage, and candidate cache
metadata matching the finalized report.

- [ ] **Step 2: Write failing publication/rollback tests**

Require a successful batch to replace the per-repository cache manifest. Force
a later atomic write failure and assert the prior cache, report index, history,
state, and immutable destination are restored together.

- [ ] **Step 3: Run focused tests and verify red**

Run: `npm.cmd test -- tests/contextual-report.test.ts tests/scan-session.test.ts tests/artifact-batch.test.ts tests/publisher.test.ts tests/report-render.test.ts`

Expected: FAIL because the candidate/report/cache publication contracts do not
yet contain reuse provenance.

- [ ] **Step 4: Implement finalization and atomic publication**

Build `review_reuse` from review-unit provenance, include it in report identity,
create a cache manifest pointing at the new report, require it in completed
candidate envelopes, and extend publisher rollback bookkeeping to cache files.
Render a concise fresh/reused review row in the report metadata.

- [ ] **Step 5: Generate schema and verify green**

Run:
`npm.cmd run contracts:generate`
`npm.cmd test -- tests/contextual-report.test.ts tests/scan-session.test.ts tests/artifact-batch.test.ts tests/publisher.test.ts tests/report-render.test.ts`

Expected: PASS.

### Task 4: Document, verify, and commit review reuse

**Files:**

- Modify: `README.md`
- Modify: `docs/architecture.md`
- Modify: `docs/operations.md`

**Interfaces:**

- Documents: cache hit requirements, invalidation, provenance, and cold policy-4 baseline.

- [ ] **Step 1: Document operator behavior**

State that scanners always rerun, v4 is cold, only identical low results reuse,
cache failures are misses, and `review_reuse` plus `review-cache.json` provide
audit provenance.

- [ ] **Step 2: Run the complete local gate**

Run:
`npm.cmd run check`
`npm.cmd run build`
`git diff --check`

Expected: formatting, TypeScript, all Vitest files, workflow-policy checks, and
build pass.

- [ ] **Step 3: Commit review reuse**

Run:
`git add src/model/review-cache.ts src/model/contextual-prompt.ts src/model/contextual-review.ts src/orchestrator/session.ts src/cli/review-target.ts src/contracts/reports-v5.ts src/report/contextual-report.ts src/publish/artifact-batch.ts src/publish/publisher.ts src/publish/render-report.ts schemas/scan-report.v5.schema.json tests/review-cache.test.ts tests/contextual-prompt.test.ts tests/contextual-review.test.ts tests/scan-session.test.ts tests/cli.test.ts tests/contextual-report.test.ts tests/artifact-batch.test.ts tests/publisher.test.ts tests/report-render.test.ts README.md docs/architecture.md docs/operations.md`
`git commit -m "feat(review): reuse unchanged low-risk evidence"`

Expected: commit succeeds only after the full gate passes.

### Task 5: Release and operational proof

**Files:**

- Verify: all branch changes
- Live state: `operations/state.json` through trusted workflows

**Interfaces:**

- Produces: hosted green checks, merged main, cold v4 catalog queue, and later cache-hit evidence.

- [ ] **Step 1: Review the complete diff against the approved design**

Check policy boundary, version tuple, priority, cooldown, retired coverage,
cache invalidation, no-scanner-suppression, atomicity, and public-data safety.

- [ ] **Step 2: Push and open a PR**

Push the feature branch, create a PR against `main`, and require exact-head
hosted `check` and `scanner-toolchain` success.

- [ ] **Step 3: Merge and reconcile the cold catalog baseline**

After merge, run reconciliation. Verify the coverage campaign is empty, every
out-of-version target is queued, no v4 entry has a catch-up rescan deadline,
and the planned order is new, updated, then remaining catalog.

- [ ] **Step 4: Prove canary and subsequent reuse behavior**

For first v4 scans, require zero reused groups. On a later exact-input match,
require all scanners completed/applicable as before, reused counts above zero,
model calls only for misses, complete coverage, and cache provenance pointing
to a valid immutable report.
