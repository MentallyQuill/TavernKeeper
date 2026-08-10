# Contextual Policy V4 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Apply the approved SillyTavern user-harm threshold through contextual-review policy 4 without changing the assessment object shape.

**Architecture:** Advance policy and prompt versions together, state the recoverable-local-degradation boundary explicitly in the authoritative model prompt, and keep the deterministic report/site gates aligned with policy 4. Historical V5 reports remain valid.

**Tech Stack:** TypeScript, Zod, Vitest, JSON Schema, Prettier.

## Global Constraints

- Recoverable degradation confined to the current client/session is low risk.
- Yellow requires demonstrated, high-confidence, plausibly exploitable concrete user harm.
- Red remains limited to malicious/compromised behavior or critical readily exploitable harm.
- Contextual policy is `4`, prompt is `contextual-review-v7`, and assessment schema remains `contextual-assessment-v2`.
- Existing immutable reports remain parseable.

---

### Task 1: Version and test the policy boundary

**Files:**

- Create: `config/contextual-review.v4.json`
- Modify: `src/config/policy.ts`
- Modify: `src/model/contextual-prompt.ts`
- Modify: `src/model/contextual-review.ts`
- Modify: `src/cli/review-target.ts`
- Test: `tests/policy.test.ts`
- Test: `tests/contextual-prompt.test.ts`
- Test: `tests/cli.test.ts`

**Interfaces:**

- Produces: `CURRENT_CONTEXTUAL_REVIEW_POLICY_VERSION = "4"` and prompt version `contextual-review-v7`.
- Preserves: `contextual-assessment-v2` response fields and bounded retry behavior.

- [ ] **Step 1: Write failing policy, prompt, and CLI tests**

Assert the new versions and require prompt language that classifies a local
slowdown, frozen tab/window, crash, restart, and unsaved generated-content loss
as low impact. Require concrete yellow examples: credentials, private content,
persistent saved-data destruction, persistence, arbitrary code execution, and
cross-user/system harm.

- [ ] **Step 2: Run the focused tests and verify red**

Run: `npm.cmd test -- tests/policy.test.ts tests/contextual-prompt.test.ts tests/cli.test.ts`

Expected: FAIL on policy 3, prompt v6, and the v3 config path.

- [ ] **Step 3: Implement the version and prompt changes**

Create the v4 JSON policy with the existing numeric limits. Update the Zod
policy schema, internal completed/progress schemas, and CLI config path. Replace
the policy paragraph with the approved local-harm and concrete-harm rules.

- [ ] **Step 4: Run focused tests and verify green**

Run: `npm.cmd test -- tests/policy.test.ts tests/contextual-prompt.test.ts tests/cli.test.ts`

Expected: PASS.

### Task 2: Accept policy 4 throughout V5 reports and presentation

**Files:**

- Modify: `src/contracts/reports-v5.ts`
- Modify: `src/site/presentation.ts`
- Modify: `scripts/generate-contract-schemas.ts`
- Generate: `schemas/scan-report.v5.schema.json`
- Test: `tests/contextual-report.test.ts`
- Test: `tests/contracts.test.ts`
- Test: `tests/site-presentation.test.ts`

**Interfaces:**

- Consumes: policy/prompt constants from Task 1.
- Produces: backward-compatible V5 parsing with a strict policy-4 version tuple.

- [ ] **Step 1: Write failing report and presentation tests**

Require policy 4 to use prompt v7 and assessment schema v2, reject mismatched
tuples, preserve policy 2/3 reports, and derive indexed policy-4 colors using
the demonstrated-risk rules.

- [ ] **Step 2: Run focused tests and verify red**

Run: `npm.cmd test -- tests/contextual-report.test.ts tests/contracts.test.ts tests/site-presentation.test.ts`

Expected: FAIL because policy 4 is not a recognized current contextual tuple.

- [ ] **Step 3: Implement report and site compatibility**

Add the policy-4 conditional alongside policy 3, update indexed presentation,
and generate the schema so the policy-4 branch requires prompt v7,
assessment-v2, and `risk_exposure`.

- [ ] **Step 4: Generate schemas and verify green**

Run:
`npm.cmd run contracts:generate`
`npm.cmd test -- tests/contextual-report.test.ts tests/contracts.test.ts tests/site-presentation.test.ts`

Expected: PASS.

- [ ] **Step 5: Commit policy 4**

Run:
`git add config/contextual-review.v4.json src/config/policy.ts src/model/contextual-prompt.ts src/model/contextual-review.ts src/cli/review-target.ts src/contracts/reports-v5.ts src/site/presentation.ts scripts/generate-contract-schemas.ts schemas/scan-report.v5.schema.json tests/policy.test.ts tests/contextual-prompt.test.ts tests/cli.test.ts tests/contextual-report.test.ts tests/contracts.test.ts tests/site-presentation.test.ts`
`git commit -m "feat(review): calibrate contextual policy v4"`

Expected: commit succeeds after focused tests pass.
