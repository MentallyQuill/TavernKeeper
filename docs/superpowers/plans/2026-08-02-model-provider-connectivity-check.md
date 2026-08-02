# Model Provider Connectivity Check Implementation Plan

> **Historical and superseded:** This completed plan records the removed analyzer/per-role provider contract. TavernKeeper now performs private text chunk review followed by one strict JSON repository synthesis. See the current [architecture summary](../../architecture.md#trust-and-execution-boundaries) and [operator contract](../../operations.md#runtime-configuration).

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add and run a staff-protected, non-mutating action that proves TavernKeeper's configured provider works with the production Bearer authentication path.

**Architecture:** Extend the existing OpenAI-compatible client with a status-only connectivity probe so it reuses the current HTTPS, DNS, timeout, and error contracts. Expose that probe through a JSON-only CLI and a two-job manual workflow: protected staff authorization first, then one scanner-environment check with secrets confined to one step.

**Tech Stack:** TypeScript 6, Node.js 24 fetch, Vitest 4, GitHub Actions, YAML workflow policy checks.

## Global Constraints

- No repository checkout, scan state, retry, report, Pages, or Tavernary mutation may occur from the provider check.
- No endpoint, API key, model, prompt, token budget, or authentication mode may be supplied as workflow input.
- Provider secrets may appear only on the `Check configured model provider` step.
- Bearer success is the only passing result; `x-api-key` is attempted only after Bearer receives HTTP 401 or 403.
- The provider response body, headers, endpoint, API key, model, and request body must never be logged.
- The status request sends at most one output token; the repository-free structured diagnostic uses a bounded 8,192-token allowance. Production repository review later moved to provider-managed output capacity after live thinking-model exhaustion proved a fixed ceiling unsuitable.

## Post-rollout compatibility amendment

The initial one-token check proved the rotated credential and Bearer header, but the first Wandlight scan then failed with `MODEL_INVALID_RESPONSE` during model review. The configured beta thinking model can use a distinct reasoning/final-output shape, so the permanent check must also exercise TavernKeeper's actual analyzer JSON Schema contract before another repository retry.

- [x] Add failing tests for output exhaustion, malformed JSON, analyzer-contract incompatibility, and diagnostic allowlisting.
- [x] Split provider-envelope validation into safe, content-free response-stage diagnostics.
- [x] Add a fixed, repository-free analyzer compatibility request after the one-token Bearer proof.
- [x] Reuse the production analyzer schema, strict structured-output request, response parser, and usage accounting; retain the diagnostic's bounded 8,192-token allowance independently of production repository output capacity.
- [x] Run the full local gate, publish through PR review, run the protected compatibility action, and use its safe result to decide the Wandlight retry.

The repository-free check passed for DeepSeek V4 Flash base, while Wandlight's first large analyzer request returned `MODEL_PROVIDER`. Before changing chunking or provider configuration, retain only the integer 400-599 HTTP status in the sanitized CLI diagnostic so the next retry distinguishes request rejection from upstream failure without exposing a response body.

---

### Task 1: Status-only provider probe

**Files:**

- Modify: `src/model/openai-compatible-client.ts`
- Test: `tests/model-review.test.ts`

**Interfaces:**

- Produces: `checkModelProviderConnectivity(request: ProviderConnectivityRequest): Promise<{status: "passed"; authMode: "bearer"}>`
- Reuses: `validateModelEndpoint`, `ModelRequestError`, public-address resolution, and the existing model error codes plus `MODEL_AUTH_HEADER_MISMATCH`.

- [ ] **Step 1: Write the failing Bearer-success test**

Add a test that imports `checkModelProviderConnectivity`, supplies a public resolver and fake HTTP 200 response, and asserts the exact endpoint receives a trimmed Bearer header plus this minimal body:

```ts
{
  model: "configured/model",
  messages: [{ role: "user", content: "Reply with OK." }],
  stream: false,
  temperature: 0,
  max_tokens: 1,
}
```

Assert the response body is cancelled and the result equals `{ status: "passed", authMode: "bearer" }`.

- [ ] **Step 2: Run the focused test and verify RED**

Run: `npm test -- tests/model-review.test.ts`

Expected: FAIL because `checkModelProviderConnectivity` is not exported.

- [ ] **Step 3: Implement the minimal Bearer probe**

Add `ProviderConnectivityRequest`, extend `ModelRequestErrorCode` with `MODEL_AUTH_HEADER_MISMATCH`, validate and resolve the endpoint through the existing boundary, trim and validate configuration, POST the minimal body, cancel the response body, and return the safe success record for HTTP 2xx.

- [ ] **Step 4: Run the focused test and verify GREEN**

Run: `npm test -- tests/model-review.test.ts`

Expected: PASS.

- [ ] **Step 5: Add one failing alternate-header diagnostic test**

Return HTTP 401 for Bearer and HTTP 200 for `x-api-key`. Assert two calls, no Bearer header on the second request, and rejection with `{ code: "MODEL_AUTH_HEADER_MISMATCH", scope: "system" }`.

- [ ] **Step 6: Run the focused test and verify RED**

Run: `npm test -- tests/model-review.test.ts`

Expected: FAIL because the probe does not yet attempt the alternate header.

- [ ] **Step 7: Implement the diagnostic fallback and status mapping**

Attempt `x-api-key` only after HTTP 401 or 403. Map both rejected headers to `MODEL_AUTHENTICATION`, 402/429 to `MODEL_QUOTA`, redirects/network/other non-2xx responses to `MODEL_PROVIDER`, and invalid configuration/private resolution to `MODEL_CONFIGURATION`.

- [ ] **Step 8: Add and pass focused classification tests**

Add separate tests for dual authentication rejection, quota, generic provider failure, and empty configuration. Run `npm test -- tests/model-review.test.ts` after each test/implementation increment until all pass.

- [ ] **Step 9: Refactor shared public-endpoint resolution**

Extract one private helper used by both structured completions and connectivity checks without changing the structured-completion interface. Run `npm test -- tests/model-review.test.ts` and `npm run typecheck`.

### Task 2: Staff action and workflow policy

**Files:**

- Create: `src/cli/provider-check.ts`
- Create: `.github/workflows/provider-check.yml`
- Modify: `package.json`
- Modify: `scripts/check-workflow-policy.mjs`
- Modify: `tests/workflows.test.ts`
- Modify: `docs/operations.md`

**Interfaces:**

- Consumes: `checkModelProviderConnectivity` from Task 1.
- Produces: `npm run provider:check` and the `Staff: Check configured model provider` action.

- [ ] **Step 1: Write the failing workflow contract test**

Assert `provider-check.yml` has no inputs, root `contents: read`, non-cancelling `tavernkeeper-provider-check` concurrency, an `authorize` job in `tavernkeeper-staff` with `{}` permissions, and a dependent `check` job in `tavernkeeper-scanner` with `contents: read`. Assert exactly one step references provider secrets, its name is `Check configured model provider`, and the workflow text contains no operations-state, report, Pages, repository, endpoint, model, or token-budget input authority.

- [ ] **Step 2: Run the workflow test and verify RED**

Run: `npm test -- tests/workflows.test.ts`

Expected: FAIL because `provider-check.yml` does not exist.

- [ ] **Step 3: Add the CLI, package script, and workflow**

The CLI reads only `TAVERNKEEPER_API_ENDPOINT`, `TAVERNKEEPER_API_KEY`, and `TAVERNKEEPER_MODEL`, invokes the probe, and uses `runJsonCli`. The workflow checks out trusted `main` with persisted credentials disabled, installs Node 24 dependencies, and exposes the three secrets only to the CLI step.

- [ ] **Step 4: Update policy with an initially failing check**

Add `provider-check.yml` to the trigger, permission, and protected-manual allowlists, and allow model secrets only in either `scan-and-publish.yml`'s `Review with configured model` step or `provider-check.yml`'s `Check configured model provider` step. Update the negative workflow-policy assertion to expect the revised allowlist error.

- [ ] **Step 5: Run workflow and policy tests GREEN**

Run: `npm test -- tests/workflows.test.ts`

Expected: PASS, including the reviewed workflow-policy execution.

- [ ] **Step 6: Document the staff action**

Add `provider-check.yml` to `docs/operations.md`, explicitly documenting that it is a tiny status-only provider proof and cannot mutate scanning or publication state.

### Task 3: Verify, publish, and run

**Files:**

- Verify all changed files from Tasks 1 and 2.

**Interfaces:**

- Produces: merged GitHub Action and one protected live provider-check result.

- [ ] **Step 1: Run formatting and the full local gate**

Run: `npm run format`, then `npm run check && npm run build`.

Expected: all formatting, typecheck, unit tests, and workflow policy checks pass.

- [ ] **Step 2: Inspect the final diff and secret boundary**

Run: `git diff --check`, `git status --short`, and search the new workflow for provider-secret references. Confirm exactly one consuming step and no response-body logging.

- [ ] **Step 3: Commit and publish through a PR**

Commit implementation with `feat(model): add provider connectivity check`, push `feature/model-provider-check`, open a PR to `main`, and wait for all required checks.

- [ ] **Step 4: Merge and verify current main**

Merge only after checks pass. Verify the merge SHA and main CI.

- [ ] **Step 5: Run the protected action**

Dispatch `provider-check.yml` on `main`, approve only `tavernkeeper-staff`, and watch completion. A passing run must emit only the safe Bearer success record.

- [ ] **Step 6: Continue or stop**

If the action passes with Bearer, dispatch the full Tavernary Wandlight URL action and monitor publication/import. If it fails, stop before another repository scan and diagnose from the sanitized code.
