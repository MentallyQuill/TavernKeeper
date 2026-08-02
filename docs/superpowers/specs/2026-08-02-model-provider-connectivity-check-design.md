# Model Provider Compatibility Check Design

> **Historical and superseded:** This document records the removed analyzer/per-role provider contract. TavernKeeper now performs private text chunk review followed by one strict JSON repository synthesis. See the current [architecture summary](../../architecture.md#trust-and-execution-boundaries) and [operator contract](../../operations.md#runtime-configuration).

## Goal

Give TavernKeeper staff a fast, provider-agnostic way to prove the currently configured OpenAI-compatible endpoint, API key, model, production Bearer authentication path, and TavernKeeper analyzer structured-output contract before spending time on a repository scan.

## Non-goals

- The check does not scan, clone, or otherwise inspect a repository.
- The check does not create, update, or publish reports.
- The check does not read or mutate `operations/state.json`, retries, the circuit breaker, or backlog scheduling.
- The check does not accept an endpoint, key, model, prompt, token budget, or authentication mode as workflow input.
- The check does not replace the live Wandlight and Recursion rollout certification.

## Workflow boundary

Add a permanent manual workflow named `provider-check.yml`.

1. `authorize` runs in the protected `tavernkeeper-staff` environment without provider secrets.
2. `check` depends on `authorize`, checks out trusted `main`, and runs in `tavernkeeper-scanner` so it uses the same `TAVERNKEEPER_API_ENDPOINT`, `TAVERNKEEPER_API_KEY`, and `TAVERNKEEPER_MODEL` settings as production scans.
3. The workflow has no manual inputs, no write permissions, and a non-cancelling provider-check concurrency group.
4. Provider secrets are exposed only to the single step named `Check configured model provider`.

The workflow policy allowlist must recognize this exact trigger, job set, permission profile, staff-authorization boundary, and secret placement.

## Probe behavior

The probe validates the endpoint with TavernKeeper's existing public-HTTPS and DNS boundary, trims the API key, and performs two non-streaming Chat Completions requests using the configured model.

The first request asks for a one-token response without structured output. It proves status and authentication while retaining the alternate-header diagnostic below.

After Bearer succeeds, the second request uses the same `json_schema`, strictness, response envelope, usage accounting, 8,192-token per-role allowance, and analyzer payload parser as a production scan. Its fixed prompt contains no repository URL, source, finding, or report data and asks for empty analyzer collections. This distinguishes a mere HTTP success from actual production-protocol compatibility.

The production-compatible attempt uses:

- `Authorization: Bearer <trimmed key>`
- `Content-Type: application/json`

Bearer success is the only passing outcome. If Bearer returns HTTP 401 or 403, the probe makes one diagnostic attempt with `x-api-key: <trimmed key>`:

- If the alternate header succeeds, fail with `MODEL_AUTH_HEADER_MISMATCH`.
- If both headers are rejected, fail with `MODEL_AUTHENTICATION`.

HTTP 402 or 429 maps to `MODEL_QUOTA`. Redirects, DNS/network failures, and other non-success responses map to `MODEL_PROVIDER`. Invalid local configuration maps to `MODEL_CONFIGURATION`.

## Output and secret safety

The first response body is never read. The structured response is read only inside the same bounded production parser and is never printed or persisted. The probe never prints the endpoint, key, model, request body, response headers, response body, assistant content, or reasoning content. Success emits only a small JSON record identifying `passed`, `bearer`, and `structuredOutput: passed`; failure uses TavernKeeper's sanitized JSON CLI error record.

Malformed structured responses may add one allowlisted shape/stage diagnostic such as `output_limit`, `response_content`, `response_usage`, or `role_schema_analyzer`. A rejected provider request may add only its integer HTTP error status from 400 through 599. Arbitrary provider text cannot enter either field. GitHub Actions logs and summaries therefore contain only safe classifications.

## Testing and release

Unit tests cover Bearer success, alternate-header-only success, rejected credentials, quota responses, provider responses, key trimming, the status-response no-body contract, production analyzer compatibility, output exhaustion, malformed JSON, and diagnostic allowlisting. Workflow contract tests and the policy checker cover permissions, environments, trigger authority, and provider-secret placement.

Before merging, run the focused tests and the complete `npm run check` gate. After merge, staff approves and runs the action once. Only a Bearer pass permits the paused Wandlight rollout test to continue.
