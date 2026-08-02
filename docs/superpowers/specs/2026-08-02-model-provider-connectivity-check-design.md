# Model Provider Connectivity Check Design

## Goal

Give TavernKeeper staff a fast, provider-agnostic way to prove the currently configured OpenAI-compatible endpoint, API key, model, and production Bearer authentication path before spending time on a repository scan.

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

The probe validates the endpoint with TavernKeeper's existing public-HTTPS and DNS boundary, trims the API key, and sends a minimal non-streaming Chat Completions request using the configured model. The request asks for a one-token response and does not request structured output.

The production-compatible attempt uses:

- `Authorization: Bearer <trimmed key>`
- `Content-Type: application/json`

Bearer success is the only passing outcome. If Bearer returns HTTP 401 or 403, the probe makes one diagnostic attempt with `x-api-key: <trimmed key>`:

- If the alternate header succeeds, fail with `MODEL_AUTH_HEADER_MISMATCH`.
- If both headers are rejected, fail with `MODEL_AUTHENTICATION`.

HTTP 402 or 429 maps to `MODEL_QUOTA`. Redirects, DNS/network failures, and other non-success responses map to `MODEL_PROVIDER`. Invalid local configuration maps to `MODEL_CONFIGURATION`.

## Output and secret safety

The probe never reads, parses, or logs the provider response body. It never prints the endpoint, key, model, request body, response headers, or response body. Success emits only a small JSON record identifying `passed` and `bearer`; failure uses TavernKeeper's existing sanitized JSON CLI error record.

The response body is cancelled after status classification. GitHub Actions logs and summaries therefore contain only the safe status classification.

## Testing and release

Unit tests cover Bearer success, alternate-header-only success, rejected credentials, quota responses, provider responses, key trimming, and the no-response-body contract. Workflow contract tests and the policy checker cover permissions, environments, trigger authority, and provider-secret placement.

Before merging, run the focused tests and the complete `npm run check` gate. After merge, staff approves and runs the action once. Only a Bearer pass permits the paused Wandlight rollout test to continue.
