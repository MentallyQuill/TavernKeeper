# Contextual Review Batching Design

## Goal

Reduce contextual-review model calls without weakening evidence coverage or
reusing a result against changed evidence.

## Decision

Review cache hits are replayed and validated before batching. Remaining
evidence groups are packed in source order into calls with both of these hard
limits:

- no more than five evidence groups per call;
- no more than the configured estimated input-token budget, except that one
  indivisible oversized group is still reviewed alone; and
- no more than one candidate per 2,048 configured output tokens across a
  multi-group call, while a dense indivisible group is still reviewed alone.

The estimate is deliberately conservative and derived from the UTF-8 bytes of
the exact system message, user message, and structured-output JSON Schema.
Every call records the estimate and the provider's actual input, output,
cache-read, and reasoning token counts.

## Wire contract

A batch response contains an exact `reviews` array. Every entry is keyed by the
supplied `group_id` and contains the existing policy-v4 review object. The
structured-output schema specializes each entry to that group's candidate,
evidence, and path identities.

Each entry is parsed and replayed through the existing authoritative per-group
coverage validator. A group is accepted only when its own response is complete
and valid. Duplicate, unknown, missing, or invalid group entries are never
accepted.

## Retries and progress

Valid groups from a partially bad batch are checkpointed immediately. Only
unresolved groups are repacked and retried. Per-group attempt limits remain
unchanged. Context expansion and optional bounded JSON binding repair remain
per group. Provider or globally malformed responses fail closed; they cannot
produce a completed group.

Progress remains an ordered completed prefix so an interrupted scan can resume
without repurchasing accepted work. Reusable cached groups and newly reviewed
groups are processed in original evidence order before each checkpoint.

## Compatibility

The contextual policy, assessment schema, and per-group review identity remain
v4/v7/v2. Batching is a transport optimization, so existing exact-identity
review-cache entries remain eligible and are still replay-validated. New
optional batch-usage records are persisted and published for cost auditing.
