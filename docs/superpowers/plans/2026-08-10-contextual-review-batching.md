# Contextual Review Batching Implementation Plan

1. Add policy limits and batch usage contracts.
2. Add a multi-group prompt envelope and specialized structured-output schema.
3. Pack only cache misses into token-bounded batches of at most five groups.
4. Validate results independently, checkpoint successes, and retry only misses.
5. Preserve single-group context expansion and JSON repair behavior.
6. Publish per-batch estimated and actual token usage.
7. Run targeted, full, contract, and workflow verification before a live canary.
