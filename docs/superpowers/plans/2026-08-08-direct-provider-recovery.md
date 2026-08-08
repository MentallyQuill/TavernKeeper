# Direct Provider Recovery Implementation Plan

1. Add failing backlog and retry tests for direct hold selection, hold-only
   success/failure transitions, and uncontaminated target retry budgets.
2. Implement direct-probe planning and automatic-hold transition functions.
3. Add a validated CLI that applies a provider-probe outcome to
   `operations/state.json`, with focused CLI tests.
4. Add failing workflow and workflow-policy tests for an automatic scanner
   environment probe, durable state publication, and reconciliation dispatch.
5. Implement the reconcile probe job and update workflow policy enforcement.
6. Run formatting, type checking, the full unit suite, workflow policy checks,
   and the complete project check.
7. Review the diff, publish a PR, verify required checks, merge it, dispatch
   live reconciliation, and prove both the deployed SHA and resumed scan/report
   progress.
