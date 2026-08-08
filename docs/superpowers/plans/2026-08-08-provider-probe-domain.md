# Provider Probe Domain Implementation Plan

1. Add failing planner, CLI, workflow, and workflow-policy tests for forced
   direct probes and target-domain circuit recovery.
2. Add the bounded force flag to backlog planning and reconciliation.
3. Classify a sanitized target-domain probe result as shared-circuit success and
   pin the classifier in workflow policy.
4. Run the full project gate, review, publish, merge, force one live probe, and
   prove a normal repository batch starts.
