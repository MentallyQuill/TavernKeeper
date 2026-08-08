# Direct Provider Recovery Design

## Problem

An automatic shared model-provider hold currently recovers by selecting one due
repository and running its full scan as a probe. A provider outage therefore
serializes the entire backlog behind arbitrary repositories, and each shared
failure increments that repository's target-local failure streak. The queue is
alive but makes no useful progress.

## Design

Reconciliation will treat provider health and repository health as separate
state transitions.

- While an automatic hold exists, backlog planning emits no repository scan.
- When the oldest hold is due, planning emits its fingerprint as a direct
  provider probe request.
- The reconcile workflow runs the existing bounded benign provider
  compatibility check in the scanner environment.
- A successful probe removes only that exact automatic hold, commits the state
  transition, and redispatches reconciliation so normal batches resume.
- A failed probe advances only that hold's failure streak and backoff, commits
  the state transition, and redispatches reconciliation so the next delayed
  wake is scheduled.
- Shared and security failures found during repository scans create or update
  automatic holds without rotating or incrementing the repository's retry
  counters. Target-domain failures retain the existing target retry behavior.

The direct probe uses the existing sanitized error boundary. It never publishes
a report and never needs a target checkout. The state commit uses the existing
publisher GitHub App and retry-safe main-branch update pattern.

## Safety and liveness

Only one due hold is probed per reconciliation, ordered by probe time and
fingerprint. An emergency staff stop still suppresses both scans and probes.
Provider secrets remain confined to the scanner environment. Every probe
outcome produces a durable state transition before reconciliation is
redispatched, preventing tight-loop probing.

## Verification

Tests must prove that a held backlog emits no repository request, a due hold
emits one direct fingerprint, probe success clears only the selected hold,
probe failure backs off only the selected hold, and shared scan failures leave
all target retry fields unchanged. Workflow policy tests must prove the probe
job is bounded, secret-scoped, and followed by a durable state commit and
redispatch.
