# OpenGrep Parser-Warning Policy V3 Design

## Status

Approved for implementation on 2026-08-03 as the production-release repair for the first priority-queue batch.

## Production evidence

The first production batch selected the intended five `top_30` repositories, proving the established priority order. The SillyTavern scan then caused the system circuit breaker to stop the batch.

Reproducing the exact SillyTavern commit with the pinned OpenGrep 1.26.0 binary produced exit code 0, four findings, and three warning-level parser diagnostics. Two diagnostics were `PartialParsing` (code 3), and one was `Other syntax error` (code 2), all in vendored or minified JavaScript. The current adapter treats any nonempty `errors` array as a scanner failure, so a successful scan with known parser limitations is incorrectly promoted to `SCANNER_FAILED`.

The exact TopInfoBar commit scanned successfully in isolation. Its production job was canceled only because the fail-fast batch stopped after the SillyTavern system failure.

## Approved behavior

Scanner policy version 3 classifies only these OpenGrep diagnostics as tolerated parser limitations:

- `level` is exactly `warn`, `code` is `2`, and `type` is exactly `Other syntax error`.
- `level` is exactly `warn`, `code` is `3`, and `type` is a tuple whose first item is exactly `PartialParsing`.

When every diagnostic matches one of those forms, the adapter completes the scan and preserves all valid findings. Tolerated diagnostics are not added to Technical Report V5; policy version 3 is the public indication that the bounded classification was applied.

The adapter remains fail-closed for every other condition, including:

- an unknown warning code or type;
- a recognized code or type at any level other than `warn`;
- malformed diagnostic structure;
- malformed scanner output;
- a nonzero OpenGrep exit code; or
- command launch, timeout, and output-limit failures.

We will not exclude minified or vendored source files and will not accept arbitrary warnings.

## Version and compatibility contract

The versioned policy file becomes `config/scanner-policy.v3.json` with version `3`. TavernKeeper runtime literals, validation, queue freshness checks, workflow policy checks, fixtures, and documentation move to version 3.

Tavernary's active TavernKeeper scanner-policy constant also moves to version 3. Reports produced under policy 2 remain valid historical documents but are not active catalog evidence.

Technical Report V5, contextual-review policy 1, and synthesis policy 1 remain unchanged. No report-schema migration or scan-card layout change is required. Existing source links continue to use the repository tree URL at the scanned commit.

## Workflow runtime compatibility

`scan-and-publish.yml` will pin the current Node 24 artifact actions by immutable commit:

- `actions/upload-artifact` v7.0.1 at `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a`;
- `actions/download-artifact` v8.0.1 at `3e5f45b2cfb9172054b4087a40e8e0b5a5461e7c`.

Workflow-policy tests will enforce those exact pins so the repaired production run is warning-free.

## Release recovery and data reset

The queue stays staff-paused throughout implementation and deployment.

Because policy 3 changes scan behavior and output eligibility, the release must remove all existing public scan history for only these canaries before either is rescanned:

- Wandlight, GitHub repository ID `1254077407`;
- Recursion, GitHub repository ID `1285208664`.

Their report trees and report-index entries are deleted in a dedicated, reviewable reset change. Tavernary import must then prove that neither stale summary remains. Each canary is scanned once under policy 3, and its resulting history must contain exactly one policy-3 entry with no policy-2 report ID.

The two failed production retry entries are cleared through the supported staff-retry operation while the staff pause still prevents dispatch. Only after policy-3 canaries, publication, Tavernary import, and live card links are verified may staff resume reactivate the queue.

## Verification gates

Implementation is releasable only when all of the following pass:

1. Unit tests prove accepted parser warnings preserve findings and prove unknown, wrong-level, malformed, and nonzero-exit cases remain fatal.
2. TavernKeeper type, unit, workflow-policy, and repository checks pass with policy 3 and exact Node 24 action pins.
3. Tavernary tests and build pass with scanner policy 3 as the active version.
4. Protected-branch pull requests merge and exact merge SHAs deploy successfully.
5. The reset is visible in TavernKeeper and imported into Tavernary before rescanning.
6. Wandlight and Recursion each have exactly one policy-3 history record after targeted rescans.
7. Production scan/deploy/import jobs have no Node 20 action annotations.
8. The queue resumes in the established priority order without a scanner-system circuit breaker.

## Out of scope

- Changing Technical Report V5 or adding warning details to its public schema.
- Changing scan-card visual design or tree-link generation.
- Broadly suppressing OpenGrep warnings.
- Excluding source classes merely because they are minified or vendored.
- Resetting any repository history other than Wandlight and Recursion.
