# Tavernary Report Import Quarantine Design

## Status

Approved in conversation on 2026-08-04. Written-spec review is pending.

This is an independently deployable Tavernary change. It consumes unchanged
TavernKeeper Technical Report V5 files and does not depend on the TavernKeeper
catalog-first scheduler release.

## Problem

Tavernary's importer processes new TavernKeeper reports sequentially but writes
the assessment snapshot only after every synthesis succeeds. One invalid model
response therefore prevents all later reports from publishing.

The linked failure and five subsequent reconciliation failures show two
repeating validation classes:

- the model cited an unknown finding ID; and
- the model returned counts that did not match the V5 reviewed items.

The synthesis input exposes both candidate IDs and observation IDs while the
validator permits only candidate IDs in `cited_finding_ids`. The instruction
"cite V5 finding IDs" does not explain that distinction. Repair attempts carry
only a generic error string and can repeat without receiving the rejected IDs,
allowed IDs, or required counts.

## Goals

- Make candidate IDs the only possible synthesis citation identity.
- Give rejected synthesis attempts bounded, structured repair feedback.
- Quarantine one invalid report without publishing its summary.
- Continue importing and publishing successful reports from the same batch.
- Keep provider outages and source-integrity failures batch-failing.
- Persist quarantine state so the same immutable report does not jam every
  scheduled run.
- Make a changed report digest, synthesis-policy change, or explicit operator
  retry eligible again.
- Create a visible, deduplicated operational incident for each quarantined
  report.

## Non-goals

- Weakening the assessment schema, evidence floor, citation completeness, or
  interaction-chain validation.
- Accepting model counts that disagree with deterministic V5 counts.
- Publishing a partial assessment for a quarantined report.
- Changing TavernKeeper report generation or Technical Report V5.
- Treating provider authentication, provider availability, report fetch, report
  identity, or report integrity failures as report-local synthesis defects.
- Coupling Tavernary deployment to the TavernKeeper scheduler deployment.

## Approved invariants

1. Each report is an independent synthesis transaction.
2. Invalid synthesis quarantines only that immutable report digest.
3. A quarantined report has no preferred Tavernary summary.
4. Successful reports in the same import run still publish.
5. Provider outages remain batch-level failures.
6. Validation remains fail-closed.
7. Repair attempts must change the next request.
8. A visible incident records the safe failure without model prose.

## Considered approaches

### 1. Per-report transactional quarantine — selected

Persist a small import-state file beside the existing assessment snapshot.
Synthesize each missing report independently, quarantine only terminal invalid
output, and commit successful summaries plus quarantine state together.

This fixes the batch-jamming failure while preserving all existing validation.

### 2. Prompt and repair improvements only

This likely fixes the current Twemoji failure, but the next novel schema error
would still block every report behind it. It does not satisfy independent
progress.

### 3. Accept or normalize invalid model output

This would maximize throughput by silently correcting citations or counts, but
it would make Tavernary rather than the validated response authoritative for
security conclusions. It is rejected.

## Candidate-only synthesis contract

The synthesis projection makes the allowed identity explicit:

- `allowed_candidate_ids` contains every and only `report.candidates[].candidate_id`;
- assessment rows retain their `candidate_id`;
- observations retain `related_candidate_ids` but do not expose
  `observation_id` to the model;
- `cited_finding_ids` and every interaction-chain `finding_ids` value may use
  only an ID from `allowed_candidate_ids`; and
- the instructions explicitly state that observation IDs are never valid
  citations.

The input also supplies deterministic `required_counts`:

```js
{
  minor_cautions,
  material_concerns,
  high_danger,
}
```

The model must copy these values exactly. The validator remains authoritative
and recalculates them from the V5 assessments and observations.

## Structured validation and repair

Assessment validation throws a typed, sanitized error:

```ts
type TavernaryAssessmentDiagnostic =
  | "response_schema"
  | "unknown_candidate_ids"
  | "missing_candidate_ids"
  | "count_mismatch"
  | "interaction_chain_ids"
  | "below_evidence_floor"
  | "unsupported_escalation";

interface TavernaryAssessmentRepair {
  diagnostic: TavernaryAssessmentDiagnostic;
  rejected_candidate_ids?: string[];
  required_candidate_ids?: string[];
  allowed_candidate_ids: string[];
  required_counts: {
    minor_cautions: number;
    material_concerns: number;
    high_danger: number;
  };
}
```

Every ID is first validated as a 64-character lowercase hexadecimal value.
Repair data contains no generated prose, repository content, URLs, credentials,
provider bodies, or hidden reasoning.

Synthesis makes at most three attempts. Attempt two includes the first
structured repair payload. A later attempt occurs only if its repair payload
differs from the payload already supplied; otherwise synthesis stops early
instead of issuing an identical request.

## Synthesis failure classes

The synthesis wrapper preserves a bounded terminal kind:

```ts
type TavernKeeperSynthesisFailureKind =
  "invalid-output" | "provider-transient" | "provider-security";
```

Assessment validation failures and provider structured-response parse failures
are `invalid-output`. Provider timeout, rate limit, network, and server failures
are `provider-transient`. Authentication, configuration, request-boundary, and
model-identity failures are `provider-security`.

Only `invalid-output` is report-local and quarantineable. Both provider kinds
abort the batch without writing a partial working-tree result. Existing
provider retries may remain bounded, but they never become report quarantine
entries.

Report fetch, schema, digest, source identity, and index/snapshot consistency
failures also abort the batch. They protect trusted input and cannot be reduced
to a model-output problem.

## Import quarantine state

Tavernary adds
`data/security/tavernkeeper-import-state.json` with a strict schema:

```ts
interface TavernKeeperImportStateV1 {
  schema_version: 1;
  updated_at: string;
  quarantines: Array<{
    report_id: string;
    report_digest: string;
    repository_id: number;
    repository: string;
    target_sha: string;
    synthesis_policy_version: string;
    diagnostic: TavernaryAssessmentDiagnostic | "provider_response_invalid";
    first_failed_at: string;
    last_failed_at: string;
    attempts: number;
  }>;
}
```

The file contains no report content or generated output. Quarantines are unique
by `[report_digest, synthesis_policy_version]` and sorted deterministically.
The synthesis policy version advances for the candidate-only contract.

An exact quarantine is skipped on later scheduled runs. It becomes eligible
when:

- the preferred report has a different digest;
- the current synthesis policy version differs from the stored version; or
- a validated workflow-dispatch input explicitly retries that report digest.

An operator retry removes only the matching eligibility guard for that run. A
second invalid synthesis recreates or updates the same quarantine.

## Per-report import transaction

For each preferred TavernKeeper index entry:

1. If a matching assessed report already exists, validate its immutable index
   projection and retain it.
2. If the exact digest is quarantined for the current synthesis policy, skip it
   without calling the provider.
3. Otherwise fetch and validate the immutable V5 report.
4. Synthesize and validate it with candidate-only repair.
5. On success, stage the assessed entry and remove any matching quarantine.
6. On terminal `invalid-output`, stage a quarantine and continue to the next
   report.
7. On provider, source, integrity, or configuration failure, abort the batch.

After the loop, Tavernary validates both complete in-memory outputs before
writing either file:

- the assessment snapshot retains historical assessed reports and makes only
  successfully assessed current index entries preferred; and
- the import state contains the updated exact-report quarantines.

A quarantined preferred report is deliberately absent from
`preferred_report_ids`. If an older assessed report exists for the same
repository, it remains retained history but is not represented as the current
preferred assessment. This preserves fail-closed status semantics.

Both files are staged and committed in one protected workflow commit. If only
quarantine state changed, that state is still committed so the next scheduled
run does not repeat the same model spend.

## Operational incidents

A report incident key is:

```text
report incident key = SHA-256([
  "tavernary-synthesis",
  report_digest,
  synthesis_policy_version,
])
```

The workflow has `issues: write` and creates or updates one issue containing
only the incident key, repository identity, target SHA, report digest, policy
version, safe diagnostic, attempt count, and run URL. It never includes model
output or provider response content.

When that report later imports successfully, or a newer policy makes the old
quarantine obsolete, the matching issue closes with a short recovery comment.
Provider failures remain workflow failures and use existing workflow
visibility rather than report-local incidents.

## Workflow behavior

The reconciliation workflow:

1. checks out main and installs pinned dependencies;
2. runs the importer with an optional validated `retry_report_digest` dispatch
   input;
3. validates the assessment snapshot, import state, catalog, tests, and build;
4. stages both security JSON files;
5. commits and rebases them together through the existing serialized path;
6. creates, updates, or closes report-local incidents from the sanitized import
   result; and
7. deploys the exact reconciled commit.

An import run succeeds when it published one or more assessments, recorded only
report-local quarantines, or had no changes. It fails when a batch-level
provider or trusted-input boundary fails.

## Verification

TDD coverage must prove:

- the provider prompt omits observation IDs and explicitly permits candidate
  IDs only;
- deterministic required counts are present in every synthesis request;
- unknown candidate IDs produce rejected and allowed ID repair fields;
- count mismatch repair contains the exact required counts;
- the second request differs from the first;
- identical repair feedback stops a redundant later request;
- a valid corrected response succeeds and records the requested model identity;
- invalid output after bounded attempts produces a typed report-local failure;
- provider transient and provider security failures remain batch-level;
- one invalid report is quarantined while later valid reports are assessed;
- a quarantine is skipped without a provider call on the next run;
- a changed digest, policy version, or explicit retry is eligible;
- quarantined reports are absent from preferred IDs while historical reports
  remain retained;
- state-only quarantine changes are persisted;
- incident identity deduplicates repeated scheduled runs; and
- workflow permissions, staging, validation, and exact deployment include the
  new state path.

Focused synthesis, report-import, publication, workflow, and static-export
tests run before Tavernary's complete `npm.cmd run check` gate.

## Rollout

1. Implement and review this change on a Tavernary branch independently of the
   TavernKeeper scheduler branch.
2. Merge only after focused and complete Tavernary checks pass.
3. Dispatch report reconciliation against the live TavernKeeper index.
4. Verify the previously blocking report either succeeds with candidate-only
   repair or becomes one persisted quarantine.
5. Verify later valid reports import and publish in the same run.
6. Verify a second scheduled run does not call synthesis for the unchanged
   quarantine.
7. Verify the incident contains only sanitized fields and points to the failed
   run.
8. Verify the exact committed summary deploys and the site exposes no preferred
   assessment for the quarantined report.

No TavernKeeper report or catalog reset is required.
