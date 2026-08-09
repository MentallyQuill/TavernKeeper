# Advisory Color Calibration Design

**Date:** 2026-08-09

## Goal

Restore the public advisory colors as meaningful security signals while keeping
coverage gaps and minor security hygiene visible. Yellow must mean a concrete,
demonstrated, non-malicious vulnerability that requires exploitation. Red must
remain limited to confirmed malicious or compromised behavior, or a confirmed
critical and readily exploitable vulnerability. Everything else remains teal
with explicit findings and limitations.

This change applies to TavernKeeper's report contract and Tavernary's imported
advisory synthesis. It does not rescan the catalog, bypass the 48-hour rule, or
spend model calls to recolor existing reports.

## Current failure

Two independent policy choices inflate yellow:

1. TavernKeeper and Tavernary promote an otherwise-low result to material when
   JavaScript analysis is incomplete or evidence is metadata-only.
2. The contextual-review prompt and schema require unresolved material-looking
   candidates to remain material even when the affected package, runtime path,
   attacker-controlled trigger, or concrete data flow is not demonstrated.

The model is following those contracts. Changing model providers or editing
summary wording cannot correct the deterministic color result.

## Public color contract

### Teal: findings or limitations, but no demonstrated caution-level risk

Teal includes:

- expected behavior;
- minor security hygiene;
- vulnerable-dependency matches without a demonstrated affected version,
  shipped runtime path, and attacker-controlled trigger;
- same-file or broad correlations without a demonstrated data flow;
- secrets found only in tests, fixtures, documentation, or tooling unless the
  evidence establishes that the credential is current and usable;
- incomplete JavaScript analysis and metadata-only evidence; and
- uncertainty that remains after bounded context expansion.

These items stay visible in the technical report and public limitations. Teal
does not mean certified safe or complete.

### Yellow: demonstrated, exploitable, non-malicious risk

A finding may produce yellow only when all of these are true:

- the disposition is `material_vulnerability`;
- exposure is `demonstrated`;
- confidence is `high`;
- impact is `medium`, `high`, or `critical`;
- exploitability is `plausible` or `readily_exploitable`; and
- the evidence identifies the affected shipped or executable behavior and a
  concrete attacker-controlled or untrusted-input trigger or data flow.

The behavior appears non-malicious and does not cause harm autonomously. Harm
requires an exploit or triggering condition. This is the exact meaning of
"handle with caution."

### Red: confirmed immediate danger

Red remains limited to either:

- high-confidence, demonstrated credible malicious or compromised behavior; or
- a demonstrated material vulnerability with critical impact, readily
  exploitable behavior, and high confidence.

Coverage gaps, scanner severity, advisory severity, popularity, and model
uncertainty can never create red.

## TavernKeeper review contract

The contextual assessment schema gains
`risk_exposure: "not_demonstrated" | "demonstrated"`. The contextual-review
policy, prompt, and assessment-schema versions advance together. The strict
JSON schema requires the field on every new assessment and observation.

`demonstrated` means the supplied evidence shows the affected shipped or
executable component or behavior and its concrete activation, trigger, or
untrusted-input path. A package advisory, file presence, scanner correlation,
metadata-only record, or incomplete coverage state is insufficient by itself.

Schema validation enforces the color contract. `material_vulnerability` can
recommend material only with demonstrated exposure, high confidence,
medium-or-greater impact, and plausible-or-greater exploitability. The existing
critical/readily/high branch recommends high and also requires demonstrated
exposure. Credible malicious behavior requires demonstrated exposure and high
confidence. Other assessments recommend low.

On the final bounded model attempt, unresolved uncertainty is expressed as
`risk_exposure: "not_demonstrated"`, low confidence where appropriate, and low
recommended risk. It is not promoted to material.

Published-report parsing remains backward compatible with older assessment
schemas. New reports contain `risk_exposure`; immutable historical reports do
not need to be rewritten.

## Dependency evidence

The OSV adapter retains the bounded package identity already present in
OSV-Scanner JSON: ecosystem, package name, and resolved version. These fields
are normalized into safe candidate title and explanation text and remain
subject to the existing public-text length and character limits. Raw advisory
text and arbitrary URLs are not published.

Package identity and version improve review accuracy, but an advisory still
does not produce yellow without a demonstrated shipped runtime path and
attacker-controlled input reaching the vulnerable behavior.

## Coverage behavior

Incomplete JavaScript analysis and metadata-only evidence continue to:

- appear in fixed report limitations;
- appear in coverage status and unresolved-path details; and
- prevent any claim of complete safety.

They no longer alter advisory risk or material counts. Hard acquisition,
scanner, evidence, provider, finalization, or publication failures continue to
publish no report and enter the existing retry path.

## Legacy report calibration

Tavernary advances its synthesis policy. Existing entries whose report identity
has not changed are migrated without scanning their repositories and without a
model call.

For historical assessments that predate `risk_exposure`, a yellow finding must
already satisfy the high-confidence, medium-impact, plausible-exploitability
tuple and must point to shipped code. Test, fixture, documentation, and tooling
findings do not qualify. Dependency or correlation findings that explicitly
state reachability or data flow is unconfirmed do not qualify. Existing red
findings retain the immediate-danger rules and are never silently lowered by a
coverage limitation.

Low existing summaries can be version-migrated directly when their report
projection is unchanged. Existing yellow or red summaries fetch only their
immutable report JSON and receive a deterministic recalibration. New reports
using the new TavernKeeper contextual policy use Luna synthesis normally. New
reports using an older contextual policy use the deterministic legacy path.

The migrated summary records
`assessment_source: "deterministic_regrade"`. Calibrated public counts mean:

- `minor_cautions`: low-risk non-expected items, including downgraded legacy
  candidates;
- `material_concerns`: items that satisfy the yellow contract; and
- `high_danger`: items that satisfy the red contract.

This avoids contradictory teal cards that still claim material concerns. Raw
immutable counts and findings remain available in the linked TavernKeeper
report.

## Release order and safety

1. Keep TavernKeeper's catalog-wide emergency stop active.
2. Land and verify the TavernKeeper contract, OSV evidence, coverage behavior,
   report rendering, and backward-compatible parsing.
3. Land and verify Tavernary synthesis policy and deterministic regrade.
4. Reconcile Tavernary until every preferred report uses the new synthesis
   policy, proving that legacy migration made no model calls.
5. Deploy both exact merged SHAs and verify hydrated public cards and linked
   reports.
6. Only then continue the one-time bounded coverage campaign and ordinary
   new-or-updated scanning.

Rollback is a code rollback plus regeneration from immutable report JSON. It
does not require repository rescans or state deletion.

## Verification

Required tests include:

- strict schema rejection for material risk without demonstrated exposure;
- strict schema acceptance for the imported-template execution example;
- teal results for incomplete JavaScript and metadata-only coverage;
- OSV package identity/version preservation without raw advisory text;
- legacy dependency and broad-correlation downgrade fixtures;
- legacy shipped-code execution staying yellow;
- red malicious and critical-exploitable fixtures staying red;
- no-model migration of unchanged low summaries and deterministic regrade of
  non-low summaries;
- exact calibrated public counts and assessment-source validation; and
- full repository checks in both projects before merge and deployment.
