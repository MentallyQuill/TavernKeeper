# Report Consistency and Yellow Rescan Design

## Problem

The reports landing page derives a project advisory from the aggregated counters in `reports/index.json`, while an individual report page re-derives its advisory from the report's candidates, assessments, observations, and evidence metadata. Legacy reports can therefore show different colors in those two views. `Coneja-Chibi/VectHare` demonstrates the defect: its policy-2 index entry contains 16 stored material recommendations, but the current evidence-aware presentation policy regrades every item low.

The current public index contains 13 yellow entries. Every one predates the active scanner policy 5, contextual-review policy 5, prompt 7, and contextual-assessment schema 2 tuple.

## Considered Approaches

1. **Render all public views from the exact report evidence (chosen).** During the Pages build, load each preferred report once, derive its advisory with the same helper used by the detail renderer, and supply that advisory to the landing renderer. Preserve `reports/index.json` as the immutable machine projection of the original report.
2. Rewrite legacy index counters during deployment. This would make the landing page agree with current policy, but it would make the machine index counters disagree with the immutable report JSON that they claim to summarize.
3. Stop regrading individual reports and trust their historical counters. This would restore consistency by showing VectHare as yellow, but it would knowingly restore obsolete risk semantics and contradict the current demonstrated-risk presentation contract.

## Site Architecture

`render-report.ts` will expose one report-level advisory derivation function. It will combine candidate metadata with its matching assessment and enrich observations with their related candidate metadata before calling `deriveProjectAdvisory`. Both `renderReportV5Html` and `buildSite` will call this function.

`buildSite` will load and sanitize all preferred reports before rendering any page. It will create a map from `report_id` to the derived advisory, use that map for the landing page, and use the same parsed reports for detail pages. A missing advisory becomes a build error rather than silently falling back to aggregated index counters.

The copied machine-readable `reports/index.json` remains unchanged. It continues to record the historical report's original counters and version identity.

## Frozen Yellow Campaign

The staff policy-rescan workflow will gain an explicit `scope` choice with `all` as the compatibility default and `yellow` as the targeted option. The CLI will validate the scope and, for `yellow`, read the preferred report index and select repositories whose stored recommended-risk counts contain at least one `material` or `high` item. It will intersect those IDs with the current Tavernary target manifest.

The selected repository IDs are written into a durable policy campaign in `operations/state.json` at creation time. That list is the frozen campaign snapshot: later index changes do not add or remove targets. The workflow result will report the scope and target count, and ordinary reconciliation will process the campaign using policy 5.

For this approved run, the expected frozen target count is 13.

## Error Handling

- Reject unsupported campaign scopes before mutating state.
- Refuse to create an empty yellow campaign so a stale or malformed index cannot produce a misleading successful dispatch.
- Parse the index and reports through the existing V5 schemas.
- Fail the site build if a preferred report cannot be loaded or has no matching derived advisory.
- Preserve the existing protected staff environment, Publisher App token isolation, bounded push retry, and reconciliation path.

## Verification

- A site-build regression fixture will deliberately give its index a material counter while its report evidence derives low; both the generated landing card and report page must render low.
- Unit tests will prove yellow scope selects only material/high preferred reports, intersects with the current manifest, freezes literal repository IDs, rejects invalid scope, and rejects an empty selection.
- Workflow tests will prove the staff choice is bounded to `all` and `yellow` and is passed to the CLI without exposing new secrets.
- Full formatting, type checking, unit tests, workflow-policy checks, build, and hostile-fixture end-to-end tests must pass before publication.
- After merge, dispatch `policy-rescan.yml` with `scope=yellow`, verify the committed campaign contains the approved 13 IDs, monitor reconciliation until each gets a policy-5/schema-2 preferred report, then verify the deployed landing/detail color agreement.
