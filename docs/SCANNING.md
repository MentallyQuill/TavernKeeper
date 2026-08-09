# Scanning policy

TavernKeeper policy 4 is an automated, exact-SHA, static security scan. It is a
first filter for Tavernary, not a full audit and never a certification that a
project is safe. Its main improvement over policy 3 is explicit analysis of
minified, encoded, and bundled JavaScript, including committed dependencies and
generated distributions that older first-party-only classification could omit.

## GitHub-only automation boundary

The production path uses GitHub-hosted Actions, repository state, one-day
GitHub artifacts, GitHub release assets for pinned scanner binaries, and GitHub
Pages. JavaScript analysis uses exact locked npm packages installed inside the
Action. The only non-GitHub runtime call is the already configured contextual
model. TavernKeeper has no scan server, database, daemon, persistent worker,
source cache, or separately hosted deobfuscation service.

The existing `scan-and-publish.yml` workflow is divided at a credential
boundary:

1. The credential-free `prepare` matrix job checks out trusted TavernKeeper
   code, acquires the exact target as hostile data, scans it, constructs bounded
   redacted evidence, verifies the target HEAD, deletes the target checkout,
   and uploads `prepared-${repository_id}` for one day. It receives no model,
   artifact-encryption, or Publisher credential.
2. The fresh `scan` matrix job downloads only its matching prepared artifact,
   checks the request, schema, byte ceiling, session identity, file digests, and
   evidence digest, and restores only `prepared.json` and
   `evidence-context.json`. It never receives a target checkout path or complete
   derived source. A sanitized preparation failure bypasses the model.
3. Successful evidence receives contextual model review. The finalized public
   report and sanitized transition then use the existing authenticated,
   encrypted `scan-${repository_id}` artifact and serialized publisher.

GitHub artifact transport is the only prepare-to-review handoff. The prepared
artifact is capped at 20,000,000 bytes and contains fixed scanner descriptions,
coverage, provenance digests, and character-bounded redacted evidence windows;
it contains no raw scanner payload, provider response, full repository file, or
full derivative.

## Static JavaScript pipeline

Every inventoried `.js`, `.cjs`, `.mjs`, `.jsx`, `.ts`, `.cts`, `.mts`, and
`.tsx` path is a candidate. This includes committed `node_modules`, `vendor`,
`dist`, generated bundles, and minified files. Inventory SHA-256 and byte length
are rechecked before a candidate is read.

For each candidate, TavernKeeper:

1. requires the repository OpenGrep run to account for the exact JavaScript
   path set, with minified-file exclusion disabled;
2. scans raw text with correlated credential-to-network and
   download-to-execution signatures plus NodeSecure JS-X-Ray;
3. decodes bounded literal-only base64, hex, percent, character-code, escape,
   and literal-concatenation forms without evaluating expressions;
4. asks locked `webcrack` code to unminify and unpack bundles with
   `deobfuscate: false`, producing data-only normalized and module
   representations;
5. rescans every novel derivative with the same signatures, JS-X-Ray, and the
   pinned OpenGrep rules; and
6. deduplicates findings while retaining only original repository paths and
   stage, digest, parent, transform, and depth provenance.

TavernKeeper never imports, evaluates, executes, builds, tests, or installs the
target. It never runs target package scripts, hooks, macros, Actions,
containers, WebAssembly, browser code, or native executables. The trusted
normalizer runs in a memory- and time-bounded worker; that worker is an
isolation mechanism for the scanner library, not permission to execute target
code.

## Policy ceilings

Policy 4 currently bounds JavaScript analysis to:

- 10,000 candidates and 536,870,912 aggregate candidate bytes;
- 16,777,216 bytes per transform input and derivative;
- 67,108,864 derivative bytes and 64 derivatives per candidate;
- 268,435,456 aggregate derivative bytes;
- three transform levels and 256 decoded literals per representation;
- 30 seconds and 512 MB old-generation heap per normalizer worker;
- 1,200,000 milliseconds for the integrated JavaScript analysis; and
- 24,000 evidence characters per finding and 20,000,000 prepared-artifact
  bytes per target.

The public report carries candidate bytes, representation counts, stage scan
counts, and at most 100 sorted unique unresolved original-path records. It does
not publish synthetic `derived/...` filenames or derivative contents.

## Complete and incomplete results

`complete` means every selected JavaScript candidate and derivative stayed
within the declared pipeline's coverage contract. It does not mean the code is
safe or that TavernKeeper can detect every Trojan.

`incomplete` means at least one parser, transform, recursion, timeout, memory,
input, output, candidate, derivative, target, or unsupported-data boundary was
unresolved. A completed deterministic run may still publish this bounded
coverage state so the gap is visible. The report includes the fixed first-filter
warning that there is no clean conclusion about unobserved behavior. An
otherwise-low project advisory is raised to at least material; incomplete
coverage alone never creates an immediate-danger basis and never lowers an
existing material or high advisory.

Hard acquisition, inventory, tool-integrity, malformed-output, evidence,
provider, finalization, sanitizer, or publication failures still publish no
new report and enter automatic retry. A report is therefore proof of a
validated run under a stated policy, not proof of exhaustive security.

## Verification

The inert hostile fixtures cover readable, minified, encoded, nested-encoded,
bundled, benign-minified, and malformed JavaScript. Tests read these files as
bytes and never import or execute them. On Linux x64, the production smoke test
also proves raw OpenGrep path closure and real decoded and bundle-module rescans
with the pinned binary.

```text
npm run check
npm run test:e2e
npm run build
npm run scanners:verify
npm run scanners:smoke
```
