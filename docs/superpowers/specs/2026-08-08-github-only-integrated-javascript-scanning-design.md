# GitHub-Only Integrated JavaScript Scanning Design

**Status:** Approved for implementation on 2026-08-08
**Decision owner:** TavernKeeper operator
**Scope:** Policy-v4 JavaScript analysis inside TavernKeeper's existing exact-SHA scanning, contextual review, reporting, publishing, and reconciliation stack

## Decision

TavernKeeper will improve detection of malicious minified, bundled, vendored,
and encoded JavaScript using only GitHub-hosted Actions, GitHub artifacts and
repository storage, pinned npm packages and GitHub release assets, and the
existing contextual-review model. TavernKeeper will not depend on a persistent
external service or execute target code.

This is an in-place evolution of the current scanner. It is not a second
scanner product, a parallel publication path, or an optional sidecar. The
existing sequence remains authoritative:

1. durable queue selects an exact GitHub source SHA;
2. TavernKeeper checks out and inventories that SHA;
3. the existing scanner orchestration runs every required tool;
4. deterministic evidence is packaged and contextually reviewed;
5. Technical Report V5 is finalized, sanitized, published, and reconciled;
6. GitHub Pages deploys the same report family and history.

Policy version 4 adds stronger JavaScript stages and new coverage contracts to
that sequence. Reports created under policy 3 remain readable historical
records, while policy freshness schedules exact-SHA rescans under policy 4.

## Problem

The current production pipeline analyzes readable first-party text with
TavernKeeper rules and scans the repository with OpenGrep. Inventory separately
classifies minified files, generated bundles, and vendored dependencies, but
those classifications are not proof that the files were parsed or analyzed by
the applicable engines. OpenGrep's default target-size and minified-file
behavior is not closed against an expected path manifest. A parser error, skip,
or large one-line bundle can therefore reduce actual coverage without creating
an equally prominent coverage result.

Minified or bundled JavaScript also defeats ordinary evidence handling. A
finding with no trustworthy line number currently falls back to line one. For a
single-line multi-megabyte bundle, that can place the entire line into model
context. Conversely, formatting only the bundle wrapper can leave nested
webpack/browserify modules or encoded second stages unexamined.

The abandoned pass-two dynamic design required a Kubernetes/gVisor provider,
OIDC endpoint, signing service, container images, and persistent replay state.
Those requirements violate the GitHub-only operating boundary. Running hostile
code directly on a GitHub-hosted runner is also unacceptable: a hosted runner
is not a malware detonation sandbox, and job compromise can expose platform
tokens or later-step credentials.

No finite static scanner can prove that a project is safe. The enforceable
guarantee is that TavernKeeper accounts for every required stage and never
turns unknown or exhausted analysis into a clean-looking result.

## Goals

- Analyze every inventoried JavaScript/TypeScript path, including committed
  `dist`, `build`, `vendor`, `third-party`, and `node_modules` content.
- Scan original bytes before any transformation.
- Normalize minified code and extract actual webpack/browserify modules without
  evaluating target expressions.
- Recover common literal-encoded second stages with TavernKeeper-owned,
  non-executing decoders.
- Scan every novel bounded derivative with parser-independent signatures,
  JS-X-Ray, and the existing TavernKeeper OpenGrep rules.
- Preserve the original repository path plus safe representation provenance for
  findings and model evidence.
- Bound memory, time, derivative count, recursion, output, and model context.
- Publish deterministic findings when analysis is incomplete while preventing
  incomplete coverage from appearing low risk or clean.
- Keep all scheduling, retries, reports, Pages deployment, and operational
  reconciliation in the existing GitHub Actions stack.
- Separate untrusted parsing from model credentials at a GitHub Actions job
  boundary.

## Non-goals

- Executing repository scripts, lifecycle hooks, builds, packages, extensions,
  decoded strings, or transformed JavaScript.
- Claiming proof of safety or universal Trojan detection.
- Deploying Kubernetes, gVisor, microVMs, a remote HTTP provider, a database, or
  any persistent compute service.
- Making CodeQL a universal requirement. A later conditional experiment may be
  evaluated separately where licensing and language support permit it.
- Publishing transformed source, literal payloads, raw scanner messages,
  recovered URLs, credentials, or unbounded source excerpts.
- Allowing the model to declare scanner coverage complete, waive an unresolved
  stage, or replace deterministic finding identity.
- Downloading or installing target dependencies.

## Existing-stack architecture

### Scanner orchestration

`runApplicableScanners` remains the single scanner composition point. Policy 4
adds one required `javascript-analysis` run after the repository OpenGrep run.
The JavaScript adapter consumes inventory records and OpenGrep's validated path
coverage, performs raw and derived analysis, and returns ordinary normalized
findings plus JavaScript coverage and internal evidence hints.

The required tool order becomes:

1. `inventory`;
2. `tavernkeeper-static`;
3. `gitleaks`;
4. `opengrep`;
5. `javascript-analysis`;
6. `osv-scanner`;
7. `zizmor`;
8. `malcontent`.

The existing atomic finalization rules still apply. Inventory file length and
SHA-256 are revalidated before reading a candidate, and the exact Git HEAD is
revalidated after scanners finish. A changed checkout cannot produce a report.

### GitHub Actions phase boundary

The reusable `scan-and-publish.yml` workflow remains the only production scan
path, but its target matrix is divided into two jobs:

- **Prepare job:** checks out trusted TavernKeeper code, checks out the exact
  target SHA as data, runs deterministic scanners, constructs sanitized bounded
  evidence, verifies the target SHA, deletes the target checkout, and uploads a
  short-retention prepared-evidence artifact. It receives no model credential,
  publisher credential, or other repository secret.
- **Review job:** downloads and validates the prepared-evidence artifact on a
  fresh GitHub-hosted runner, performs contextual review with the existing model
  credentials, finalizes and encrypts the sanitized outcome, and uploads the
  existing outcome artifact for publication. It never receives the target
  checkout or complete derived source.

The prepared artifact contains only schema-validated report metadata, fixed
scanner descriptions, redacted bounded evidence windows, coverage records, and
content digests. It contains no raw tool output or full source file. GitHub's
artifact transport is the only handoff; no external endpoint or server is
introduced.

The existing publish, Pages deploy, incident reconciliation, queue continuation,
and provider-recovery jobs remain downstream. Their behavior changes only as
required to understand policy 4 and the new coverage fields.

## JavaScript candidate selection

Inventory remains the source of truth. A candidate is every inventoried path
whose filename ends in `.js`, `.cjs`, `.mjs`, `.jsx`, `.ts`, `.cts`, `.mts`, or
`.tsx`, regardless of first-party/excluded classification. Path segments such
as `dist`, `build`, `vendor`, `third-party`, and `node_modules` do not suppress
selection when those files were committed to the scanned source SHA.

Candidate selection includes text, binary, and oversized inventory records so
that an applicable path can never disappear. Text candidates proceed to
analysis. A JavaScript path inventoried as binary, unsafe, or beyond the raw
file ceiling produces a typed unresolved record.

Stage applicability is explicit. Raw signatures, literal decoding, and raw
OpenGrep accounting apply to every text JavaScript/TypeScript candidate.
JS-X-Ray, webcrack normalization, and bundle extraction are required for
JavaScript-family extensions (`.js`, `.cjs`, `.mjs`, and `.jsx`). They are
opportunistic, not coverage requirements, for TypeScript-family extensions
because unsupported TypeScript syntax must not make an otherwise completely
scanned source repository permanently inconclusive. A TypeScript file marked
minified or containing a supported encoded-literal execution signal is still
decoded and its JavaScript-like derivatives receive the full derived stages.

Each selected candidate is bound to:

- normalized repository-relative path;
- inventory kind and byte length;
- SHA-256 of original bytes;
- minified/generated/vendored classification;
- required stages under the active policy.

Candidates and every derivative are processed in stable path/digest order.

## Analysis stages

### 1. Raw byte signatures

A TavernKeeper-owned scanner examines the original UTF-8 bytes without needing
an AST. It records safe, fixed rule identities for high-signal combinations,
including:

- credential or browser-storage access combined with an outbound network sink;
- generated-code APIs (`eval`, `Function`, `vm`) combined with encoded or
  reconstructed input;
- child-process or shell execution combined with download/network behavior;
- installation or persistence hooks combined with a network retrieval;
- long encoded literals adjacent to decoding and execution primitives;
- Unicode bidirectional controls and suspicious mixed escaping.

Rules are correlation rules, not isolated keyword alarms. A bare `fetch`,
base64 string, `eval` example in documentation, or ordinary minification does
not by itself become a material advisory. The scanner returns fixed
TavernKeeper-owned explanations and never includes the matched literal.

The raw signature scanner works in bounded chunks and records offsets internally
for evidence-window construction. It must complete for every text candidate or
coverage is incomplete.

### 2. Raw AST analysis

Pinned `@nodesecure/js-x-ray` analyzes each candidate using aggressive
sensitivity. Allowlisted warning kinds map to TavernKeeper-owned categories,
severity, confidence, titles, and explanations. Parser failures become typed
coverage results. Unknown future warning kinds map to one fixed generic
low-confidence signal without retaining the untrusted warning text; malformed
locations or structurally invalid tool output fail the scanner contract.

Raw AST parsing is recoverable when at least one semantically equivalent
normalized representation parses successfully. Recovery is recorded rather
than silently erasing the raw parser failure.

### 3. Safe literal decoding

TavernKeeper-owned decoders extract only literal, locally decidable forms:

- direct `atob("...")` and `Buffer.from("...", "base64")` literals;
- quoted hexadecimal or JavaScript `\\xNN` / `\\uNNNN` escape sequences;
- percent-encoded string literals;
- bounded numeric `String.fromCharCode(...)` and
  `String.fromCodePoint(...)` literal argument lists;
- concatenations composed solely of quoted literals.

The decoder never resolves identifiers, invokes user functions, evaluates an
expression, follows network references, or executes decoded output. Decoding
requires valid syntax for the supported literal form, valid UTF-8 text, a
minimum signal/printability threshold, and policy-compliant output size.

Novel decoded outputs are content-addressed derivatives. Duplicate digests are
analyzed once per original candidate. A derivative may itself contain another
supported literal and may recurse only within the shared depth, count, time,
and byte ceilings.

### 4. Non-executing normalization and bundle extraction

Pinned `webcrack` runs in a worker thread with a memory ceiling and parent-owned
timeout. It is invoked with:

```ts
{
  deobfuscate: false,
  unminify: true,
  unpack: true,
  jsx: false,
}
```

The sandbox callback is omitted because deobfuscation is disabled. TavernKeeper
does not call `save` and does not accept arbitrary output paths. It collects:

- `result.code` when its digest differs from the input; and
- every `result.bundle.modules` entry, sorted by stable module ID, using the
  module's generated code.

This distinction is required: formatting only the wrapper is not bundle
coverage. Each extracted module becomes an independently bounded derivative
whose identity records `webcrack-normalized` or `webcrack-module`, parent
digest, depth, and output bytes.

Worker timeout, parser failure, memory termination, excessive output, invalid
UTF-8, duplicate/conflicting module identity, or limit exhaustion becomes typed
coverage. Target-controlled exception messages are discarded.

### 5. Derived scanning

Every novel decoded, normalized, or extracted-module derivative receives:

- parser-independent TavernKeeper signatures;
- JS-X-Ray AST analysis; and
- OpenGrep with the existing committed rule catalog.

Derived OpenGrep inputs live in a scan-session temporary directory under
synthetic content-addressed names. OpenGrep findings are mapped back to the
original repository path and retain internal derivative digest, transform,
depth, line, and column evidence hints. Synthetic paths never enter the public
report. The directory is removed before the prepare job completes.

Derivatives may re-enter safe literal decoding and normalization until a fixed
point or a policy ceiling. Content digests prevent loops.

## OpenGrep coverage closure

The existing OpenGrep adapter is extended rather than replaced. It receives:

- an explicit maximum target byte value;
- explicit inclusion of minified files;
- an expected JavaScript path manifest for the repository scan or synthetic
  derivative manifest for a derived scan.

TavernKeeper parses OpenGrep's `paths.scanned` and `paths.skipped` metadata.
Every path must resolve inside the requested root. Every expected path must be
accounted for exactly once as scanned or skipped. Every skipped path must map to
an allowlisted typed reason. Unknown paths, missing expected paths, conflicting
records, malformed metadata, or unsafe traversal is a scanner contract failure.

Parser syntax warnings, rule timeouts, and target-size skips are coverage
limitations. Raw parser coverage may be marked recovered only when a bounded
derived representation completes the corresponding analysis; the raw skip
remains visible in internal provenance.

## Coverage and provenance contracts

Policy 4 adds `javascript-analysis` to the required Scan Package tools and adds
a required JavaScript coverage object for new packages:

```ts
interface JavaScriptAnalysisCoverage {
  status: "complete" | "incomplete";
  candidates: number;
  candidate_bytes: number;
  representations: {
    raw: number;
    decoded: number;
    normalized: number;
    bundle_modules: number;
  };
  stages: {
    raw_signatures: number;
    raw_ast: number;
    raw_opengrep: number;
    derived_signatures: number;
    derived_ast: number;
    derived_opengrep: number;
  };
  unresolved: Array<{
    path: string;
    stage:
      | "raw-signatures"
      | "raw-ast"
      | "raw-opengrep"
      | "literal-decode"
      | "normalize"
      | "bundle-extract"
      | "derived-signatures"
      | "derived-ast"
      | "derived-opengrep";
    reason:
      | "binary"
      | "invalid-utf8"
      | "parse"
      | "timeout"
      | "memory-limit"
      | "input-limit"
      | "output-limit"
      | "candidate-limit"
      | "derivative-limit"
      | "recursion-limit"
      | "target-limit"
      | "unsupported";
    recovered: boolean;
  }>;
}
```

The exact schema may use snake-case field names consistent with the existing
Scan Package, but its semantics and enumerations are fixed by this design.
Coverage is complete only when every candidate has complete raw signature and
OpenGrep accounting, and every required AST/normalization/derivative branch
either completes or has an explicitly valid recovered alternative. Exhausting
a ceiling is not a fixed point and never counts as success.

`javascript-analysis` uses `completed-with-limitations` only when its coverage
is incomplete and at least one typed unresolved record exists. No JavaScript
candidate yields `not-applicable` with complete zero-candidate coverage.

Internal evidence provenance binds a normalized finding to one or more safe
representations:

```ts
interface JavaScriptEvidenceHint {
  finding_fingerprint: string;
  original_path: string;
  stage: "raw" | "decoded" | "normalized" | "bundle-module";
  representation_sha256: string;
  transform_depth: number;
  line_start: number | null;
  line_end: number | null;
  column_start: number | null;
  column_end: number | null;
  source: string;
}
```

This structure is ephemeral. Complete `source` is used only inside the
credential-free prepare job to create redacted bounded evidence windows, then
discarded. The prepared artifact retains only safe stage/digest/depth metadata
and those windows.

Technical Report V5 receives backward-compatible JavaScript coverage fields.
New policy-v4 reports always include them. Historical V5 reports without the
fields continue to validate. Report indexes and project cards must not derive a
low advisory from incomplete JavaScript coverage.

## Bounded model evidence

Evidence construction is representation-aware and character-bounded.

- Multiline source uses line-centered windows with a maximum character count.
- A single-line or very long-line artifact uses column/offset-centered windows,
  never the whole line.
- A finding with no trustworthy location receives bounded leading, middle, and
  trailing signal windows selected by deterministic signature/AST evidence,
  not an unbounded line-one fallback.
- Multiple representations for one candidate are labeled with fixed stage,
  transform depth, and digest prefix and combined only up to the group ceiling.
- Existing secret redaction runs before serialization, and the existing unique
  untrusted-repository-data boundary remains around all source supplied to the
  model.
- Expansion tiers are computed in the prepare job, redacted, character-bounded,
  and stored in the prepared artifact. The model job never reopens the target
  checkout.

The model contextualizes intent, project role, and practical risk. It cannot
change coverage, tool status, deterministic finding identity, or whether a
coverage limitation blocks a low presentation.

## Policy limits

All limits live in `config/scanner-policy.v4.json`, are validated as exact
runtime constants, and participate in scan freshness. Initial production
ceilings are:

- maximum candidates: 10,000;
- maximum raw bytes considered across candidates: 536,870,912 (512 MiB);
- maximum normalization input per representation: 16,777,216 (16 MiB);
- maximum normalization worker time: 30 seconds;
- maximum worker old-generation memory: 512 MiB;
- maximum single derivative: 16,777,216 (16 MiB);
- maximum derivative bytes per original candidate: 67,108,864 (64 MiB);
- maximum derivative bytes per repository: 268,435,456 (256 MiB);
- maximum derivatives per original candidate: 64;
- maximum recursion depth: 3;
- maximum decoded literals per representation: 256;
- maximum prepared evidence characters per finding: 24,000;
- maximum prepared evidence artifact bytes per target: 20,000,000;
- maximum JavaScript analysis wall time per target: 1,200 seconds.

Raw signature scanning is streaming and may inspect a candidate beyond the
normalization ceiling up to the inventory maximum. AST, normalization, and
derived stages that cannot operate within their own ceiling remain explicitly
incomplete. Limits may be tuned only through a new reviewed policy version or
scanner generation, followed by exact-SHA rescanning.

## Failure semantics and reliability

Target-specific limitations do not discard completed findings or abort the
remaining candidates. The adapter continues in stable order and publishes an
incomplete result. Examples include parser errors, an oversized bundle,
normalization timeout, invalid UTF-8, or exhausted derivative count.

System-integrity failures abort the target scan and use the existing durable
retry/reconciliation path. Examples include:

- inventory digest disagreement;
- path traversal or a derived path outside the temporary root;
- malformed or internally contradictory tool coverage;
- unknown required stage/reason values;
- duplicate derivative identity with conflicting bytes;
- prepared artifact digest/schema disagreement;
- target HEAD changing before prepare finalization.

Target-controlled exception text, stdout, stderr, source literals, and URLs are
not copied into phase errors. Existing operational incidents receive only the
bounded code/domain/component/diagnostic tuple.

An incomplete scan is still published because hiding it would be less safe. Its
report:

- prominently labels JavaScript coverage `Incomplete`;
- lists bounded repository paths and fixed unresolved reasons;
- retains deterministic findings and completed model assessments;
- states that no clean conclusion is available for unresolved code; and
- cannot render as low risk solely because no material finding was detected.

Red advisories remain discoverable under the existing product policy. Scanner
coverage changes do not introduce automatic delisting.

## Dependency and supply-chain policy

- `webcrack` and `@nodesecure/js-x-ray` are exact versions in
  `package-lock.json`; no ranges are permitted for these production analyzers.
- Existing external scanners remain SHA-256/digest pinned to reviewed GitHub
  release assets or container images.
- GitHub Actions remain commit-SHA pinned and workflow policy checks enforce the
  pins.
- Target repositories are never passed to `npm install`, `npm ci`, a build
  command, lifecycle hook, browser, shell, or imported module loader.
- TavernKeeper dependencies are installed only from TavernKeeper's reviewed
  lockfile before the target checkout is analyzed.
- No scanner may use network access while processing target content. Existing
  scanner command environments remain restricted; JavaScript workers receive
  only source bytes and numeric policy limits.

## Policy-v4 migration and automated rollout

1. Add policy 4, contracts, analyzers, evidence changes, and workflow phase
   split on one feature branch based on current `main`.
2. Preserve policy-3 report parsing and history while switching new scan
   preparation and policy freshness to version 4.
3. Verify focused tests, full tests, typecheck, formatting, build, workflow
   policy, scanner installation, and scanner smoke tests locally.
4. Run hostile fixtures without executing fixture code:
   - readable credential-to-network behavior;
   - one-line minified equivalent;
   - direct base64 literal decoded into a second-stage network/execution signal;
   - nested literal encoding within the recursion ceiling;
   - webpack/browserify wrapper whose malicious signal exists only in an
     extracted module;
   - benign minified library;
   - malformed, oversized, timeout, derivative-limit, and recursion-limit
     inputs.
5. Commit and push the feature branch, run the repository's ordinary branch
   checks, then merge the verified branch into `main` through the authorized
   existing integration process. A new pull request is not required by this
   design.
6. Dispatch the existing reconciliation/policy-rescan workflow. Do not create a
   separate scanner deployment workflow.
7. Prove live behavior at exact deployed `main` SHA with at least one benign
   catalog target and controlled exact-SHA scanning canaries for minified,
   encoded, and bundled fixtures.
8. Follow every linked Actions run through preparation, model review,
   publication, queue transition, and Pages deployment. Diagnose failures from
   execution-time logs and state, add a failing regression test, fix, redeploy,
   and repeat until the canaries publish reliably and ordinary queue progress
   resumes.

Policy activation is complete only when source, merged main, deployed workflow
SHA, published report, coverage presentation, and hydrated Pages behavior agree.
A passing unit suite or one passing Actions submission is not sufficient.

## Acceptance criteria

- All committed JavaScript paths are selected regardless of generated or
  vendored classification.
- OpenGrep accounts for every expected raw and derived JavaScript path.
- webcrack runs with deobfuscation disabled and scans both normalized code and
  every extracted bundle module.
- Supported literal encodings reveal controlled second-stage fixtures without
  evaluating them.
- Raw and every derivative receive parser-independent signatures plus bounded
  AST/OpenGrep analysis.
- Limits and parser failures produce explicit incomplete coverage rather than a
  clean result or an opaque target failure.
- A multi-megabyte one-line bundle cannot create multi-megabyte model context.
- Model credentials exist only in the fresh review job, which has no target
  checkout or complete derived source.
- New policy-v4 Scan Packages and reports validate, while historical policy-3
  Technical Report V5 artifacts still render.
- Incomplete JavaScript coverage cannot appear as a low advisory.
- Existing queue, retries, publication, report history, red-advisory
  discoverability, and Pages deployment continue to work.
- No external server, Kubernetes resource, dynamic-provider workflow, OIDC
  endpoint, or target-code execution is required.
- Live exact-SHA minified, encoded, bundled, and benign canaries complete and
  publish repeatedly through the existing automated stack.

## Rollback

If policy 4 causes a production-wide system failure, disable new reconciliation
dispatches through the existing emergency mechanism and revert the policy-4
activation commit on `main`. Do not rewrite or delete published reports. Policy
3 reports remain historical evidence, and queued targets retain their exact
source identities for a repaired policy-4 rescan. A rollback must not silently
mark policy-4 incomplete reports clean.

## Authoritative platform references

- GitHub-hosted runner specifications:
  https://docs.github.com/en/actions/reference/runners/github-hosted-runners
- GitHub Actions limits:
  https://docs.github.com/en/actions/reference/limits
- GitHub compromised-runner guidance:
  https://docs.github.com/en/actions/concepts/security/compromised-runners
- GitHub secure-use guidance:
  https://docs.github.com/en/actions/reference/security/secure-use
- webcrack repository: https://github.com/j4k0xb/webcrack
- JS-X-Ray repository: https://github.com/NodeSecure/js-x-ray
