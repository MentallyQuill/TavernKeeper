# GitHub-Only Integrated JavaScript Scanning Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Integrate bounded, non-executing analysis of minified, bundled, vendored, and literal-encoded JavaScript into TavernKeeper's existing exact-SHA GitHub Actions scanning and reporting stack.

**Architecture:** Policy 4 adds a required `javascript-analysis` adapter after the existing repository OpenGrep run. The adapter accounts for all committed JavaScript paths, scans raw and safely derived representations, returns typed coverage and ephemeral provenance, and supplies bounded redacted evidence to the existing contextual reviewer. The existing reusable workflow is split into credential-free preparation and fresh-runner model-review jobs without introducing another workflow, service, or publication path.

**Tech Stack:** Node.js 24, TypeScript 6, Vitest 4, Zod 4, OpenGrep 1.26.0, `@nodesecure/js-x-ray` 16.0.0, `webcrack` 2.16.0, GitHub Actions, GitHub artifacts, Technical Report V5

## Global Constraints

- Use only GitHub-hosted Actions, GitHub repository/artifact storage, pinned npm packages or GitHub release assets, and the existing model provider.
- Do not add Kubernetes, gVisor, a dynamic provider, an external endpoint, persistent compute, or target-code execution.
- Integrate through the existing queue, exact-SHA checkout, scanner orchestration, contextual review, Technical Report V5, publication, reconciliation, and Pages workflow.
- Never run target `npm install`, lifecycle hooks, builds, imports, scripts, browsers, shells, or decoded/transformed code.
- Select committed JavaScript/TypeScript paths even under `dist`, `build`, `vendor`, `third-party`, and `node_modules`.
- Use exact analyzer dependency versions: `webcrack` 2.16.0 and `@nodesecure/js-x-ray` 16.0.0.
- Invoke webcrack with `deobfuscate: false`, `unminify: true`, `unpack: true`, and `jsx: false`; omit the sandbox callback.
- Keep deterministic coverage authoritative. The model cannot waive unresolved coverage or create a clean result from incomplete coverage.
- Preserve policy-3 Technical Report V5 history while requiring JavaScript coverage on policy-4 output.
- Preserve red-advisory discoverability and the distinction between immediate danger and material concern.
- Every production behavior change follows a witnessed RED, minimal GREEN, and regression run.

---

## File structure

### New focused modules

- `config/scanner-policy.v4.json` — exact policy-4 limits and queue/history constants.
- `src/scanners/javascript-analysis-types.ts` — Zod coverage, unresolved, representation, and ephemeral evidence-hint contracts.
- `src/scanners/javascript-candidates.ts` — deterministic candidate selection and stage applicability.
- `src/scanners/javascript-signatures.ts` — parser-independent correlated Trojan signatures with safe fixed metadata.
- `src/scanners/javascript-literals.ts` — bounded non-executing literal extraction and decoding.
- `src/scanners/javascript-normalizer.ts` — webcrack worker boundary and bundle-module extraction.
- `src/scanners/javascript-analysis.ts` — derivative queue, JS-X-Ray mapping, OpenGrep derived scan, coverage closure, and evidence provenance.
- `src/contracts/prepared-evidence.ts` — schema and identity for the secret-free prepare-to-review artifact.
- `src/cli/prepared-evidence.ts` — create/validate the prepared artifact envelope used by the existing workflow.
- `tests/javascript-analysis-primitives.test.ts` — candidates, signatures, and literal decoder tests.
- `tests/javascript-normalizer.test.ts` — real webcrack normalization/module extraction and worker failure tests.
- `tests/javascript-analysis.test.ts` — end-to-end adapter coverage and provenance tests.
- `tests/prepared-evidence.test.ts` — phase-handoff identity, size, and failure-envelope tests.
- `tests/fixtures/javascript-analysis/webpack-hidden.js` — inert browserify/webpack-style unit fixture with a hidden module signal.
- `tests/fixtures/javascript-analysis/benign.min.js` — inert benign minified unit fixture.
- `tests/fixtures/javascript-analysis/readable-trojan/src/index.js` — readable E2E signal fixture.
- `tests/fixtures/javascript-analysis/minified-trojan/dist/app.min.js` — one-line minified E2E signal fixture.
- `tests/fixtures/javascript-analysis/encoded-trojan/dist/app.min.js` — literal-encoded E2E signal fixture.
- `tests/fixtures/javascript-analysis/nested-encoded-trojan/dist/app.min.js` — bounded recursive-decoding E2E fixture.
- `tests/fixtures/javascript-analysis/bundled-trojan/dist/app.bundle.js` — module-extraction E2E fixture.
- `tests/fixtures/javascript-analysis/benign-minified/dist/library.min.js` — benign E2E control fixture.
- `tests/fixtures/javascript-analysis/malformed/dist/broken.min.js` — incomplete-coverage E2E fixture.
- `docs/SCANNING.md` — public operator description of policy-4 JavaScript coverage.

### Existing modules changed in place

- `package.json`, `package-lock.json` — exact analyzer dependencies.
- `src/config/policy.ts`, `src/cli/prepare-target.ts`, `src/cli/policy-rescan.ts` — policy-4 loading and freshness.
- `src/scanners/opengrep.ts`, `src/scanners/types.ts`, `src/scanners/run-scanners.ts` — path closure and required adapter integration.
- `src/contracts/scan-package.ts`, `src/contracts/reports-v5.ts` — policy-4 coverage contracts with historical compatibility.
- `src/orchestrator/scan-handler.ts`, `src/orchestrator/session.ts` — atomic integration, prepared evidence, and checkout removal.
- `src/context/evidence-context.ts`, `src/cli/review-target.ts` — bounded representation-aware context and offline expansion tiers.
- `src/report/contextual-report.ts`, `src/publish/sanitize.ts`, `src/publish/render-report.ts`, `src/publish/publisher.ts`, `src/site/presentation.ts` — coverage publication and non-low incomplete presentation.
- `.github/workflows/scan-and-publish.yml`, `scripts/check-workflow-policy.mjs` — prepare/review job boundary and secret checks.
- `scripts/smoke-scanners.ts`, `README.md`, `docs/architecture.md`, `docs/operations.md` — verification and operator documentation.
- Existing focused tests are updated alongside their owning production modules.

---

### Task 1: Introduce scanner policy 4 without breaking report history

**Files:**

- Create: `config/scanner-policy.v4.json`
- Modify: `src/config/policy.ts`
- Modify: `src/cli/prepare-target.ts`
- Modify: `src/cli/policy-rescan.ts`
- Modify: `src/orchestrator/scan-handler.ts`
- Modify: `src/orchestrator/session.ts`
- Modify: `src/report/contextual-report.ts`
- Modify: `scripts/check-workflow-policy.mjs`
- Test: `tests/policy.test.ts`
- Test: `tests/scan-atomicity.test.ts`
- Test: `tests/scan-session.test.ts`
- Test: `tests/workflows.test.ts`
- Test: `tests/e2e/scan-fixtures.test.ts`

**Interfaces:**

- Produces: `ScannerPolicyV4Schema`, `ScannerPolicyV4`, `JavascriptAnalysisPolicy`, and `loadScannerPolicy(path): Promise<ScannerPolicyV4>`.
- Preserves: Technical Report V5 parsing for historical `scanner_policy_version: "3"`.
- Changes runtime authority: every newly prepared scan requires `policy.version === "4"` and `scanner_policy_version === "4"`.

- [ ] **Step 1: Write failing policy and runtime-version tests**

```ts
test("loads exact policy 4 JavaScript limits", async () => {
  const policy = await loadScannerPolicy("config/scanner-policy.v4.json");
  expect(policy.version).toBe("4");
  expect(policy.javascriptAnalysis).toEqual(
    expect.objectContaining({
      maxCandidates: 10_000,
      maxCandidateBytes: 536_870_912,
      maxTransformInputBytes: 16_777_216,
      transformTimeoutMs: 30_000,
      maxWorkerOldGenerationMb: 512,
      maxDerivativeBytes: 16_777_216,
      maxDerivativeBytesPerCandidate: 67_108_864,
      maxTotalDerivativeBytes: 268_435_456,
      maxDerivativesPerCandidate: 64,
      maxRecursionDepth: 3,
      maxDecodedLiteralsPerRepresentation: 256,
      maxEvidenceCharactersPerFinding: 24_000,
      maxPreparedEvidenceBytes: 20_000_000,
      analysisTimeoutMs: 1_200_000,
    }),
  );
});

test("rejects policy 3 for a newly prepared target", async () => {
  await expect(
    prepareWith({ scannerPolicyVersion: "3" }),
  ).rejects.toMatchObject({
    code: "SCAN_POLICY_MISMATCH",
  });
});
```

- [ ] **Step 2: Run the focused tests and verify RED**

Run: `npm test -- tests/policy.test.ts tests/scan-atomicity.test.ts tests/scan-session.test.ts tests/workflows.test.ts tests/e2e/scan-fixtures.test.ts`
Expected: FAIL because `scanner-policy.v4.json`, `ScannerPolicyV4Schema`, and policy-4 runtime support do not exist.

- [ ] **Step 3: Add the exact policy schema and version migration**

Implement this public shape in `src/config/policy.ts`:

```ts
export const JavascriptAnalysisPolicySchema = z.strictObject({
  maxCandidates: z.literal(10_000),
  maxCandidateBytes: z.literal(536_870_912),
  maxTransformInputBytes: z.literal(16_777_216),
  transformTimeoutMs: z.literal(30_000),
  maxWorkerOldGenerationMb: z.literal(512),
  maxDerivativeBytes: z.literal(16_777_216),
  maxDerivativeBytesPerCandidate: z.literal(67_108_864),
  maxTotalDerivativeBytes: z.literal(268_435_456),
  maxDerivativesPerCandidate: z.literal(64),
  maxRecursionDepth: z.literal(3),
  maxDecodedLiteralsPerRepresentation: z.literal(256),
  maxEvidenceCharactersPerFinding: z.literal(24_000),
  maxPreparedEvidenceBytes: z.literal(20_000_000),
  analysisTimeoutMs: z.literal(1_200_000),
});

export const ScannerPolicyV4Schema = z.strictObject({
  version: z.literal("4"),
  queue: scannerPolicyShape.queue,
  history: scannerPolicyShape.history,
  inventory: scannerPolicyShape.inventory,
  commands: scannerPolicyShape.commands,
  javascriptAnalysis: JavascriptAnalysisPolicySchema,
  retry: scannerPolicyShape.retry,
});
```

Create `config/scanner-policy.v4.json`, update new-scan hardcoded literals and workflow-policy checks to version 4, and leave report schemas version-pattern based so policy-3 reports remain valid.

- [ ] **Step 4: Run focused tests and make GREEN**

Run: `npm test -- tests/policy.test.ts tests/scan-atomicity.test.ts tests/scan-session.test.ts tests/workflows.test.ts tests/e2e/scan-fixtures.test.ts`
Expected: PASS with all newly prepared fixtures using policy 4.

- [ ] **Step 5: Commit the policy boundary**

```text
feat(policy): add scanner policy v4
```

---

### Task 2: Close OpenGrep coverage against expected paths

**Files:**

- Modify: `src/scanners/types.ts`
- Modify: `src/scanners/opengrep.ts`
- Test: `tests/opengrep.test.ts`
- Test: `tests/external-tools.test.ts`

**Interfaces:**

- Produces: `ScannerPathCoverage = { scanned: string[]; skipped: Array<{ path: string; reason: "parse" | "timeout" | "target-limit" | "unsupported" }> }`.
- Extends: `ScannerRun.pathCoverage?: ScannerPathCoverage`.
- Extends: `runOpenGrep({ expectedPaths?, maxTargetBytes?, ... }): Promise<ScannerRun>`.

- [ ] **Step 1: Write failing path-accounting tests**

```ts
test("accounts for each expected minified path exactly once", async () => {
  const run = await runWithReport(
    {
      paths: {
        scanned: ["dist/app.min.js"],
        skipped: [{ path: "dist/large.js", reason: "Too_big" }],
      },
    },
    ["dist/app.min.js", "dist/large.js"],
  );
  expect(run.pathCoverage).toEqual({
    scanned: ["dist/app.min.js"],
    skipped: [{ path: "dist/large.js", reason: "target-limit" }],
  });
});

test.each([
  { scanned: [], skipped: [], name: "missing" },
  {
    scanned: ["dist/app.js"],
    skipped: [{ path: "dist/app.js", reason: "Timeout" }],
    name: "conflicting",
  },
  { scanned: ["../outside.js"], skipped: [], name: "escaping" },
])("rejects $name expected-path accounting", async ({ scanned, skipped }) => {
  await expect(
    runWithReport({ paths: { scanned, skipped } }, ["dist/app.js"]),
  ).rejects.toMatchObject({ code: "MALFORMED_SCANNER_OUTPUT" });
});
```

- [ ] **Step 2: Run the adapter tests and verify RED**

Run: `npm test -- tests/opengrep.test.ts tests/external-tools.test.ts`
Expected: FAIL because OpenGrep does not parse `paths`, accept expected paths, or expose coverage.

- [ ] **Step 3: Implement strict path closure and explicit flags**

Add this bounded command argument before `--config`:

```ts
`--max-target-bytes=${maxTargetBytes}`,
```

The pinned Python-compatible OpenGrep release scans minified files by default and does not accept the native CLI's `--no-exclude-minified-files` option. Normalize every scanned/skipped path through the existing root-boundary check. OpenGrep reports all attempted paths under `scanned` and may also report a failed path under `skipped`; project that native overlap into disjoint JavaScript coverage, ignore non-JavaScript repository paths for the coverage projection, and reject duplicates, missing expected paths, unknown skip reasons, or absent `paths` metadata for a manifest-bound scan. Preserve ordinary repository-wide findings outside `expectedPaths`.

- [ ] **Step 4: Run the adapter tests and make GREEN**

Run: `npm test -- tests/opengrep.test.ts tests/external-tools.test.ts`
Expected: PASS, including exact command argument assertions.

- [ ] **Step 5: Commit OpenGrep closure**

```text
feat(opengrep): account for expected paths
```

---

### Task 3: Add candidate selection, correlated signatures, and safe literal decoding

**Files:**

- Create: `src/scanners/javascript-analysis-types.ts`
- Create: `src/scanners/javascript-candidates.ts`
- Create: `src/scanners/javascript-signatures.ts`
- Create: `src/scanners/javascript-literals.ts`
- Create: `tests/javascript-analysis-primitives.test.ts`

**Interfaces:**

- Produces: `selectJavascriptCandidates(files): JavascriptCandidate[]` where candidate applicability distinguishes JavaScript and TypeScript stages.
- Produces: `scanJavascriptSignatures({ source, path, representation }): JavascriptPrimitiveResult`.
- Produces: `decodeJavascriptLiterals({ source, maxOutputs, maxOutputBytes }): DecodedLiteral[]`.
- Produces: Zod schemas for coverage stages/reasons, representations, and `JavaScriptEvidenceHint` without publishing source.

- [ ] **Step 1: Write failing primitive tests with inert strings**

```ts
test("selects committed vendored and generated JavaScript", () => {
  expect(
    selectJavascriptCandidates([
      inventoryFile("src/index.ts"),
      inventoryFile("dist/app.min.js", { likelyMinified: true }),
      inventoryFile("node_modules/pkg/index.js"),
      inventoryFile("assets/logo.png", { kind: "binary" }),
    ]).map(({ path }) => path),
  ).toEqual(["dist/app.min.js", "node_modules/pkg/index.js", "src/index.ts"]);
});

test("requires normalization only for JavaScript-family source", () => {
  expect(candidate("src/a.js").requiresNormalization).toBe(true);
  expect(candidate("src/a.ts").requiresNormalization).toBe(false);
});

test("correlates credential access with an outbound sink without retaining literals", () => {
  const source = "const t=process.env.API_TOKEN;fetch(endpoint,{body:t})";
  const result = scanJavascriptSignatures({
    source,
    path: "dist/a.min.js",
    representation: rawRepresentation(source),
  });
  expect(result.findings).toMatchObject([
    { rule_id: "javascript.credential-to-network", path: "dist/a.min.js" },
  ]);
  expect(JSON.stringify(result.findings)).not.toContain("API_TOKEN");
});

test("does not flag an isolated base64 literal or ordinary fetch", () => {
  const source = `const logo="${Buffer.from("ordinary image data").toString("base64")}"; fetch("/status")`;
  expect(
    scanJavascriptSignatures({
      source,
      path: "src/a.js",
      representation: rawRepresentation(source),
    }).findings,
  ).toEqual([]);
});

test.each([
  [
    `atob("${Buffer.from("eval(fetch(endpoint))").toString("base64")}")`,
    "base64",
  ],
  ["String.fromCharCode(101,118,97,108,40,120,41)", "char-code"],
  ["decodeURIComponent('%65%76%61%6c%28%78%29')", "percent"],
])(
  "decodes supported literal form without executing it",
  (source, transform) => {
    const outputs = decodeJavascriptLiterals({
      source,
      maxOutputs: 8,
      maxOutputBytes: 4096,
    });
    expect(outputs[0]).toMatchObject({ transform });
    expect(outputs[0]?.content).toMatch(/eval/);
  },
);
```

- [ ] **Step 2: Run primitive tests and verify RED**

Run: `npm test -- tests/javascript-analysis-primitives.test.ts`
Expected: FAIL because the primitive modules do not exist.

- [ ] **Step 3: Implement conservative non-executing primitives**

Candidate selection sorts portable paths and includes applicable binary/oversized entries for coverage accounting. Signature rules require combinations of source/sink/execution/download/persistence signals and return fixed metadata plus safe offsets. Literal decoding accepts only quoted literals, numeric literal argument lists, and literal-only concatenations; it rejects identifier resolution, malformed encodings, non-UTF-8 output, output beyond the supplied byte ceiling, and low-printability noise.

The result contracts are:

```ts
export interface JavascriptRepresentation {
  stage: "raw" | "decoded" | "normalized" | "bundle-module";
  sha256: string;
  parentSha256: string | null;
  transform:
    | "original"
    | "base64"
    | "hex"
    | "percent"
    | "char-code"
    | "literal-concat"
    | "webcrack-normalized"
    | "webcrack-module";
  depth: number;
}

export interface DecodedLiteral {
  content: string;
  transform: "base64" | "hex" | "percent" | "char-code" | "literal-concat";
  sourceStart: number;
  sourceEnd: number;
}
```

- [ ] **Step 4: Run primitive tests and make GREEN**

Run: `npm test -- tests/javascript-analysis-primitives.test.ts`
Expected: PASS with no target code executed.

- [ ] **Step 5: Commit the primitives**

```text
feat(scanner): add safe JavaScript primitives
```

---

### Task 4: Normalize and scan derivatives without execution

**Files:**

- Modify: `package.json`
- Modify: `package-lock.json`
- Create: `src/scanners/javascript-normalizer.ts`
- Create: `src/scanners/javascript-analysis.ts`
- Create: `tests/javascript-normalizer.test.ts`
- Create: `tests/javascript-analysis.test.ts`
- Create: `tests/fixtures/javascript-analysis/webpack-hidden.js`
- Create: `tests/fixtures/javascript-analysis/benign.min.js`
- Modify: `src/policy/rule-descriptions.ts`
- Test: `tests/rule-descriptions.test.ts`

**Interfaces:**

- Produces: `normalizeJavascript(source, limits): Promise<NormalizationResult>` with sorted normalized/module derivatives.
- Produces: `runJavascriptAnalysis(spec, dependencies?): Promise<ScannerRun>`.
- Extends: `ScannerRun.javascriptAnalysis`, `ScannerRun.evidenceHints`, and `ScannerRun.derivativeAncestry` as internal typed fields.

- [ ] **Step 1: Install exact analyzer dependencies**

Run: `npm install --save-exact webcrack@2.16.0 @nodesecure/js-x-ray@16.0.0`
Expected: `package.json` contains exact versions and the lockfile records their resolved integrity.

- [ ] **Step 2: Write failing real-normalizer and adapter tests**

```ts
test("extracts and returns actual bundle modules", async () => {
  const source = await readFile(
    "tests/fixtures/javascript-analysis/webpack-hidden.js",
    "utf8",
  );
  const result = await normalizeJavascript(source, testLimits);
  expect(
    result.derivatives.some(({ transform }) => transform === "webcrack-module"),
  ).toBe(true);
  expect(result.derivatives.map(({ content }) => content).join("\n")).toMatch(
    /process\.env/,
  );
});

test("does not enable webcrack deobfuscation or a sandbox", async () => {
  const calls: unknown[] = [];
  await normalizeJavascript(
    "const value=1",
    testLimits,
    async (source, options) => {
      calls.push(options);
      return { code: source, bundle: undefined };
    },
  );
  expect(calls).toEqual([
    { deobfuscate: false, unminify: true, unpack: true, jsx: false },
  ]);
});

test("finds a signal revealed only after literal decoding", async () => {
  const encoded = Buffer.from(
    "const t=process.env.API_TOKEN;fetch(endpoint,{body:t})",
  ).toString("base64");
  const run = await analyzeFixture(`eval(atob("${encoded}"))`);
  expect(run.findings).toEqual(
    expect.arrayContaining([
      expect.objectContaining({ rule_id: "javascript.credential-to-network" }),
    ]),
  );
  expect(run.javascriptAnalysis?.representations.decoded).toBeGreaterThan(0);
});

test("marks exhausted recursion incomplete instead of clean", async () => {
  const run = await analyzeNestedEncoding({ depth: 4, maxRecursionDepth: 3 });
  expect(run.javascriptAnalysis).toMatchObject({
    status: "incomplete",
    unresolved: [
      expect.objectContaining({
        stage: "literal-decode",
        reason: "recursion-limit",
        recovered: false,
      }),
    ],
  });
});
```

- [ ] **Step 3: Run focused tests and verify RED**

Run: `npm test -- tests/javascript-normalizer.test.ts tests/javascript-analysis.test.ts tests/rule-descriptions.test.ts`
Expected: FAIL because the normalizer/adapter and JavaScript rule descriptions do not exist.

- [ ] **Step 4: Implement the worker and derivative queue**

The worker returns data only:

```ts
type WorkerReply =
  | { ok: true; code: string; modules: Array<{ id: string; code: string }> }
  | { ok: false; reason: "parse" | "memory-limit" | "unsupported" };
```

Create the worker with `resourceLimits.maxOldGenerationSizeMb` from policy. The parent terminates it at `transformTimeoutMs`. The worker imports webcrack, passes the exact approved options, reads `result.code`, and serializes `result.bundle?.modules` in module-ID order. It never calls `save`.

`runJavascriptAnalysis` verifies candidate bytes, processes representations breadth-first in stable digest order, deduplicates per original path, enforces every byte/count/depth/time limit, maps JS-X-Ray warning locations from `[[line, column], [line, column]]`, runs derived OpenGrep against a synthetic manifest, and builds complete/incomplete coverage. It catches target-specific parse/limit errors as unresolved records and rethrows schema/path/digest contradictions as `ScannerError`.

- [ ] **Step 5: Run focused tests and make GREEN**

Run: `npm test -- tests/javascript-normalizer.test.ts tests/javascript-analysis.test.ts tests/rule-descriptions.test.ts`
Expected: PASS, including the real bundle fixture and nested encoding fixture.

- [ ] **Step 6: Commit the derivative engine**

```text
feat(scanner): analyze JavaScript derivatives
```

---

### Task 5: Integrate JavaScript analysis into the required scanner and Scan Package

**Files:**

- Modify: `src/scanners/types.ts`
- Modify: `src/scanners/run-scanners.ts`
- Modify: `src/contracts/scan-package.ts`
- Modify: `src/orchestrator/scan-handler.ts`
- Modify: `src/orchestrator/session.ts`
- Test: `tests/conditional-scanners.test.ts`
- Test: `tests/scan-package.test.ts`
- Test: `tests/scan-atomicity.test.ts`
- Test: `tests/scan-session.test.ts`

**Interfaces:**

- Required tool set includes `javascript-analysis` between OpenGrep and conditional scanners.
- `ApplicableScannerSpec.inventoryFiles` carries the complete safe inventory so candidate selection cannot be reconstructed from first-party classification.
- `BuildScanPackageInput` accepts the validated JavaScript coverage from the adapter.
- Policy-4 `ScanPackageV1` requires `javascript_analysis`; historical policy-3 packages remain parseable only where already persisted and are not newly built.

- [ ] **Step 1: Write failing integration and package-invariant tests**

```ts
test("runs JavaScript analysis after repository OpenGrep with its path coverage", async () => {
  const calls: string[] = [];
  const runs = await runApplicableScanners(
    { ...spec, inventoryFiles: completeInventory.files },
    adaptersRecording(calls),
  );
  expect(calls).toEqual([
    "gitleaks",
    "opengrep",
    "javascript-analysis",
    "osv",
    "zizmor",
    "malcontent",
  ]);
  expect(runs.map(({ name }) => name)).toContain("javascript-analysis");
});

test("rejects policy-4 packages without JavaScript coverage", () => {
  expect(() =>
    validateScanPackageEvidence(
      policy4Package({ javascript_analysis: undefined }),
    ),
  ).toThrow(/JavaScript coverage/);
});

test("rejects complete status when unresolved JavaScript stages exist", () => {
  expect(() =>
    validateScanPackageEvidence(
      policy4Package({
        javascript_analysis: coverage({
          status: "complete",
          unresolved: [unresolved("parse")],
        }),
      }),
    ),
  ).toThrow();
});
```

- [ ] **Step 2: Run integration tests and verify RED**

Run: `npm test -- tests/conditional-scanners.test.ts tests/scan-package.test.ts tests/scan-atomicity.test.ts tests/scan-session.test.ts`
Expected: FAIL because the required scanner set and package do not include JavaScript analysis.

- [ ] **Step 3: Add the adapter to the authoritative orchestration**

Pass repository OpenGrep `pathCoverage`, inventory files, policy limits, rules root, executable, runner, and temporary root into `runJavascriptAnalysis`. Extend required tool origin mapping with `javascript-analysis`. Validate that `completed-with-limitations` is allowed only when coverage is incomplete and includes `javascript_unresolved`; reject missing/extra adapters, wrong version strings, or disagreement between tool status and coverage.

Use a stable composition version:

```ts
export const JAVASCRIPT_ANALYSIS_VERSION =
  "webcrack-2.16.0_js-x-ray-16.0.0_signatures-1_literals-1";
```

- [ ] **Step 4: Run integration tests and make GREEN**

Run: `npm test -- tests/conditional-scanners.test.ts tests/scan-package.test.ts tests/scan-atomicity.test.ts tests/scan-session.test.ts`
Expected: PASS with exact required-tool and coverage validation.

- [ ] **Step 5: Commit stack integration**

```text
feat(scanner): integrate JavaScript coverage
```

---

### Task 6: Build bounded representation-aware evidence and remove checkout dependence

**Files:**

- Modify: `src/context/evidence-context.ts`
- Modify: `src/orchestrator/session.ts`
- Modify: `src/cli/review-target.ts`
- Test: `tests/evidence-context.test.ts`
- Test: `tests/contextual-review.test.ts`
- Test: `tests/scan-session.test.ts`
- Test: `tests/cli.test.ts`

**Interfaces:**

- `EvidenceContextGroup.context` gains `expansions: string[]` and safe `representations` metadata.
- `buildEvidenceContextGroups` accepts JavaScript evidence hints and consumes full source only during the prepare phase.
- `expandEvidenceContextGroup(group, attempt)` uses precomputed tiers and no checkout/source argument.
- `reviewConfiguredTarget` requires session/model variables only; `TAVERNKEEPER_CHECKOUT_ROOT` is removed.
- `prepareTargetSession` performs the final exact-HEAD check before persisting evidence and deleting the checkout; `finalizePreparedSession` no longer accepts or performs checkout verification.

- [ ] **Step 1: Write failing evidence-boundary tests**

```ts
test("bounds a multi-megabyte one-line finding by characters", async () => {
  const source = `${"a".repeat(1_000_000)}eval(payload)${"b".repeat(1_000_000)}`;
  const groups = await buildGroupsWithHint(source, { columnStart: 1_000_001 });
  expect(groups[0]?.context.source.length).toBeLessThanOrEqual(24_000);
  expect(groups[0]?.context.source).toContain("eval(payload)");
});

test("expands from precomputed tiers without reading a checkout", () => {
  const group = evidenceGroup({
    context: { source: "small", expansions: ["larger"] },
  });
  expect(expandEvidenceContextGroup(group, 1).context.source).toBe("larger");
});

test("review target does not require a checkout path", async () => {
  await expect(
    reviewConfiguredTarget(modelEnvironmentWithoutCheckout(), dependencies),
  ).resolves.toEqual({ status: "reviewed" });
});

test("prepare removes the target checkout after verified evidence is written", async () => {
  await prepareTargetSession(spec);
  await expect(access(spec.checkoutRoot)).rejects.toMatchObject({
    code: "ENOENT",
  });
  await expect(
    access(resolve(spec.sessionRoot, "prepared.json")),
  ).resolves.toBeUndefined();
});
```

- [ ] **Step 2: Run evidence/session tests and verify RED**

Run: `npm test -- tests/evidence-context.test.ts tests/contextual-review.test.ts tests/scan-session.test.ts tests/cli.test.ts`
Expected: FAIL because evidence windows can include whole long lines, expansions read the checkout, and prepare retains it.

- [ ] **Step 3: Implement bounded windows and offline expansion tiers**

Introduce a deterministic character cap at every tier. For known lines/columns, center the window on the offset. For unknown locations, use the safe offsets from evidence hints; when none exist, take bounded head/middle/tail windows whose combined length stays under policy. Redact each tier before serialization. Attach only:

```ts
representations: Array<{
  stage: "raw" | "decoded" | "normalized" | "bundle-module";
  sha256: string;
  transform_depth: number;
}>;
```

After scanners and context construction, call exact-head verification, write the identity-bound session, and remove the checkout in `finally`. Review expansion selects `context.expansions[attempt - 1]` and rejects attempts beyond the precomputed array. Finalization validates the prepared-session and evidence identities instead of receiving a checkout verifier.

- [ ] **Step 4: Run evidence/session tests and make GREEN**

Run: `npm test -- tests/evidence-context.test.ts tests/contextual-review.test.ts tests/scan-session.test.ts tests/cli.test.ts`
Expected: PASS with no checkout requirement in the model phase.

- [ ] **Step 5: Commit the evidence boundary**

```text
feat(review): bound derived evidence context
```

---

### Task 7: Split the existing workflow into secret-free prepare and model-review jobs

**Files:**

- Create: `src/contracts/prepared-evidence.ts`
- Create: `src/cli/prepared-evidence.ts`
- Modify: `package.json`
- Modify: `.github/workflows/scan-and-publish.yml`
- Modify: `scripts/check-workflow-policy.mjs`
- Create: `tests/prepared-evidence.test.ts`
- Modify: `tests/workflows.test.ts`
- Modify: `tests/scan-session.test.ts`

**Interfaces:**

- Produces a secret-free artifact envelope with `schema_version`, `request`, `status`, `session_id`, `evidence_digest`, and either bounded session files or a sanitized phase failure.
- The existing `scan-and-publish.yml` gains a `prepare` matrix job; its `scan` matrix job becomes review/finalization and still produces the existing encrypted outcome artifact.
- Publish/deploy/reconcile job names and output contracts remain unchanged where consumed externally.

- [ ] **Step 1: Write failing envelope and workflow security tests**

```ts
test("rejects a prepared artifact whose evidence digest changed", async () => {
  const artifact = await createPreparedArtifact(validSession());
  artifact.files["evidence-context.json"] = artifact.files[
    "evidence-context.json"
  ].replace("source", "tampered");
  expect(() => validatePreparedArtifact(artifact)).toThrow(/identity|digest/);
});

test("caps the prepared artifact before upload", async () => {
  expect(() => createPreparedArtifact(oversizedSession(20_000_001))).toThrow(
    /size ceiling/,
  );
});

test("keeps model secrets out of the prepare job", () => {
  const workflow = loadScanWorkflow();
  expect(JSON.stringify(workflow.jobs.prepare)).not.toMatch(
    /TAVERNKEEPER_API_KEY|TAVERNKEEPER_MODEL|secrets\./,
  );
  expect(JSON.stringify(workflow.jobs.scan)).toMatch(/TAVERNKEEPER_API_KEY/);
  expect(JSON.stringify(workflow.jobs.scan)).not.toMatch(
    /TAVERNKEEPER_CHECKOUT_ROOT/,
  );
});
```

- [ ] **Step 2: Run workflow/handoff tests and verify RED**

Run: `npm test -- tests/prepared-evidence.test.ts tests/workflows.test.ts tests/scan-session.test.ts`
Expected: FAIL because the envelope and prepare job do not exist.

- [ ] **Step 3: Implement the prepared artifact contract and workflow split**

The prepare job performs trusted checkout/dependency/tool installation and target preparation, then always creates one short-retention artifact named `prepared-${repository_id}`. A successful envelope binds session/evidence identities. A target/shared failure envelope contains only the existing code/domain/component/diagnostic fields.

The review job has `needs: [plan, prepare]`, recreates the same request matrix, downloads only its repository-ID artifact, validates it, and either:

- resumes contextual review/finalization for a successful prepared session; or
- passes the sanitized failure into the existing transition/outcome path without calling the model.

The review job uploads the same encrypted `scan-${repository_id}` outcome expected by publish. Pin upload/download actions by commit SHA and set prepared artifact retention to one day. Extend workflow policy checks to prove the prepare job has no environment containing scanner secrets and the review job does not checkout target source.

- [ ] **Step 4: Run workflow/handoff tests and make GREEN**

Run: `npm test -- tests/prepared-evidence.test.ts tests/workflows.test.ts tests/scan-session.test.ts`
Expected: PASS with one prepared and one encrypted outcome per matrix request.

- [ ] **Step 5: Commit the GitHub job boundary**

```text
ci(scanner): isolate model review phase
```

---

### Task 8: Publish coverage and prevent incomplete analysis from appearing low

**Files:**

- Modify: `src/contracts/reports-v5.ts`
- Modify: `schemas/scan-report.v5.schema.json`
- Modify: `schemas/report-index.v5.schema.json`
- Modify: `src/report/contextual-report.ts`
- Modify: `src/publish/sanitize.ts`
- Modify: `src/publish/publisher.ts`
- Modify: `src/publish/render-report.ts`
- Modify: `src/site/presentation.ts`
- Test: `tests/contextual-report.test.ts`
- Test: `tests/report-render.test.ts`
- Test: `tests/publisher.test.ts`
- Test: `tests/site-presentation.test.ts`

**Interfaces:**

- `ScanReportV5.coverage.javascript_analysis` is optional for historical policy 3 and required when `scanner_policy_version === "4"`.
- Report-index coverage carries `javascript_analysis_status: "complete" | "incomplete" | "legacy"`.
- `deriveIndexedProjectAdvisory` and report-level advisory derivation accept coverage and return at least material risk for incomplete analysis unless an immediate-danger rule already makes it high.

- [ ] **Step 1: Write failing report/presentation tests**

```ts
test("requires JavaScript coverage on policy-4 reports", () => {
  expect(
    ScanReportV5Schema.safeParse(
      policy4Report({ javascript_analysis: undefined }),
    ).success,
  ).toBe(false);
  expect(ScanReportV5Schema.safeParse(policy3HistoricalReport()).success).toBe(
    true,
  );
});

test("presents incomplete JavaScript coverage as material, not low", () => {
  const advisory = deriveIndexedProjectAdvisory(
    indexEntry({
      recommended_risk: { high: 0, material: 0, low: 2 },
      javascript_analysis_status: "incomplete",
    }),
  );
  expect(advisory.risk).toBe("material");
  expect(advisory.dangerBasis).toBeNull();
});

test("renders bounded unresolved paths and the first-filter warning", () => {
  const html = renderReportV5Html(
    policy4Report({ javascriptStatus: "incomplete" }),
  );
  expect(html).toMatch(/JavaScript coverage.*Incomplete/isu);
  expect(html).toMatch(/no clean conclusion/iu);
  expect(html).not.toContain("derived/000001-");
});
```

- [ ] **Step 2: Run report/presentation tests and verify RED**

Run: `npm test -- tests/contextual-report.test.ts tests/report-render.test.ts tests/publisher.test.ts tests/site-presentation.test.ts`
Expected: FAIL because reports and cards do not carry JavaScript coverage.

- [ ] **Step 3: Add backward-compatible report coverage and rendering**

Add the same count/stage/unresolved schema used by the Scan Package, omitting all ephemeral source. Limit public unresolved entries to deterministic sorted unique records and the schema maximum. Add a fixed limitation sentence for incomplete coverage. Render coverage status, representation/stage counts, and bounded path/reason rows. Make incomplete coverage elevate only a low advisory to material; it never invents immediate danger and never lowers a high/material contextual advisory.

Regenerate schemas with:

```text
npm run contracts:generate
```

- [ ] **Step 4: Run report/presentation tests and make GREEN**

Run: `npm test -- tests/contextual-report.test.ts tests/report-render.test.ts tests/publisher.test.ts tests/site-presentation.test.ts`
Expected: PASS for both policy-3 historical and policy-4 reports.

- [ ] **Step 5: Commit report coverage**

```text
feat(report): publish JavaScript coverage
```

---

### Task 9: Add hostile canaries, smoke coverage, and integrated documentation

**Files:**

- Create: `tests/fixtures/javascript-analysis/readable-trojan/src/index.js`
- Create: `tests/fixtures/javascript-analysis/minified-trojan/dist/app.min.js`
- Create: `tests/fixtures/javascript-analysis/encoded-trojan/dist/app.min.js`
- Create: `tests/fixtures/javascript-analysis/nested-encoded-trojan/dist/app.min.js`
- Create: `tests/fixtures/javascript-analysis/bundled-trojan/dist/app.bundle.js`
- Create: `tests/fixtures/javascript-analysis/benign-minified/dist/library.min.js`
- Create: `tests/fixtures/javascript-analysis/malformed/dist/broken.min.js`
- Modify: `tests/e2e/scan-fixtures.test.ts`
- Modify: `scripts/smoke-scanners.ts`
- Modify: `tests/external-tools.test.ts`
- Modify: `README.md`
- Create: `docs/SCANNING.md`
- Modify: `docs/architecture.md`
- Modify: `docs/operations.md`
- Modify: `tests/workflows.test.ts`

**Interfaces:**

- Scanner smoke output proves raw OpenGrep path closure plus minified, encoded, and bundle-module analysis.
- Documentation names policy 4, GitHub-only resources, non-execution, limits, incomplete semantics, and the first-filter boundary.
- No fixture is imported or executed; all are read as inert bytes by scanner tests.

- [ ] **Step 1: Write failing end-to-end canary assertions**

```ts
test.each([
  ["readable-trojan", "raw"],
  ["minified-trojan", "normalized"],
  ["encoded-trojan", "decoded"],
  ["bundled-trojan", "bundle_modules"],
] as const)(
  "detects %s with %s representations",
  async (fixture, representationKey) => {
    const result = await fixtureScan(fixture);
    expect(result.ok).toBe(true);
    expect(result.value.scanPackage.findings).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ category: "credential-theft" }),
      ]),
    );
    expect(result.value.scanPackage.javascript_analysis.status).toBe(
      "complete",
    );
    expect(
      result.value.scanPackage.javascript_analysis.representations[
        representationKey
      ],
    ).toBeGreaterThan(0);
  },
);

test("keeps a benign minified library complete without material findings", async () => {
  const result = await fixtureScan("benign-minified");
  expect(result.value.scanPackage.javascript_analysis.status).toBe("complete");
  expect(
    result.value.scanPackage.findings.filter(
      ({ severity }) => severity === "high",
    ),
  ).toEqual([]);
});
```

- [ ] **Step 2: Run E2E and smoke tests and verify RED**

Run: `npm test -- tests/e2e/scan-fixtures.test.ts tests/external-tools.test.ts`
Expected: FAIL until every controlled representation is detected and documented smoke output is implemented.

- [ ] **Step 3: Complete inert fixtures, smoke output, and documentation**

Use `.invalid` endpoints and fake credential names. Fixture package manifests contain no lifecycle scripts. Add scanner smoke summary fields:

```ts
{
  raw_paths_accounted: number,
  javascript_candidates: number,
  decoded_representations: number,
  normalized_representations: number,
  bundle_modules: number,
  javascript_coverage: "complete" | "incomplete"
}
```

Document that incomplete is a published material concern, not a clean result, and that TavernKeeper remains a first filter rather than certification.

- [ ] **Step 4: Run the entire local verification ladder**

Run in order:

```text
npm run format:check
npm run typecheck
npm test
npm run build
npm run workflows:check
npm run scanners:verify
npm run scanners:smoke
```

Expected: every command exits 0; full Vitest output has zero skipped/failed files; smoke output reports complete controlled JavaScript coverage.

- [ ] **Step 5: Commit final canaries and documentation**

```text
test(scanner): certify GitHub-only coverage
```

---

## Deployment and reliability loop

After all nine tasks are locally green:

1. Review the complete branch diff against the design specification and run `git diff --check`.
2. Push `codex/github-only-scanning-v4` to `origin`.
3. Run and inspect all branch checks available to the repository.
4. Merge the verified branch into current `main`, resolve only genuine current-main integration conflicts, rerun the full verification ladder, and push `main`.
5. Verify the remote `main` SHA equals the local merged SHA.
6. Dispatch the existing reconciliation/policy-rescan workflow for policy 4.
7. Follow every linked run and every execution-time issue/state transition, not only one passing submission.
8. Verify exact-SHA reports for benign, minified, encoded, and bundled canaries; verify publication commit and Pages deployment SHA separately.
9. If a run fails, use systematic debugging: capture the failing phase/log, write a focused failing regression test, implement the minimal fix, rerun local verification, push the fix, and repeat the live scan.
10. Stop only when controlled canaries repeatedly publish with expected coverage and the ordinary durable queue resumes forward progress without a policy-4 systemic failure.
