# TavernKeeper favicon set Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a transparent orange favicon family derived from `scan.svg` and publish it from every TavernKeeper Pages route.

**Architecture:** `src/site/assets/` owns the canonical SVG and checked-in raster derivatives. `presentation.ts` owns one shared site-root-absolute favicon metadata fragment, all three HTML renderers insert it into their `<head>`, and `buildSite()` copies the allowlisted asset directory into `.site/assets/`.

**Tech Stack:** TypeScript 6, Node.js 24, Vitest 4, static HTML generation, SVG, PNG, ICO.

## Global Constraints

- Use the existing TavernKeeper orange `#E18A24`.
- Preserve the supplied scan mark geometry and transparent background.
- Use site-root-absolute URLs under `https://mentallyquill.github.io/TavernKeeper/assets/` so nested report and history routes resolve icons correctly.
- Do not add a runtime dependency, manifest, service worker, remote asset, icon library, or UI redesign.
- Leave the unrelated untracked `TavernKeeper/` directory untouched.

---

### Task 1: Add failing favicon contract tests

**Files:**

- Create: `tests/favicon.test.ts`
- Modify: `tests/site-build.test.ts`

**Interfaces:**

- Consumes the existing `renderLandingHtml`, `renderReportV5Html`, `renderHistoryHtml`, `buildSite`, `fixtureReportV5`, and `SITE_ROOT` APIs.
- Produces executable assertions for the source SVG, metadata contract, and allowlisted build output.

- [ ] **Step 1: Write the failing tests**

Add tests that require:

```ts
const expectedAssets = [
  "assets/apple-touch-icon.png",
  "assets/favicon-16.png",
  "assets/favicon-32.png",
  "assets/favicon-48.png",
  "assets/favicon-192.png",
  "assets/favicon-512.png",
  "assets/favicon.ico",
  "assets/favicon.svg",
];

expect(renderLandingHtml(index)).toContain(
  'href="https://mentallyquill.github.io/TavernKeeper/assets/favicon.svg"',
);
expect(renderReportV5Html(report)).toContain(
  'href="https://mentallyquill.github.io/TavernKeeper/assets/favicon-32.png"',
);
expect(renderHistoryHtml([entry])).toContain('rel="apple-touch-icon"');
```

Read `src/site/assets/favicon.svg` and assert it contains `#E18A24`, a
24-by-24 viewBox, and no opaque background fill. Read PNG headers to assert
the six raster files are square at their specified dimensions; assert the
ICO header reports three image entries.

Extend the existing temporary-root build test with a fixture
`src/site/assets/favicon.svg`, then assert `buildSite()` copies that file to
`assets/favicon.svg` while still excluding `src/secret.ts`.

- [ ] **Step 2: Run the focused tests and verify they fail**

Run:

```powershell
npm.cmd exec vitest run tests/favicon.test.ts tests/site-build.test.ts
```

Expected: failure because the source asset directory, shared metadata, and
asset-copy step do not exist yet.

### Task 2: Add the canonical asset family and HTML/build integration

**Files:**

- Create: `src/site/assets/favicon.svg`
- Create: `src/site/assets/favicon-16.png`
- Create: `src/site/assets/favicon-32.png`
- Create: `src/site/assets/favicon-48.png`
- Create: `src/site/assets/apple-touch-icon.png`
- Create: `src/site/assets/favicon-192.png`
- Create: `src/site/assets/favicon-512.png`
- Create: `src/site/assets/favicon.ico`
- Modify: `src/site/presentation.ts`
- Modify: `src/site/render-landing.ts`
- Modify: `src/publish/render-report.ts`
- Modify: `src/publish/render-history.ts`
- Modify: `src/site/build-site.ts`

**Interfaces:**

- `presentation.ts` exports a `FAVICON_LINKS` string containing the complete
  site-root-absolute `<link>` family.
- `buildSite()` adds `src/site/assets` to its allowlist and copies it to
  `.site/assets` before writing generated scripts.

- [ ] **Step 1: Add the canonical SVG**

Copy the supplied `scan.svg` geometry into `src/site/assets/favicon.svg`, set
the visible mark's fill to `#E18A24`, retain `viewBox="0 0 24 24"`, and keep
the background path `fill="none"`.

- [ ] **Step 2: Generate checked-in raster derivatives**

Use a temporary cached `sharp@0.34.5` install outside the repository to
rasterize the SVG at 16, 32, 48, 180, 192, and 512 pixels with RGBA output.
Write 180px to `apple-touch-icon.png`; write the other sizes to their named
`favicon-*.png` files. Build `favicon.ico` as a standard ICO container with
the 16px, 32px, and 48px PNG payloads. Do not add `sharp` to
`package.json`; the checked-in assets are the production source.

- [ ] **Step 3: Add shared metadata**

In `src/site/presentation.ts`, define `FAVICON_LINKS` using `SITE_ROOT`:

```ts
export const FAVICON_LINKS = [
  `<link rel="icon" href="${SITE_ROOT}assets/favicon.svg" type="image/svg+xml">`,
  `<link rel="icon" href="${SITE_ROOT}assets/favicon.ico" sizes="any">`,
  `<link rel="icon" href="${SITE_ROOT}assets/favicon-32.png" type="image/png" sizes="32x32">`,
  `<link rel="icon" href="${SITE_ROOT}assets/favicon-16.png" type="image/png" sizes="16x16">`,
  `<link rel="apple-touch-icon" href="${SITE_ROOT}assets/apple-touch-icon.png" sizes="180x180">`,
  `<link rel="icon" href="${SITE_ROOT}assets/favicon-192.png" type="image/png" sizes="192x192">`,
  `<link rel="icon" href="${SITE_ROOT}assets/favicon-512.png" type="image/png" sizes="512x512">`,
].join("\n  ");
```

Insert `${FAVICON_LINKS}` in the `<head>` of the landing, report, and history
renderers. Extend `buildSite()`'s source list with `src/site/assets` and call
`copyTree()` into the existing output `assets` directory.

- [ ] **Step 4: Run focused tests and verify they pass**

Run:

```powershell
npm.cmd exec vitest run tests/favicon.test.ts tests/site-build.test.ts tests/site-presentation.test.ts
```

Expected: all focused favicon, allowlist, and presentation tests pass.

### Task 3: Rebuild and certify the generated Pages artifact

**Files:**

- Regenerate (ignored): `.site/index.html`, `.site/assets/*`, and generated
  report/history HTML

- [ ] **Step 1: Rebuild the static site**

Run:

```powershell
npm.cmd run site:build -- .site
```

Expected: the build completes and `.site/assets/` contains every expected
favicon file alongside `report-search.js`.

- [ ] **Step 2: Verify route-safe metadata and asset dimensions**

Search all generated HTML for the site-root favicon URLs and confirm no
favicon URL starts with `./` or points at a nested report directory. Run the
focused favicon test against the generated artifact and inspect the PNG/ICO
headers.

- [ ] **Step 3: Run the repository verification suite**

Run:

```powershell
npm.cmd run typecheck
npm.cmd run build
npm.cmd test
npm.cmd run format:check
```

Expected: each command exits 0 with no test failures or formatting changes.
