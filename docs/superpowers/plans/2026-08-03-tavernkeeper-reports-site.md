# TavernKeeper Reports Site Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a concise Tavernary-family landing page with searchable reports and progressively disclosed technical report and history pages.

**Architecture:** Keep the site statically generated. A shared presentation module owns safe HTML helpers, semantic risk summaries, header markup, and the compact Tavernary-derived theme; dedicated renderers consume it for landing, report, and history pages. The landing page pre-renders the sanitized V5 index and adds one self-hosted, no-network filter script, while report and history pages remain script-free.

**Tech Stack:** TypeScript 6, Node.js 24, Vitest, static HTML/CSS, one dependency-free browser script, existing Zod V5 contracts.

## Global Constraints

- Plain language precedes scanner, provider, policy, and immutable identity details.
- Do not add a UI framework, runtime dependency, remote font, image, icon library, analytics, client data store, modal, sidebar, sticky navigation, score, gauge, or certification badge.
- Preserve TavernKeeper's advisory language and Tavernary's authority over final public project assessment and freshness.
- State that target code is not executed and bounded candidate context is sent to the named configured model provider.
- Keep report and history pages script-free; landing search may use one same-origin script with no fetch calls.
- Use native semantic elements and support 320px width without horizontal page scrolling.
- Do not mutate report JSON, report IDs, evidence, risk contracts, or the user-owned nested `F:\git\TavernKeeper\TavernKeeper` clone.

---

### Task 1: Shared presentation contract

**Files:**

- Create: `src/site/presentation.ts`
- Create: `tests/site-presentation.test.ts`

**Interfaces:**

- Consumes: `ContextualCountsV5` from `src/contracts/reports-v5.ts`.
- Produces: `RiskLevel`, `highestRisk`, `assessmentSummary`, `shortSha`, `formatPublicDate`, `escapeHtml`, `renderSiteHeader`, `SITE_STYLES`, and `SCRIPT_FREE_CSP`.

- [ ] **Step 1: Write failing behavior tests**

Create `tests/site-presentation.test.ts` with literal expectations that catch incorrect risk precedence, misleading copy, unsafe escaping, unreadable identity formatting, and missing shared navigation:

```ts
import { describe, expect, test } from "vitest";

import {
  assessmentSummary,
  escapeHtml,
  formatPublicDate,
  highestRisk,
  renderSiteHeader,
  shortSha,
} from "../src/site/presentation.js";

describe("public site presentation", () => {
  test("uses the highest published recommendation without calling it a verdict", () => {
    expect(highestRisk({ high: 1, material: 4, low: 8 })).toBe("high");
    expect(highestRisk({ high: 0, material: 2, low: 8 })).toBe("material");
    expect(highestRisk({ high: 0, material: 0, low: 8 })).toBe("low");
    expect(assessmentSummary({ high: 0, material: 0, low: 4 })).toBe(
      "No material or high-risk concern was identified in this review.",
    );
  });

  test("formats public identity without losing exact machine values", () => {
    expect(shortSha("1bce1fa73fe6c0fe8e767c773a832b94bb336720")).toBe(
      "1bce1fa",
    );
    expect(formatPublicDate("2026-08-03T10:32:31.505Z")).toBe("Aug 3, 2026");
    expect(escapeHtml('<img src="x">')).toBe("&lt;img src=&quot;x&quot;&gt;");
  });

  test("renders the small shared family header", () => {
    const html = renderSiteHeader();
    expect(html).toContain("Advisory reports for Tavernary");
    expect(html).toContain(
      'href="https://mentallyquill.github.io/TavernKeeper/#reports"',
    );
    expect(html).toContain('href="https://tavernary.org/"');
  });
});
```

- [ ] **Step 2: Run the focused test and confirm the missing-module failure**

Run:

```powershell
npm.cmd test -- tests/site-presentation.test.ts
```

Expected: FAIL because `src/site/presentation.ts` does not exist.

- [ ] **Step 3: Implement the smallest shared presentation module**

Create `src/site/presentation.ts` with these exact public shapes and behaviors:

```ts
import type { ContextualCountsV5 } from "../contracts/reports-v5.js";

export type RiskLevel = "low" | "material" | "high";
type RecommendedRiskCounts = ContextualCountsV5["recommended_risk"];

export const SITE_ROOT = "https://mentallyquill.github.io/TavernKeeper/";
export const TAVERNARY_URL = "https://tavernary.org/";

export function highestRisk(counts: RecommendedRiskCounts): RiskLevel {
  if (counts.high > 0) return "high";
  if (counts.material > 0) return "material";
  return "low";
}

export function assessmentSummary(counts: RecommendedRiskCounts) {
  if (counts.high > 0)
    return `${counts.high} high-risk concern${counts.high === 1 ? "" : "s"} identified.`;
  if (counts.material > 0)
    return `${counts.material} material concern${counts.material === 1 ? "" : "s"} identified.`;
  return "No material or high-risk concern was identified in this review.";
}

export function shortSha(value: string) {
  return value.slice(0, 7);
}

export function formatPublicDate(value: string) {
  return new Intl.DateTimeFormat("en-US", {
    day: "numeric",
    month: "short",
    timeZone: "UTC",
    year: "numeric",
  }).format(new Date(value));
}
```

Move the existing character-map HTML escaping into exported `escapeHtml`.
Add `renderSiteHeader()` using only the wordmark/subtitle and three links from
the spec. Add `SCRIPT_FREE_CSP` with `default-src 'none'`, inline style only,
and explicit denials for images, connections, fonts, media, objects, frames,
base changes, and forms.

Define `SITE_STYLES` as one CSS string containing the exact theme tokens from
the spec and only shared selectors used by the three page types:

```css
:root {
  color-scheme: dark;
  --canvas: #0d1117;
  --header: #101820;
  --surface: #182228;
  --surface-raised: #1c282e;
  --border: #2b3a40;
  --border-strong: #3e535b;
  --text: #e6edf3;
  --text-secondary: #a8b3ba;
  --muted: #829099;
  --link: #6ee7d8;
  --link-hover: #99f6e4;
  --focus: #5eead4;
  --functional: #e18a24;
  --warning: #d29922;
  --danger: #f85149;
  --radius: 8px;
}
* {
  box-sizing: border-box;
}
html {
  min-width: 320px;
  background: var(--canvas);
  color-scheme: dark;
}
body {
  margin: 0;
  background: var(--canvas);
  color: var(--text);
  font-family: Inter, system-ui, sans-serif;
  line-height: 1.55;
}
a {
  color: var(--link);
  text-underline-offset: 2px;
}
a:hover {
  color: var(--link-hover);
}
a:focus-visible,
button:focus-visible,
input:focus-visible,
select:focus-visible,
summary:focus-visible {
  outline: 2px solid var(--focus);
  outline-offset: 2px;
}
.site-header {
  border-bottom: 1px solid var(--border);
  background: var(--header);
}
.site-header-inner,
.page-shell {
  width: min(100% - 32px, 1040px);
  margin-inline: auto;
}
.site-header-inner {
  display: flex;
  min-height: 66px;
  align-items: center;
  justify-content: space-between;
  gap: 24px;
}
.brand {
  display: grid;
  color: var(--functional);
  font-size: 21px;
  font-weight: 750;
  line-height: 1;
  text-decoration: none;
}
.brand small {
  margin-top: 5px;
  color: var(--text-secondary);
  font-size: 10px;
  font-weight: 500;
}
.site-nav {
  display: flex;
  flex-wrap: wrap;
  justify-content: flex-end;
  gap: 16px;
  font-size: 12px;
}
.page-shell {
  padding-block: 42px 64px;
}
.eyebrow {
  color: var(--functional);
  font-size: 12px;
  font-weight: 750;
  letter-spacing: 0.09em;
  text-transform: uppercase;
}
h1,
h2,
h3 {
  color: var(--text);
  line-height: 1.2;
}
h1 {
  font-size: clamp(2rem, 5vw, 3.25rem);
  letter-spacing: -0.035em;
}
h2 {
  margin-top: 0;
  font-size: 1.5rem;
}
.surface {
  border: 1px solid var(--border);
  border-radius: var(--radius);
  background: var(--surface);
  box-shadow:
    0 1px 2px rgb(0 0 0 / 24%),
    0 4px 12px rgb(0 0 0 / 12%);
}
.secondary {
  color: var(--text-secondary);
}
.risk-low {
  --risk: var(--link);
}
.risk-material {
  --risk: var(--warning);
}
.risk-high {
  --risk: var(--danger);
}
.risk-mark {
  border-left: 4px solid var(--risk);
}
.metadata {
  display: grid;
  grid-template-columns: minmax(9rem, auto) 1fr;
  gap: 0.45rem 1rem;
}
.metadata dt {
  color: var(--muted);
}
.metadata dd {
  min-width: 0;
  margin: 0;
  overflow-wrap: anywhere;
}
details > summary {
  cursor: pointer;
  font-weight: 700;
}
@media (max-width: 640px) {
  .site-header-inner {
    align-items: flex-start;
    flex-direction: column;
    gap: 14px;
    padding-block: 14px;
  }
  .site-nav {
    justify-content: flex-start;
  }
  .page-shell {
    padding-top: 28px;
  }
  .metadata {
    grid-template-columns: 1fr;
    gap: 0.15rem;
  }
  .metadata dd {
    margin-bottom: 0.65rem;
  }
}
@media (prefers-reduced-motion: no-preference) {
  a,
  button,
  input,
  select {
    transition:
      border-color 150ms ease,
      color 150ms ease,
      background 150ms ease;
  }
}
```

- [ ] **Step 4: Run the focused test and full unit suite**

Run:

```powershell
npm.cmd test -- tests/site-presentation.test.ts
npm.cmd test
```

Expected: 3 focused tests pass; all baseline tests remain green.

- [ ] **Step 5: Commit the shared contract**

```powershell
git add src/site/presentation.ts tests/site-presentation.test.ts
git commit -m "feat(site): add presentation contract"
```

---

### Task 2: Static landing page and progressive search

**Files:**

- Create: `src/site/render-landing.ts`
- Create: `src/site/search-script.ts`
- Create: `tests/site-search.test.ts`
- Modify: `src/site/build-site.ts`
- Modify: `tests/site-build.test.ts`

**Interfaces:**

- Consumes: `ReportIndexV5`, shared presentation helpers, existing report JSON,
  and history JSON.
- Produces: `renderLandingHtml(index: ReportIndexV5): string`,
  `REPORT_SEARCH_SCRIPT: string`, and a site artifact whose current copied HTML
  is re-rendered from sanitized JSON.

- [ ] **Step 1: Add failing site-build expectations**

Update the isolated allowlist test to create a real V5 report with
`fixtureReportV5()`, project it with `projectReportToIndexV5()`, and write the
matching `report.json`, `history.json`, and index. Assert these literal outcomes:

```ts
expect(result.files).toContain("assets/report-search.js");
const landing = await readFile(join(output, "index.html"), "utf8");
expect(landing).toContain("Technical security reports for Tavernary projects");
expect(landing).toContain('id="reports"');
expect(landing).toContain('data-report-search="true"');
expect(landing).toContain(report.repository);
expect(landing).toContain("No material or high-risk concern was identified");
expect(landing).toContain("bounded candidate context");
expect(landing).toContain(
  "does not run dependencies, scripts, builds, tests, Actions, or target executables",
);
expect(landing).not.toContain("Report ID");
```

Also read the copied report and history `index.html` files and assert that the
old dummy markup was replaced by the corresponding V5 renderer output.

- [ ] **Step 2: Add a failing executable search-script test**

Create `tests/site-search.test.ts`. Execute `REPORT_SEARCH_SCRIPT` with
`node:vm` and small real stateful element doubles supporting `value`, `hidden`,
`dataset`, `textContent`, `addEventListener`, and `click`. Provide two cards:

```ts
const recursion = element({
  dataset: {
    reportCard: "",
    risk: "low",
    search: "mentallyquill recursion 1bce1fa no material concern",
  },
});
const wandlight = element({
  dataset: {
    reportCard: "",
    risk: "material",
    search: "mentallyquill wandlight 2d4f818 material concern",
  },
});
```

Assert observable behavior, not script text:

```ts
search.value = "Recursion 1bce";
search.dispatch("input");
expect(recursion.hidden).toBe(false);
expect(wandlight.hidden).toBe(true);
expect(status.textContent).toBe("1 report shown");

search.value = "";
risk.value = "material";
risk.dispatch("change");
expect(recursion.hidden).toBe(true);
expect(wandlight.hidden).toBe(false);

clear.click();
expect(search.value).toBe("");
expect(risk.value).toBe("all");
expect(recursion.hidden).toBe(false);
expect(wandlight.hidden).toBe(false);
```

- [ ] **Step 3: Run focused tests and confirm missing landing/search behavior**

Run:

```powershell
npm.cmd test -- tests/site-build.test.ts tests/site-search.test.ts
```

Expected: FAIL because the landing renderer and search script do not exist and
the builder still emits the browser-default root page.

- [ ] **Step 4: Implement pre-rendered landing HTML**

Create `renderLandingHtml` to:

- sort a copy of `index.reports` by `completed_at` descending;
- render the shared header and one `.page-shell`;
- use the exact content order and operational truth from the design spec;
- render one `<li class="report-card surface risk-mark risk-${risk}">` per
  entry with `data-report-card`, `data-risk`, and a lowercased escaped
  `data-search` value containing repository, full SHA, risk label, and summary;
- show repository, `assessmentSummary`, `formatPublicDate`, `shortSha`, the
  three risk counts, View report, and Scan history;
- render the search input, native select, Clear button, polite result status,
  and a hidden no-results paragraph; and
- emit a landing CSP with `script-src 'self'` and every other denial preserved.

The opening copy is:

```html
<p class="eyebrow">Tavernary security context</p>
<h1>Technical security reports for Tavernary projects.</h1>
<p class="lead">
  TavernKeeper examines one exact repository commit and publishes the evidence
  and limitations of that review. It helps inform Tavernary's project
  assessment; it does not certify that software is safe.
</p>
```

The developer-facing disclosure includes these exact facts in concise prose:

```html
<p>
  TavernKeeper treats the checkout as untrusted data. It inventories the exact
  commit, runs required deterministic scanners, and sends bounded candidate
  context to the named configured model provider for structured contextual
  assessment.
</p>
<p>
  It does not run dependencies, scripts, builds, tests, Actions, or target
  executables. Incomplete scanner, review, evidence, or publication coverage
  produces no report.
</p>
```

- [ ] **Step 5: Implement the dependency-free search script**

Create `REPORT_SEARCH_SCRIPT` as an IIFE that exits when the search root is
absent. It reads the existing pre-rendered cards, splits the lowercased query on
whitespace without mutating what the user typed, requires every token to appear
in `card.dataset.search`, applies the selected highest-risk value, updates
`card.hidden`, the polite singular/plural status, and the empty state, and makes
Clear reset both controls and reapply filtering. It makes no fetch or storage
calls.

- [ ] **Step 6: Wire the site builder and current HTML presentation**

In `buildSite`:

1. read and parse `reports/index.json` with `parseReportIndexV5`;
2. copy the three existing allowlisted trees;
3. write `index.html` from `renderLandingHtml`;
4. write `assets/report-search.js` from `REPORT_SEARCH_SCRIPT`;
5. for every preferred index entry, derive its safe relative public path from
   the schema-validated `report_url`, read its committed `report.json`, and
   overwrite only the output copy's `index.html` with `renderReportV5Html`;
6. for each unique schema-validated history URL, read `history.json` and
   overwrite only the output copy's `index.html` with `renderHistoryHtml`.

The source report JSON and HTML remain untouched. The Pages artifact receives
the current presentation, while the publisher renderers cover newly published
reports.

- [ ] **Step 7: Run focused tests and the site build**

Run:

```powershell
npm.cmd test -- tests/site-build.test.ts tests/site-search.test.ts
npm.cmd run site:build -- .site
```

Expected: focused tests pass; `.site/index.html` and
`.site/assets/report-search.js` exist; both current report pages and both
history pages in `.site/reports/` contain the shared header.

- [ ] **Step 8: Commit landing and search**

```powershell
git add src/site/render-landing.ts src/site/search-script.ts src/site/build-site.ts tests/site-build.test.ts tests/site-search.test.ts
git commit -m "feat(site): add searchable report landing"
```

---

### Task 3: Plain-language report hierarchy

**Files:**

- Modify: `src/publish/render-report.ts`
- Modify: `tests/report-render.test.ts`

**Interfaces:**

- Consumes: shared presentation primitives and sanitized `ScanReportV5`.
- Produces: script-free report HTML with summary-first hierarchy and unchanged
  evidence content.

- [ ] **Step 1: Write failing report hierarchy tests**

Extend `tests/report-render.test.ts` with assertions that catch regressions in
meaning, order, exact identity retention, CSP, and script isolation:

```ts
expect(html).toContain("Advisory reports for Tavernary");
expect(html).toContain(
  "No material or high-risk concern was identified in this review.",
);
expect(html).toContain('class="assessment-summary surface risk-mark risk-low"');
expect(html).toContain(
  `<time datetime="${report.completed_at}">Aug 2, 2026</time>`,
);
expect(html).toContain(">aaaaaaa<");
expect(html.indexOf("What this review found")).toBeLessThan(
  html.indexOf("Technical scan identity"),
);
expect(html).toContain(report.target_sha);
expect(html).toContain(report.report_id);
expect(html).toContain(report.contextual_reviewer.model);
expect(html).not.toMatch(/<script\b/iu);
expect(html).not.toMatch(/https:\/\/(?:fonts|cdn)\./iu);
```

Retain the existing checks that the renderer does not assign Tavernary's final
teal/orange/red grade.

- [ ] **Step 2: Run the report test and confirm the hierarchy failure**

Run:

```powershell
npm.cmd test -- tests/report-render.test.ts
```

Expected: FAIL because the old report front-loads technical identity and lacks
the shared header and plain-language summary.

- [ ] **Step 3: Refactor the report renderer minimally**

Keep candidate, observation, GitHub evidence-link, and sanitization logic.
Replace only page composition and CSS:

1. import shared escaping, theme, header, risk, date, summary, SHA, CSP, and URL
   helpers;
2. render the shared site header;
3. use `<main class="page-shell report-page">`;
4. render repository and short commit as the page heading context;
5. render `.assessment-summary` with `assessmentSummary` and the advisory
   limitation;
6. title the main assessment section "What this review found";
7. keep material/high cards visible, minor cautions visible, and expected
   scanner matches in the existing collapsed details;
8. render coverage and limitations next;
9. render reviewer, provider, full commit, exact time, policy versions, usage,
   and report ID inside a final `<details class="technical-identity">` titled
   "Technical scan identity"; and
10. keep the footer links to history/report directory and Tavernary.

Add only report-specific CSS selectors needed for spacing, finding cards,
technical evidence, and responsive wrapping. Use shared tokens and no new
visual system.

- [ ] **Step 4: Run focused and related publication tests**

Run:

```powershell
npm.cmd test -- tests/report-render.test.ts tests/report-sanitize.test.ts tests/publisher.test.ts
```

Expected: all focused publication tests pass.

- [ ] **Step 5: Commit report hierarchy**

```powershell
git add src/publish/render-report.ts tests/report-render.test.ts
git commit -m "feat(reports): clarify scan presentation"
```

---

### Task 4: Useful newest-first history

**Files:**

- Modify: `src/publish/render-history.ts`
- Modify: `tests/history-render.test.ts`

**Interfaces:**

- Consumes: shared presentation primitives and `ReportIndexEntryV5` history.
- Produces: script-free, newest-first repository history HTML.

- [ ] **Step 1: Change the history test to the desired observable order**

Replace the current oldest-first expectation and add family/clarity checks:

```ts
expect(html.indexOf("Aug 3, 2026")).toBeLessThan(html.indexOf("Aug 2, 2026"));
expect(html).toContain("Advisory reports for Tavernary");
expect(html).toContain("Scan history");
expect(html).toContain("View report");
expect(html).toContain("bbbbbbb");
expect(html).toContain("0 high · 0 material · 0 low");
expect(html).not.toMatch(/<script\b/iu);
expect(html).not.toMatch(/\b(?:teal|orange|red)\b/iu);
```

Construct the first fixture with completion `2026-08-02T12:00:00.000Z` and SHA
`"a".repeat(40)`. Construct the second with completion
`2026-08-03T12:00:00.000Z`, SHA `"b".repeat(40)`, report version 2, and the first
report ID as `supersedes_report_id`, so the literal date and short-SHA order is
unambiguous.

- [ ] **Step 2: Run the history test and confirm the old-order failure**

Run:

```powershell
npm.cmd test -- tests/history-render.test.ts
```

Expected: FAIL because `compareHistory` currently sorts oldest first and the
page lacks shared presentation.

- [ ] **Step 3: Implement compact newest-first history**

Reverse the completed-time comparison. Render the shared header, repository
heading, advisory sentence, and one `<li class="history-item surface risk-mark
risk-${highestRisk(...)}">` per report. Each item shows readable `<time>`, short
commit, high/material/low counts, completed/required contextual coverage, and a
View report link. Keep full report identity only in the existing URL.

- [ ] **Step 4: Run history, publisher, and site tests**

Run:

```powershell
npm.cmd test -- tests/history-render.test.ts tests/publisher.test.ts tests/site-build.test.ts
```

Expected: all related tests pass and current `.site` histories render newest
first after rebuilding.

- [ ] **Step 5: Commit history hierarchy**

```powershell
git add src/publish/render-history.ts tests/history-render.test.ts
git commit -m "feat(reports): improve scan history"
```

---

### Task 5: Full verification and rendered proof

**Files:**

- Verify only; change production files only in response to a reproduced test or
  rendered defect.

**Interfaces:**

- Consumes: all completed tasks.
- Produces: verified static artifact and desktop/mobile evidence.

- [ ] **Step 1: Run formatting and static checks**

```powershell
npm.cmd run format:check
npm.cmd run typecheck
npm.cmd run workflows:check
git diff --check
```

Expected: every command exits 0 with no formatting, type, workflow-policy, or
whitespace errors.

- [ ] **Step 2: Run the complete automated suite**

```powershell
npm.cmd test
npm.cmd run test:e2e
npm.cmd run build
npm.cmd run site:build -- .site
```

Expected: 43 or more unit test files and the E2E suite pass; TypeScript build
and production site build exit 0.

- [ ] **Step 3: Verify artifact security and content**

Run focused searches against `.site`:

```powershell
rg -n "Technical security reports for Tavernary projects|bounded candidate context|Advisory reports for Tavernary|What this review found|Technical scan identity" .site
rg -n "https://fonts|https://cdn|<script" .site/reports
```

Expected: the first command finds landing, report, and history content; the
second command finds no remote assets or report/history scripts.

- [ ] **Step 4: Perform desktop and mobile rendered checks**

Serve `.site` on `127.0.0.1` with a hidden local static server. In the in-app
browser verify the landing, a low/no-material report, and repository history at
1280x720 and 390x844. Check visible hierarchy, no horizontal scrolling, labeled
search and risk controls, keyboard focus, search by repository and SHA, risk
filter, Clear, empty state, collapsed expected matches, readable hashes, and
working links. Confirm no console errors.

- [ ] **Step 5: Review the complete branch diff against the spec**

```powershell
git status --short
git diff --stat 75c89c1634f8c1e97e269df040dba49038963d26..HEAD
git diff --check 75c89c1634f8c1e97e269df040dba49038963d26..HEAD
```

Read the final diff and confirm every design acceptance criterion has an
implementation or verification, with no unrelated files changed.
