import type {
  ReportIndexEntryV5,
  ReportIndexV5,
} from "../contracts/reports-v5.js";
import {
  deriveIndexedProjectAdvisory,
  escapeHtml,
  formatPublicDate,
  FAVICON_LINKS,
  projectAdvisorySummary,
  renderSiteHeader,
  shortSha,
  SITE_STYLES,
  TAVERNARY_URL,
} from "./presentation.js";

const LANDING_CSP = [
  "default-src 'none'",
  "style-src 'unsafe-inline'",
  "script-src 'self'",
  "img-src 'none'",
  "connect-src 'none'",
  "font-src 'none'",
  "media-src 'none'",
  "object-src 'none'",
  "frame-src 'none'",
  "base-uri 'none'",
  "form-action 'none'",
  "frame-ancestors 'none'",
].join("; ");

const EXTERNAL_SCANNERS = [
  {
    name: "Gitleaks",
    url: "https://github.com/gitleaks/gitleaks",
    what: "Searches source and repository history for exposed secrets and credential-like values.",
    usage:
      "TavernKeeper runs the pinned scanner against the exact commit and its bounded history as untrusted data.",
  },
  {
    name: "OpenGrep",
    url: "https://github.com/opengrep/opengrep",
    what: "Applies static-analysis rules to code to find security issues and suspicious patterns.",
    usage:
      "TavernKeeper runs the pinned engine with its review policy against the exact checkout without executing project code.",
  },
  {
    name: "OSV-Scanner",
    url: "https://github.com/google/osv-scanner",
    what: "Checks declared dependency inputs against known vulnerability advisories from the OSV ecosystem.",
    usage:
      "TavernKeeper applies it when the inventory contains supported dependency manifests, then records the advisory evidence for review.",
  },
  {
    name: "zizmor",
    url: "https://github.com/zizmorcore/zizmor",
    what: "Performs static analysis for security problems in GitHub Actions workflows.",
    usage:
      "TavernKeeper applies it to workflow files found in the exact commit, keeping workflow findings tied to that revision.",
  },
  {
    name: "malcontent",
    url: "https://github.com/chainguard-dev/malcontent",
    what: "Looks for signals associated with supply-chain attacks and suspicious behavior in project artifacts.",
    usage:
      "TavernKeeper applies it to eligible artifacts from the exact checkout and reports its results as candidates for contextual review.",
  },
] as const;

const LANDING_STYLES = `
  .hero { max-width: 780px; margin-bottom: 44px; }
  .hero h1 { margin: 8px 0 18px; }
  .lead { margin: 0; color: var(--text); font-size: clamp(1.05rem, 2vw, 1.24rem); line-height: 1.65; }
  .hero .secondary { margin-top: 14px; }
  .content-section { padding-block: 34px; border-top: 1px solid var(--border); }
  .section-heading { max-width: 700px; margin-bottom: 20px; }
  .section-heading p { margin-bottom: 0; }
  .report-controls {
    display: grid;
    grid-template-columns: minmax(0, 1fr) 190px auto;
    gap: 10px;
    align-items: end;
    margin-bottom: 12px;
  }
  .control { display: grid; gap: 6px; color: var(--text-secondary); font-size: 12px; font-weight: 650; }
  input,
  select,
  button {
    min-height: 42px;
    border: 1px solid var(--border-strong);
    border-radius: 6px;
    padding: 0 12px;
    color: var(--text);
    background: var(--header);
    font: inherit;
  }
  input:hover,
  select:hover,
  button:hover { border-color: var(--link); }
  button { cursor: pointer; color: var(--functional); font-weight: 700; }
  .report-status { min-height: 24px; margin: 0 0 8px; color: var(--muted); font-size: 12px; }
  .report-list { display: grid; gap: 12px; margin: 0; padding: 0; list-style: none; }
  .report-card { padding: 18px; }
  .report-card[hidden] { display: none; }
  .report-card-top { display: flex; align-items: flex-start; justify-content: space-between; gap: 18px; }
  .report-card h3 { margin: 0; font-size: 1.12rem; }
  .report-card h3 a { color: var(--text); text-decoration: none; }
  .report-card h3 a:hover { color: var(--link-hover); }
  .report-card time { flex: none; color: var(--muted); font-size: 12px; }
  .report-summary { margin: 10px 0; color: var(--text-secondary); }
  .report-meta,
  .report-actions { display: flex; flex-wrap: wrap; gap: 6px 14px; font-size: 12px; }
  .report-meta { color: var(--muted); }
  .report-actions { margin-top: 14px; }
  .report-actions a { font-weight: 700; }
  .no-results { margin: 16px 0 0; color: var(--text-secondary); }
  .steps { display: grid; gap: 12px; margin: 0; padding-left: 24px; }
  .steps li { padding-left: 8px; color: var(--text-secondary); }
  .steps strong { color: var(--text); }
  .scanner-grid { display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 14px; }
  .scanner-card { min-width: 0; padding: 18px; }
  .scanner-card h3 { margin: 0 0 10px; font-size: 1.08rem; }
  .scanner-card h3 a { color: var(--text); }
  .scanner-card h3 a:hover { color: var(--link-hover); }
  .scanner-card p { margin: 0; color: var(--text-secondary); }
  .scanner-card p + p { margin-top: 10px; }
  .scanner-card strong { color: var(--text); }
  .boundaries { display: grid; grid-template-columns: 1fr 1fr; gap: 32px; }
  .boundaries h3 { margin-top: 0; }
  .boundaries p { color: var(--text-secondary); }
  .page-footer { padding-top: 28px; border-top: 1px solid var(--border); color: var(--muted); }
  .page-footer a { margin-right: 18px; }
  @media (max-width: 700px) {
    .report-controls { grid-template-columns: 1fr; }
    .scanner-grid { grid-template-columns: 1fr; }
    .boundaries { grid-template-columns: 1fr; gap: 12px; }
    .report-card-top { flex-direction: column; gap: 5px; }
  }
`;

function renderReportCard(entry: ReportIndexEntryV5) {
  const advisory = deriveIndexedProjectAdvisory(entry);
  const risk = advisory.risk;
  const summary = projectAdvisorySummary(advisory);
  const search = [entry.repository, entry.target_sha, risk, summary]
    .join(" ")
    .toLocaleLowerCase();
  return `<li class="report-card surface risk-mark risk-${risk}" data-report-card data-risk="${risk}" data-search="${escapeHtml(search)}">
    <article>
      <div class="report-card-top">
        <h3><a href="${escapeHtml(entry.report_url)}">${escapeHtml(entry.repository)}</a></h3>
        <time datetime="${escapeHtml(entry.completed_at)}">${escapeHtml(formatPublicDate(entry.completed_at))}</time>
      </div>
      <p class="report-summary">${escapeHtml(summary)}</p>
      <div class="report-meta">
        <span>Commit <code>${escapeHtml(shortSha(entry.target_sha))}</code></span>
        <span>${escapeHtml(advisory.counts.high)} immediate danger</span>
        <span>${escapeHtml(advisory.counts.material)} material</span>
        <span>${escapeHtml(advisory.counts.low)} low</span>
      </div>
      <div class="report-actions">
        <a href="${escapeHtml(entry.report_url)}">View report</a>
        <a href="${escapeHtml(entry.history_url)}">Scan history</a>
      </div>
    </article>
  </li>`;
}

function renderScannerCard(scanner: (typeof EXTERNAL_SCANNERS)[number]) {
  return `<article class="scanner-card surface">
    <h3><a href="${escapeHtml(scanner.url)}">${escapeHtml(scanner.name)}</a></h3>
    <p><strong>What it checks.</strong> ${escapeHtml(scanner.what)}</p>
    <p><strong>How TavernKeeper uses it.</strong> ${escapeHtml(scanner.usage)}</p>
  </article>`;
}

export function renderLandingHtml(index: ReportIndexV5) {
  const reports = [...index.reports].sort(
    (left, right) =>
      Date.parse(right.completed_at) - Date.parse(left.completed_at) ||
      left.repository.localeCompare(right.repository),
  );
  const cards = reports.map(renderReportCard).join("\n");
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="Search advisory TavernKeeper security reports for Tavernary projects and understand how each exact-commit review works.">
  <meta http-equiv="Content-Security-Policy" content="${escapeHtml(LANDING_CSP)}">
  ${FAVICON_LINKS}
  <title>TavernKeeper · Advisory reports for Tavernary</title>
  <style>${SITE_STYLES}${LANDING_STYLES}</style>
  <script src="assets/report-search.js" defer></script>
</head>
<body>
  ${renderSiteHeader()}
  <main class="page-shell">
    <section class="hero" aria-labelledby="page-title">
      <p class="eyebrow">Tavernary security context</p>
      <h1 id="page-title">Technical security reports for Tavernary projects.</h1>
      <p class="lead">TavernKeeper examines one exact repository commit and publishes the evidence and limitations of that review. It helps inform Tavernary's project assessment; it does not certify that software is safe.</p>
      <p class="secondary">A completed report explains what was examined, what required attention, and what the process cannot know.</p>
    </section>

    <section class="content-section" id="reports" aria-labelledby="reports-title">
      <div class="section-heading">
        <h2 id="reports-title">Reports</h2>
        <p class="secondary">Search the current preferred report for each scanned repository. Earlier scans remain available through repository history.</p>
      </div>
      <div data-report-search="true">
        <div class="report-controls">
          <label class="control" for="report-query">Search reports
            <input id="report-query" type="search" placeholder="Repository or commit" autocomplete="off">
          </label>
          <label class="control" for="report-risk">Project advisory
            <select id="report-risk">
              <option value="all">All reports</option>
              <option value="high">Immediate danger</option>
              <option value="material">Material</option>
              <option value="low">Low / no material concern</option>
            </select>
          </label>
          <button id="report-clear" type="button">Clear</button>
        </div>
        <p class="report-status" id="report-status" aria-live="polite">${escapeHtml(reports.length)} ${reports.length === 1 ? "report" : "reports"} shown</p>
        <ul class="report-list">${cards}</ul>
        <p class="no-results" id="report-empty" hidden>No reports match this search. Clear the search to see every current report.</p>
      </div>
    </section>

    <section class="content-section" id="how-it-works" aria-labelledby="how-title">
      <div class="section-heading">
        <h2 id="how-title">How it works</h2>
        <p class="secondary">The process is exact-commit, complete-or-nothing, and designed to keep untrusted project code from becoming executable.</p>
      </div>
      <ol class="steps">
        <li><strong>Pin the target.</strong> Tavernary supplies an eligible GitHub repository identity and exact commit.</li>
        <li><strong>Inspect without executing.</strong> TavernKeeper inventories the checkout and runs required deterministic scanners against it as data.</li>
        <li><strong>Review candidate context.</strong> Bounded candidate context is sent to the named configured model provider under a strict response schema.</li>
        <li><strong>Validate and publish.</strong> Complete evidence and review coverage is validated before a sanitized immutable report is published.</li>
      </ol>
    </section>

    <section class="content-section" id="external-scanners" aria-labelledby="scanner-title">
      <div class="section-heading">
        <h2 id="scanner-title">External scanners</h2>
        <p class="secondary">TavernKeeper uses version-pinned, purpose-built scanners from established open-source projects. Each tool covers a different evidence source; applicable scanners run only when the exact commit contains the inputs they understand.</p>
      </div>
      <div class="scanner-grid">
        ${EXTERNAL_SCANNERS.map(renderScannerCard).join("\n")}
      </div>
    </section>

    <section class="content-section boundaries" aria-label="Scanning boundaries">
      <div>
        <h3>What TavernKeeper does</h3>
        <p>TavernKeeper treats the checkout as untrusted data. It inventories the exact commit, runs required deterministic scanners, and sends bounded candidate context to the named configured model provider for structured contextual assessment.</p>
      </div>
      <div>
        <h3>What TavernKeeper never does</h3>
        <p>It does not run dependencies, scripts, builds, tests, Actions, or target executables. Incomplete scanner, review, evidence, or publication coverage produces no report.</p>
      </div>
    </section>

    <footer class="page-footer">
      <p>A report is advisory evidence for one commit, not a guarantee about unknown behavior or future versions. Tavernary separately determines the public project assessment and freshness state.</p>
      <p><a href="${TAVERNARY_URL}">Visit Tavernary</a><a href="reports/index.json">Machine-readable report index</a></p>
    </footer>
  </main>
</body>
</html>
`;
}
