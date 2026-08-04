import {
  ReportIndexEntryV5Schema,
  type ReportIndexEntryV5,
} from "../contracts/reports-v5.js";
import {
  assessmentSummary,
  escapeHtml,
  FAVICON_LINKS,
  formatPublicDate,
  highestRisk,
  renderSiteHeader,
  shortSha,
  SCRIPT_FREE_CSP,
  SITE_ROOT,
  SITE_STYLES,
  TAVERNARY_URL,
} from "../site/presentation.js";

const HISTORY_STYLES = `
  .history-page { width: min(calc(100% - 32px), 900px); }
  .history-heading { max-width: 720px; margin-bottom: 32px; }
  .history-heading .eyebrow { margin-bottom: 8px; }
  .history-heading h1 { margin: 0; font-size: clamp(2rem, 5vw, 2.8rem); }
  .history-heading p:last-child { color: var(--text-secondary); }
  .history-list { display: grid; gap: 12px; margin: 0; padding: 0; list-style: none; }
  .history-item { padding: 18px; }
  .history-item-top { display: flex; align-items: flex-start; justify-content: space-between; gap: 18px; }
  .history-item h2 { margin: 0; font-size: 1.12rem; }
  .history-item h2 a { color: var(--text); }
  .history-item time { flex: none; color: var(--muted); font-size: 12px; }
  .history-summary { margin: 10px 0; color: var(--text-secondary); }
  .history-meta { display: flex; flex-wrap: wrap; gap: 6px 14px; margin: 0; color: var(--muted); font-size: 12px; }
  .history-action { margin: 14px 0 0; font-weight: 700; }
  .history-footer { display: flex; flex-wrap: wrap; gap: 8px 18px; margin-top: 30px; border-top: 1px solid var(--border); padding-top: 24px; }
  @media (max-width: 640px) {
    .history-item-top { flex-direction: column; gap: 5px; }
  }
`;

function compareHistory(left: ReportIndexEntryV5, right: ReportIndexEntryV5) {
  const time = Date.parse(right.completed_at) - Date.parse(left.completed_at);
  return time !== 0 ? time : right.report_id.localeCompare(left.report_id);
}

export function renderHistoryHtml(input: readonly unknown[]) {
  const reports = input
    .map((entry) => ReportIndexEntryV5Schema.parse(entry))
    .sort(compareHistory);
  if (reports.length === 0)
    throw new Error("Repository history requires at least one report.");
  const repository = reports[0]!.repository;
  const repositoryId = reports[0]!.repository_id;
  if (
    reports.some(
      (report) =>
        report.repository_id !== repositoryId ||
        report.repository !== repository,
    )
  )
    throw new Error("Repository history entries must share one identity.");
  const conclusions = reports
    .map((report) => {
      const risk = highestRisk(report.counts.recommended_risk);
      return `<li class="history-item surface risk-mark risk-${risk}">
        <article>
          <div class="history-item-top">
            <h2><a href="${escapeHtml(report.report_url)}"><code>${escapeHtml(shortSha(report.target_sha))}</code></a></h2>
            <time datetime="${escapeHtml(report.completed_at)}">${escapeHtml(formatPublicDate(report.completed_at))}</time>
          </div>
          <p class="history-summary">${escapeHtml(assessmentSummary(report.counts.recommended_risk))}</p>
          <p class="history-meta">
            <span>${escapeHtml(report.counts.recommended_risk.high)} high &middot; ${escapeHtml(report.counts.recommended_risk.material)} material &middot; ${escapeHtml(report.counts.recommended_risk.low)} low</span>
            <span>${escapeHtml(report.coverage.review_completed)} of ${escapeHtml(report.coverage.review_required)} candidates assessed</span>
          </p>
          <p class="history-action"><a href="${escapeHtml(report.report_url)}">View report</a></p>
        </article>
      </li>`;
    })
    .join("\n");
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="TavernKeeper scan history for ${escapeHtml(repository)}.">
  <meta http-equiv="Content-Security-Policy" content="${escapeHtml(SCRIPT_FREE_CSP)}">
  ${FAVICON_LINKS}
  <title>TavernKeeper scan history &middot; ${escapeHtml(repository)}</title>
  <style>${SITE_STYLES}${HISTORY_STYLES}</style>
</head>
<body>
  ${renderSiteHeader()}
  <main class="page-shell history-page">
    <header class="history-heading">
      <p class="eyebrow">TavernKeeper Scan History</p>
      <h1>Scan history for <a href="https://github.com/${escapeHtml(repository)}">${escapeHtml(repository)}</a></h1>
      <p>Each entry records an advisory review of one exact commit. Newer scans appear first; earlier evidence remains available for comparison.</p>
    </header>
    <ol class="history-list">${conclusions}</ol>
    <footer class="history-footer">
      <a href="${SITE_ROOT}">Browse reports</a>
      <a href="${TAVERNARY_URL}">Return to Tavernary</a>
    </footer>
  </main>
</body>
</html>
`;
}
