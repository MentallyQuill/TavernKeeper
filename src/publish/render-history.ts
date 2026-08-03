import {
  ReportIndexEntryV5Schema,
  type ReportIndexEntryV5,
} from "../contracts/reports-v5.js";

const CSP = [
  "default-src 'none'",
  "style-src 'unsafe-inline'",
  "img-src 'none'",
  "object-src 'none'",
  "frame-ancestors 'none'",
  "base-uri 'none'",
  "form-action 'none'",
].join("; ");

function escapeHtml(value: string | number) {
  return String(value).replace(
    /[&<>"']/gu,
    (character) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        character
      ]!,
  );
}

function compareHistory(left: ReportIndexEntryV5, right: ReportIndexEntryV5) {
  const time = Date.parse(left.completed_at) - Date.parse(right.completed_at);
  return time !== 0 ? time : left.report_id.localeCompare(right.report_id);
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
    .map(
      (report) => `<li class="result">
        <a href="${escapeHtml(report.report_url)}" rel="noopener noreferrer"><strong>Contextual review</strong> at <code>${escapeHtml(report.target_sha)}</code></a>
        <span>${escapeHtml(report.completed_at)} &middot; policy ${escapeHtml(report.scanner_policy_version)} &middot; ${escapeHtml(report.counts.recommended_risk.high)} high &middot; ${escapeHtml(report.counts.recommended_risk.material)} material &middot; ${escapeHtml(report.counts.recommended_risk.low)} low</span>
        <p>${escapeHtml(report.coverage.review_completed)} of ${escapeHtml(report.coverage.review_required)} candidates assessed</p>
      </li>`,
    )
    .join("\n");
  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="Content-Security-Policy" content="${escapeHtml(CSP)}">
  <title>TavernKeeper scan history &middot; ${escapeHtml(repository)}</title>
  <style>
    :root { color-scheme: dark; font-family: ui-sans-serif, system-ui, sans-serif; background: #111318; color: #ecedf0; }
    body { max-width: 58rem; margin: 0 auto; padding: 2rem 1rem 4rem; line-height: 1.55; }
    a { color: inherit; } code { overflow-wrap: anywhere; }
    ol { list-style: none; padding: 0; }
    .result { border: 1px solid #353a44; border-left: .4rem solid #56d8c9; background: #191c22; padding: 1rem; margin-block: .75rem; display: grid; gap: .35rem; }
    .result span, .result p { color: #bcc2cc; margin: 0; }
  </style>
</head>
<body>
  <main>
    <h1>TavernKeeper Scan History</h1>
    <p>${escapeHtml(repository)} &middot; GitHub repository ${escapeHtml(repositoryId)}</p>
    <ol>${conclusions}</ol>
  </main>
</body>
</html>
`;
}
