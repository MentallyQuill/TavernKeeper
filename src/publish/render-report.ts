import type { ScanReport } from "../contracts/reports.js";
import { sanitizeReport } from "./sanitize.js";

const TAVERNARY_URL = "https://tavernary.org/";
const CSP = [
  "default-src 'none'",
  "style-src 'unsafe-inline'",
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

function escapeHtml(value: string | number) {
  return String(value).replace(
    /[&<>"']/gu,
    (character) =>
      ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;",
      })[character]!,
  );
}

function link(url: string, label: string) {
  return `<a href="${escapeHtml(url)}" rel="noopener noreferrer">${escapeHtml(label)}</a>`;
}

function renderFindings(report: ScanReport) {
  if (report.findings.length === 0)
    return "<p>No sanitized findings were published for this scan.</p>";
  return report.findings
    .map((finding) => {
      const location =
        finding.line_start === null
          ? finding.path
          : `${finding.path}:${finding.line_start}${
              finding.line_end !== null &&
              finding.line_end !== finding.line_start
                ? `-${finding.line_end}`
                : ""
            }`;
      return `<article class="finding">
        <h3>${escapeHtml(finding.title)}</h3>
        <p class="finding-meta">${escapeHtml(finding.severity)} severity · ${escapeHtml(finding.confidence)} confidence · ${escapeHtml(finding.category)}</p>
        <p><strong>Location:</strong> <code>${escapeHtml(location)}</code></p>
        <p>${escapeHtml(finding.explanation)}</p>
        ${finding.remediation === undefined ? "" : `<p><strong>Remediation:</strong> ${escapeHtml(finding.remediation)}</p>`}
        ${finding.reference_url === undefined ? "" : `<p>${link(finding.reference_url, "TavernKeeper rule documentation")}</p>`}
      </article>`;
    })
    .join("\n");
}

function renderExclusions(report: ScanReport) {
  return Object.entries(report.coverage.inventory.excluded)
    .map(
      ([category, totals]) =>
        `<li><span>${escapeHtml(category.replaceAll("_", " "))}</span><strong>${escapeHtml(totals.files)} files · ${escapeHtml(totals.bytes)} bytes</strong></li>`,
    )
    .join("\n");
}

export function renderReportHtml(input: unknown) {
  const report = sanitizeReport(input);
  const commitUrl = `${report.canonical_url}/commit/${report.target_sha}`;
  const resultSummary =
    report.result === "green"
      ? "Completed with no actionable findings under the displayed scan policy."
      : `Completed with ${report.finding_counts.actionable} actionable finding${report.finding_counts.actionable === 1 ? "" : "s"} for review.`;
  const resultClass =
    report.result === "green" ? "result-green" : "result-yellow";

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="Content-Security-Policy" content="${escapeHtml(CSP)}">
  <title>TavernKeeper report · ${escapeHtml(report.repository)}</title>
  <style>
    :root { color-scheme: dark; font-family: ui-sans-serif, system-ui, sans-serif; background: #111318; color: #ecedf0; }
    body { max-width: 58rem; margin: 0 auto; padding: 2rem 1rem 4rem; line-height: 1.55; }
    a { color: #91c9ff; } code { overflow-wrap: anywhere; }
    header, section { border: 1px solid #353a44; background: #191c22; padding: 1.25rem; margin-block: 1rem; }
    h1, h2, h3 { line-height: 1.2; } h1 { margin-top: 0; }
    .result { border-left: .4rem solid currentColor; padding: 1rem; }
    .result-green { color: #8ee3a1; } .result-yellow { color: #f6cf65; }
    .result p { color: #ecedf0; margin-bottom: 0; }
    dl { display: grid; grid-template-columns: minmax(9rem, auto) 1fr; gap: .45rem 1rem; }
    dt { color: #aeb4bf; } dd { margin: 0; min-width: 0; overflow-wrap: anywhere; }
    ul { padding-left: 1.2rem; } .exclusions { list-style: none; padding: 0; }
    .exclusions li { display: flex; justify-content: space-between; gap: 1rem; border-top: 1px solid #30343d; padding: .45rem 0; }
    .finding { border-top: 1px solid #3a3f49; padding-top: 1rem; margin-top: 1rem; }
    .finding-meta { color: #bcc2cc; text-transform: capitalize; }
    footer { color: #aeb4bf; margin-top: 2rem; }
  </style>
</head>
<body>
  <header>
    <h1>TavernKeeper Scan Report</h1>
    <p>${link(report.canonical_url, report.repository)}</p>
    <div class="result ${resultClass}">
      <strong>${escapeHtml(report.result.toUpperCase())}</strong>
      <p>${escapeHtml(resultSummary)}</p>
    </div>
    <p>A green result is not a safety certification. It means only that TavernKeeper completed the displayed scan policy at this commit without actionable findings.</p>
  </header>

  <section>
    <h2>Identity</h2>
    <dl>
      <dt>Commit</dt><dd>${link(commitUrl, report.target_sha)}</dd>
      <dt>Completed</dt><dd>${escapeHtml(report.completed_at)}</dd>
      <dt>Mode</dt><dd>${escapeHtml(report.mode)}</dd>
      <dt>Scanner</dt><dd>${escapeHtml(report.scanner_version)}</dd>
      <dt>Scanner policy</dt><dd>${escapeHtml(report.scanner_policy_version)}</dd>
      <dt>Prompt policy</dt><dd>${escapeHtml(report.prompt_policy_version)}</dd>
      <dt>Report</dt><dd><code>${escapeHtml(report.report_id)}</code></dd>
    </dl>
  </section>

  <section>
    <h2>Coverage</h2>
    <dl>
      <dt>History</dt><dd>${escapeHtml(report.history.commits)} commit${report.history.commits === 1 ? "" : "s"}</dd>
      <dt>Inventory</dt><dd>${escapeHtml(report.coverage.inventory.files)} files · ${escapeHtml(report.coverage.inventory.bytes)} bytes</dd>
      <dt>Model corpus</dt><dd>${escapeHtml(report.coverage.inventory.eligible_text_files)} files · ${escapeHtml(report.coverage.inventory.eligible_text_bytes)} bytes</dd>
      <dt>Model</dt><dd>${escapeHtml(report.coverage.model.provider)} / ${escapeHtml(report.coverage.model.model)}</dd>
      <dt>Model chunks</dt><dd>${escapeHtml(report.coverage.model.completed_chunks)} of ${escapeHtml(report.coverage.model.input_chunks)} completed</dd>
      <dt>Model usage</dt><dd>${escapeHtml(report.coverage.model.input_tokens)} input · ${escapeHtml(report.coverage.model.cache_read_tokens)} cache read · ${escapeHtml(report.coverage.model.reasoning_tokens)} reasoning · ${escapeHtml(report.coverage.model.output_tokens)} output tokens</dd>
    </dl>
    <h3>Tools</h3>
    <ul>${report.coverage.tools.map((tool) => `<li>${escapeHtml(tool.name)} ${escapeHtml(tool.version)} — ${escapeHtml(tool.status)}</li>`).join("")}</ul>
    <h3>Excluded inventory</h3>
    <ul class="exclusions">${renderExclusions(report)}</ul>
  </section>

  <section>
    <h2>Sanitized findings</h2>
    ${renderFindings(report)}
  </section>

  <footer>
    <p>${link(TAVERNARY_URL, "Return to Tavernary")}</p>
  </footer>
</body>
</html>
`;
}
