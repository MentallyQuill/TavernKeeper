import type { ScanReportV4 } from "../contracts/reports.js";
import { sanitizeReportV4 } from "./sanitize.js";

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
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" })[
        character
      ]!,
  );
}

function link(url: string, label: string) {
  return `<a href="${escapeHtml(url)}" rel="noopener noreferrer">${escapeHtml(label)}</a>`;
}

function location(value: {
  path: string;
  line_start: number | null;
  line_end: number | null;
}) {
  return value.line_start === null
    ? value.path
    : `${value.path}:${value.line_start}${
        value.line_end !== null && value.line_end !== value.line_start
          ? `-${value.line_end}`
          : ""
      }`;
}

function renderFindings(report: ScanReportV4) {
  if (report.findings.length === 0)
    return "<p>No deterministic findings were published for this commit.</p>";
  return report.findings
    .map(
      (
        finding,
      ) => `<article class="finding finding-${escapeHtml(finding.policy_status)}">
        <h3>${escapeHtml(finding.title)}</h3>
        <p><strong>${escapeHtml(finding.policy_status)}</strong> &middot; ${escapeHtml(finding.severity)} severity &middot; ${escapeHtml(finding.confidence)} confidence &middot; ${escapeHtml(finding.category)}</p>
        <p>${escapeHtml(finding.explanation)}</p>
        ${finding.remediation === undefined ? "" : `<p><strong>Recommended review:</strong> ${escapeHtml(finding.remediation)}</p>`}
        <dl>
          <dt>Scanner</dt><dd>${escapeHtml(finding.origin)}</dd>
          <dt>Rule</dt><dd>${escapeHtml(finding.rule_id)}</dd>
          <dt>Location</dt><dd><code>${escapeHtml(location(finding))}</code></dd>
        </dl>
        ${finding.reference_url === undefined ? "" : `<p>${link(finding.reference_url, "View TavernKeeper rule documentation")}</p>`}
      </article>`,
    )
    .join("\n");
}

function renderExclusions(report: ScanReportV4) {
  return Object.entries(report.coverage.inventory.excluded)
    .map(
      ([category, totals]) =>
        `<li><span>${escapeHtml(category.replaceAll("_", " "))}</span><strong>${escapeHtml(totals.files)} files &middot; ${escapeHtml(totals.bytes)} bytes</strong></li>`,
    )
    .join("\n");
}

export function renderReportHtml(input: unknown) {
  const report = sanitizeReportV4(input);
  const commitUrl = `${report.canonical_url}/commit/${report.target_sha}`;
  const resultClass = report.result === "teal" ? "result-teal" : "result-red";

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="Content-Security-Policy" content="${escapeHtml(CSP)}">
  <title>TavernKeeper report &middot; ${escapeHtml(report.repository)}</title>
  <style>
    :root { color-scheme: dark; font-family: ui-sans-serif, system-ui, sans-serif; background: #111318; color: #ecedf0; }
    body { max-width: 58rem; margin: 0 auto; padding: 2rem 1rem 4rem; line-height: 1.55; }
    a { color: #91c9ff; } code { overflow-wrap: anywhere; }
    header, section { border: 1px solid #353a44; background: #191c22; padding: 1.25rem; margin-block: 1rem; }
    h1, h2, h3 { line-height: 1.2; } h1 { margin-top: 0; }
    .result { border-left: .4rem solid currentColor; padding: 1rem; }
    .result-teal { color: #56d8c9; } .result-red { color: #ff6b63; }
    .result p { color: #ecedf0; }
    dl { display: grid; grid-template-columns: minmax(9rem, auto) 1fr; gap: .45rem 1rem; }
    dt { color: #aeb4bf; } dd { margin: 0; min-width: 0; overflow-wrap: anywhere; }
    ul { padding-left: 1.2rem; } .exclusions { list-style: none; padding: 0; }
    .exclusions li { display: flex; justify-content: space-between; gap: 1rem; border-top: 1px solid #30343d; padding: .45rem 0; }
    .finding { border-top: 1px solid #3a3f49; padding-top: 1rem; margin-top: 1rem; }
    .finding-reportable { border-left: .25rem solid #ff6b63; padding-left: 1rem; }
    .finding-informational { border-left: .25rem solid #56d8c9; padding-left: 1rem; }
    footer { color: #aeb4bf; margin-top: 2rem; }
  </style>
</head>
<body>
  <header>
    <h1>TavernKeeper Scan Report</h1>
    <p>${link(report.canonical_url, report.repository)}</p>
    <dl>
      <dt>Commit</dt><dd>${link(commitUrl, report.target_sha)}</dd>
      <dt>Assessment method</dt><dd>${escapeHtml(report.assessment_method)}</dd>
      <dt>Completed</dt><dd>${escapeHtml(report.completed_at)}</dd>
      <dt>Scanner</dt><dd>${escapeHtml(report.scanner_version)}</dd>
      <dt>Scanner policy</dt><dd>${escapeHtml(report.scanner_policy_version)}</dd>
      <dt>Rule catalog</dt><dd>${escapeHtml(report.rule_catalog_version)}</dd>
      <dt>Scan Package schema</dt><dd>${escapeHtml(report.package_schema_version)}</dd>
      <dt>Report</dt><dd><code>${escapeHtml(report.report_id)}</code></dd>
    </dl>
    <p>This result is advisory and is not a safety certification. It reports deterministic scanner findings for this exact commit; absence of a reported concern does not prove that a project is harmless.</p>
  </header>

  <section>
    <h2>${escapeHtml(report.summary.headline)}</h2>
    <div class="result ${resultClass}">
      <strong>${escapeHtml(report.result.toUpperCase())}</strong>
      <p>${escapeHtml(report.summary.detail)}</p>
      <p>${escapeHtml(report.finding_counts.reportable)} reportable &middot; ${escapeHtml(report.finding_counts.informational)} informational</p>
    </div>
  </section>

  <section>
    <h2>Deterministic findings</h2>
    ${renderFindings(report)}
  </section>

  <section>
    <h2>Coverage and exclusions</h2>
    <dl>
      <dt>History</dt><dd>${escapeHtml(report.history.commits)} commit${report.history.commits === 1 ? "" : "s"}</dd>
      <dt>Inventory</dt><dd>${escapeHtml(report.coverage.inventory.files)} files &middot; ${escapeHtml(report.coverage.inventory.bytes)} bytes</dd>
      <dt>First-party text</dt><dd>${escapeHtml(report.coverage.inventory.first_party_text_files)} files &middot; ${escapeHtml(report.coverage.inventory.first_party_text_bytes)} bytes</dd>
      <dt>Evidence validation</dt><dd>${escapeHtml(report.coverage.evidence_validation.validated_findings)} findings validated</dd>
    </dl>
    <h3>Complete tool coverage</h3>
    <ul>${report.coverage.tools.map((tool) => `<li>${escapeHtml(tool.name)} ${escapeHtml(tool.version)} &mdash; ${escapeHtml(tool.status)}</li>`).join("")}</ul>
    <h3>Excluded inventory</h3>
    <ul class="exclusions">${renderExclusions(report)}</ul>
  </section>

  <footer><p>${link(TAVERNARY_URL, "Return to Tavernary")}</p></footer>
</body>
</html>
`;
}
