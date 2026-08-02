import type { ScanReportV3 } from "../contracts/reports.js";
import { sanitizeReportV3 } from "./sanitize.js";

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

function renderToolResults(report: ScanReportV3) {
  return report.tool_results
    .map(
      (tool) => `<article class="tool-result">
        <h3>${escapeHtml(tool.name)} ${escapeHtml(tool.version)}</h3>
        <p><strong>Status:</strong> ${escapeHtml(tool.status)}</p>
        ${
          tool.signals.length === 0
            ? `<p>${tool.status === "not-applicable" ? "This tool was not applicable to the scanned inventory." : "No factual signals were reported by this tool."}</p>`
            : tool.signals
                .map(
                  (signal) => `<div class="signal">
            <h4>${escapeHtml(signal.title)}</h4>
            <p>${escapeHtml(signal.severity)} severity &middot; ${escapeHtml(signal.confidence)} confidence &middot; ${escapeHtml(signal.category)}</p>
            <p><strong>Rule:</strong> ${escapeHtml(signal.rule_id)}</p>
            <p><strong>Location:</strong> <code>${escapeHtml(location(signal))}</code></p>
          </div>`,
                )
                .join("\n")
        }
      </article>`,
    )
    .join("\n");
}

function renderModelConcerns(report: ScanReportV3) {
  if (report.model_review.concerns.length === 0)
    return "<p>No additional model concerns were reported.</p>";
  return report.model_review.concerns
    .map(
      (concern) => `<article class="concern">
        <h3>${escapeHtml(concern.title)}</h3>
        <p>${escapeHtml(concern.severity)} severity &middot; ${escapeHtml(concern.confidence)} confidence &middot; ${escapeHtml(concern.category)}</p>
        <p>${escapeHtml(concern.explanation)}</p>
        <p><strong>Evidence:</strong></p>
        <ul>${concern.evidence.map((evidence) => `<li><code>${escapeHtml(location(evidence))}</code> (${escapeHtml(evidence.kind)}, ${escapeHtml(evidence.evidence_id)})</li>`).join("")}</ul>
      </article>`,
    )
    .join("\n");
}

function renderExclusions(report: ScanReportV3) {
  return Object.entries(report.coverage.inventory.excluded)
    .map(
      ([category, totals]) =>
        `<li><span>${escapeHtml(category.replaceAll("_", " "))}</span><strong>${escapeHtml(totals.files)} files &middot; ${escapeHtml(totals.bytes)} bytes</strong></li>`,
    )
    .join("\n");
}

export function renderReportHtml(input: unknown) {
  const report = sanitizeReportV3(input);
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
    h1, h2, h3, h4 { line-height: 1.2; } h1 { margin-top: 0; }
    .result { border-left: .4rem solid currentColor; padding: 1rem; }
    .result-teal { color: #56d8c9; } .result-red { color: #ff6b63; }
    .result p { color: #ecedf0; }
    dl { display: grid; grid-template-columns: minmax(9rem, auto) 1fr; gap: .45rem 1rem; }
    dt { color: #aeb4bf; } dd { margin: 0; min-width: 0; overflow-wrap: anywhere; }
    ul { padding-left: 1.2rem; } .exclusions { list-style: none; padding: 0; }
    .exclusions li { display: flex; justify-content: space-between; gap: 1rem; border-top: 1px solid #30343d; padding: .45rem 0; }
    .tool-result, .concern, .signal { border-top: 1px solid #3a3f49; padding-top: 1rem; margin-top: 1rem; }
    footer { color: #aeb4bf; margin-top: 2rem; }
  </style>
</head>
<body>
  <header>
    <h1>TavernKeeper Scan Report</h1>
    <p>${link(report.canonical_url, report.repository)}</p>
    <dl>
      <dt>Commit</dt><dd>${link(commitUrl, report.target_sha)}</dd>
      <dt>Mode</dt><dd>${escapeHtml(report.mode)}</dd>
      <dt>Completed</dt><dd>${escapeHtml(report.completed_at)}</dd>
      <dt>Scanner</dt><dd>${escapeHtml(report.scanner_version)}</dd>
      <dt>Scanner policy</dt><dd>${escapeHtml(report.scanner_policy_version)}</dd>
      <dt>Prompt policy</dt><dd>${escapeHtml(report.prompt_policy_version)}</dd>
      <dt>Report</dt><dd><code>${escapeHtml(report.report_id)}</code></dd>
    </dl>
    <p>This result is advisory and is not a safety certification. It reports only what the displayed scan and model-review policies concluded for this exact commit.</p>
  </header>

  <section>
    <h2>Overall assessment and model recap</h2>
    <div class="result ${resultClass}">
      <strong>${escapeHtml(report.result.toUpperCase())}</strong>
      <p>${escapeHtml(report.model_review.recap)}</p>
    </div>
  </section>

  <section>
    <h2>Deterministic tool results</h2>
    ${renderToolResults(report)}
  </section>

  <section>
    <h2>Validated model concerns</h2>
    ${renderModelConcerns(report)}
  </section>

  <section>
    <h2>Coverage, exclusions, and usage</h2>
    <dl>
      <dt>History</dt><dd>${escapeHtml(report.history.commits)} commit${report.history.commits === 1 ? "" : "s"}</dd>
      <dt>Inventory</dt><dd>${escapeHtml(report.coverage.inventory.files)} files &middot; ${escapeHtml(report.coverage.inventory.bytes)} bytes</dd>
      <dt>Model corpus</dt><dd>${escapeHtml(report.coverage.inventory.eligible_text_files)} files &middot; ${escapeHtml(report.coverage.inventory.eligible_text_bytes)} bytes</dd>
      <dt>Model</dt><dd>${escapeHtml(report.coverage.model.provider)} / ${escapeHtml(report.coverage.model.model)}</dd>
      <dt>Model chunks</dt><dd>${escapeHtml(report.coverage.model.completed_chunks)} of ${escapeHtml(report.coverage.model.input_chunks)} completed</dd>
      <dt>Evidence validation</dt><dd>${escapeHtml(report.coverage.evidence_validation.validated_findings)} model concerns validated</dd>
      <dt>Model usage</dt><dd>${escapeHtml(report.coverage.model.input_tokens)} input &middot; ${escapeHtml(report.coverage.model.cache_read_tokens)} cache read &middot; ${escapeHtml(report.coverage.model.reasoning_tokens)} reasoning &middot; ${escapeHtml(report.coverage.model.output_tokens)} output tokens</dd>
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
