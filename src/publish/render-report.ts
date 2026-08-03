import type { ScanReportV5 } from "../contracts/reports-v5.js";
import { sanitizeReportV5 } from "./sanitize.js";

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

function githubLocation(
  report: ScanReportV5,
  source: {
    path: string;
    line_start: number | null;
    line_end: number | null;
    evidence_sha: string;
  },
) {
  const path = source.path
    .split("/")
    .map((segment) => encodeURIComponent(segment))
    .join("/");
  const lines =
    source.line_start === null
      ? ""
      : `#L${source.line_start}${
          source.line_end !== null && source.line_end !== source.line_start
            ? `-L${source.line_end}`
            : ""
        }`;
  return `${report.canonical_url}/blob/${source.evidence_sha}/${path}${lines}`;
}

function contextualFinding(
  report: ScanReportV5,
  candidate: ScanReportV5["candidates"][number],
  assessment: ScanReportV5["assessments"][number],
) {
  const label =
    assessment.recommended_risk === "high"
      ? "High danger"
      : assessment.recommended_risk === "material"
        ? "Material concern"
        : assessment.disposition === "minor_weakness"
          ? "Minor caution"
          : "Expected behavior";
  return `<article class="finding risk-${escapeHtml(assessment.recommended_risk)}">
    <h3>${escapeHtml(candidate.title)}</h3>
    <p class="label"><strong>${escapeHtml(label)}</strong> &middot; ${escapeHtml(assessment.confidence)} confidence</p>
    <p>${escapeHtml(assessment.layman_explanation)}</p>
    <details>
      <summary>Technical evidence</summary>
      <p><strong>Scanner reason:</strong> ${escapeHtml(candidate.explanation)}</p>
      <p><strong>Contextual assessment:</strong> ${escapeHtml(assessment.technical_explanation)}</p>
      <p><strong>Impact:</strong> ${escapeHtml(assessment.impact)} &middot; <strong>Exploitability:</strong> ${escapeHtml(assessment.exploitability)}</p>
      <p><strong>Developer action:</strong> ${escapeHtml(assessment.developer_action)}</p>
      <dl>
        <dt>Scanner</dt><dd>${escapeHtml(candidate.origin)} ${escapeHtml(candidate.scanner_version)}</dd>
        <dt>Rule</dt><dd>${escapeHtml(candidate.rule_id)}</dd>
        <dt>File role</dt><dd>${escapeHtml(candidate.file_role)}</dd>
        <dt>Source</dt><dd>${link(githubLocation(report, candidate), location(candidate))}</dd>
      </dl>
    </details>
  </article>`;
}

function contextualObservation(
  report: ScanReportV5,
  observation: ScanReportV5["observations"][number],
) {
  const candidatesByEvidence = new Map(
    report.candidates.map((candidate) => [candidate.evidence_id, candidate]),
  );
  const citedCandidates = observation.evidence_ids.map((evidenceId) =>
    candidatesByEvidence.get(evidenceId)!,
  );
  const sources = observation.locations
    .map((source) => {
      const candidate = citedCandidates.find(
        (item) => item.path === source.path,
      )!;
      return `<li>${link(
        githubLocation(report, {
          ...source,
          evidence_sha: candidate.evidence_sha,
        }),
        location(source),
      )}</li>`;
    })
    .join("");
  return `<article class="finding risk-${escapeHtml(observation.recommended_risk)}">
    <h3>${escapeHtml(observation.title)}</h3>
    <p><strong>${escapeHtml(observation.recommended_risk)} risk</strong> &middot; ${escapeHtml(observation.confidence)} confidence</p>
    <p>${escapeHtml(observation.layman_explanation)}</p>
    <details><summary>Technical assessment</summary>
      <p>${escapeHtml(observation.technical_explanation)}</p>
      <p><strong>Impact:</strong> ${escapeHtml(observation.impact)} &middot; <strong>Exploitability:</strong> ${escapeHtml(observation.exploitability)}</p>
      <p><strong>Developer action:</strong> ${escapeHtml(observation.developer_action)}</p>
      <p><strong>Sources:</strong></p><ul>${sources}</ul>
    </details>
  </article>`;
}

export function renderReportV5Html(input: unknown) {
  const report = sanitizeReportV5(input);
  const commitUrl = `${report.canonical_url}/commit/${report.target_sha}`;
  const assessmentByCandidate = new Map(
    report.assessments.map((assessment) => [
      assessment.candidate_id,
      assessment,
    ]),
  );
  const rendered = report.candidates.map((candidate) => ({
    candidate,
    assessment: assessmentByCandidate.get(candidate.candidate_id)!,
  }));
  const concerning = rendered.filter(
    ({ assessment }) => assessment.recommended_risk !== "low",
  );
  const cautions = rendered.filter(
    ({ assessment }) => assessment.disposition === "minor_weakness",
  );
  const expected = rendered.filter(
    ({ assessment }) => assessment.disposition === "expected_behavior",
  );
  const reviewItems = (items: typeof rendered) =>
    [...items]
      .sort((left, right) => {
        const order = { high: 0, material: 1, low: 2 };
        return (
          order[left.assessment.recommended_risk] -
            order[right.assessment.recommended_risk] ||
          left.candidate.candidate_id.localeCompare(
            right.candidate.candidate_id,
          )
        );
      })
      .map(({ candidate, assessment }) =>
        contextualFinding(report, candidate, assessment),
      )
      .join("\n");

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="Content-Security-Policy" content="${escapeHtml(CSP)}">
  <title>TavernKeeper contextual report &middot; ${escapeHtml(report.repository)}</title>
  <style>
    :root { color-scheme: dark; font-family: ui-sans-serif, system-ui, sans-serif; background: #111318; color: #ecedf0; }
    body { max-width: 62rem; margin: 0 auto; padding: 2rem 1rem 4rem; line-height: 1.55; }
    a { color: #91c9ff; } code { overflow-wrap: anywhere; }
    header, section { border: 1px solid #353a44; background: #191c22; padding: 1.25rem; margin-block: 1rem; }
    h1, h2, h3 { line-height: 1.2; } h1 { margin-top: 0; }
    dl { display: grid; grid-template-columns: minmax(9rem, auto) 1fr; gap: .45rem 1rem; }
    dt { color: #aeb4bf; } dd { margin: 0; min-width: 0; overflow-wrap: anywhere; }
    .finding { border-left: .3rem solid #56d8c9; border-top: 1px solid #3a3f49; padding: 1rem; margin-top: 1rem; background: #15181e; }
    .risk-material { border-left-color: #f0a24a; } .risk-high { border-left-color: #ff6b63; }
    .label { color: #cdd2da; } summary { cursor: pointer; font-weight: 650; }
    .expected { margin-top: 1rem; } .limitations { color: #c1c6cf; }
    footer { color: #aeb4bf; margin-top: 2rem; }
  </style>
</head>
<body>
  <header>
    <h1>TavernKeeper Scan Report</h1>
    <p>${link(report.canonical_url, report.repository)}</p>
    <dl>
      <dt>Commit</dt><dd>${link(commitUrl, report.target_sha)}</dd>
      <dt>Completed</dt><dd>${escapeHtml(report.completed_at)}</dd>
      <dt>Method</dt><dd>Deterministic evidence with contextual review</dd>
      <dt>Reviewer</dt><dd>${escapeHtml(report.contextual_reviewer.provider)} &middot; ${escapeHtml(report.contextual_reviewer.model)}</dd>
      <dt>Report</dt><dd><code>${escapeHtml(report.report_id)}</code></dd>
    </dl>
    <p>This advisory report describes what the named tools and contextual reviewer found at one exact commit. Unknown or unobserved behavior may still exist.</p>
  </header>

  <section>
    <h2>Contextual assessments</h2>
    <p>${escapeHtml(report.counts.recommended_risk.high)} high danger &middot; ${escapeHtml(report.counts.recommended_risk.material)} material concern &middot; ${escapeHtml(report.counts.recommended_risk.low)} low concern</p>
    ${concerning.length === 0 ? "<p>No material or high-danger item was identified.</p>" : reviewItems(concerning)}
    ${cautions.length === 0 ? "" : `<h3>Minor cautions</h3>${reviewItems(cautions)}`}
    <details class="expected">
      <summary>Expected scanner matches (${escapeHtml(expected.length)})</summary>
      ${expected.length === 0 ? "<p>None.</p>" : reviewItems(expected)}
    </details>
  </section>

  ${report.observations.length === 0 ? "" : `<section><h2>Related contextual observations</h2>${report.observations.map((observation) => contextualObservation(report, observation)).join("\n")}</section>`}

  <section>
    <h2>Coverage and limitations</h2>
    <dl>
      <dt>History</dt><dd>${escapeHtml(report.history.commits)} commit${report.history.commits === 1 ? "" : "s"}</dd>
      <dt>Inventory</dt><dd>${escapeHtml(report.coverage.inventory.files)} files &middot; ${escapeHtml(report.coverage.inventory.bytes)} bytes</dd>
      <dt>Contextual coverage</dt><dd>${escapeHtml(report.review_coverage.completed)} of ${escapeHtml(report.review_coverage.required)} candidates assessed</dd>
    </dl>
    <h3>Tools</h3>
    <ul>${report.coverage.tools.map((tool) => `<li>${escapeHtml(tool.name)} ${escapeHtml(tool.version)} &mdash; ${escapeHtml(tool.status)}</li>`).join("")}</ul>
    <h3>Limitations</h3>
    <ul class="limitations">${report.limitations.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>
  </section>

  <footer><p>${link(TAVERNARY_URL, "Return to Tavernary")}</p></footer>
</body>
</html>
`;
}
