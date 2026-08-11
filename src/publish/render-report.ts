import type { ScanReportV5 } from "../contracts/reports-v5.js";
import {
  dangerBasisLabel,
  deriveProjectAdvisory,
  escapeHtml,
  FAVICON_LINKS,
  formatPublicDate,
  projectAdvisorySummary,
  renderSiteHeader,
  shortSha,
  SCRIPT_FREE_CSP,
  SITE_ROOT,
  SITE_STYLES,
  TAVERNARY_URL,
  type ProjectAdvisory,
} from "../site/presentation.js";
import { sanitizeReportV5 } from "./sanitize.js";

const REPORT_STYLES = `
  .report-page { width: min(calc(100% - 32px), 900px); }
  .report-heading { margin-bottom: 24px; }
  .report-heading .eyebrow { margin-bottom: 8px; }
  .report-heading h1 { margin: 0; font-size: clamp(2rem, 5vw, 2.8rem); }
  .report-heading h1 a { color: var(--text); text-decoration: none; }
  .report-heading h1 a:hover { color: var(--link-hover); }
  .report-identity-line { display: flex; flex-wrap: wrap; gap: 5px 14px; margin-top: 12px; color: var(--text-secondary); }
  .assessment-summary { margin-bottom: 34px; padding: 20px; }
  .assessment-summary h2 { margin-bottom: 8px; font-size: 1.35rem; }
  .assessment-summary p { margin: 8px 0 0; }
  .risk-counts { display: flex; flex-wrap: wrap; gap: 6px 14px; color: var(--text-secondary); font-size: 13px; }
  .report-section { padding-block: 28px; border-top: 1px solid var(--border); }
  .report-section > p:first-of-type { color: var(--text-secondary); }
  .finding { margin-top: 14px; border: 1px solid var(--border); border-left: 4px solid var(--risk); border-radius: var(--radius); padding: 18px; background: var(--surface); }
  .finding h3 { margin: 0 0 8px; font-size: 1.08rem; }
  .finding p { color: var(--text-secondary); }
  .finding .label { color: var(--text); }
  .finding details { margin-top: 14px; border-top: 1px solid var(--border); padding-top: 12px; }
  .expected { margin-top: 16px; border: 1px solid var(--border); border-radius: var(--radius); padding: 14px 16px; background: var(--surface); }
  .expected > p { color: var(--text-secondary); }
  .technical-evidence-list { margin: 14px 0 0; padding-left: 22px; }
  .technical-evidence-list li + li { margin-top: 12px; }
  .technical-evidence-list p { margin: 3px 0; color: var(--text-secondary); }
  .coverage-summary { margin-bottom: 22px; }
  .tools,
  .limitations { color: var(--text-secondary); }
  .technical-identity { margin-top: 28px; padding: 16px 18px; }
  .technical-identity[open] > summary { margin-bottom: 18px; }
  .technical-identity .metadata { margin: 0; }
  .report-footer { display: flex; flex-wrap: wrap; gap: 8px 18px; margin-top: 30px; border-top: 1px solid var(--border); padding-top: 24px; color: var(--muted); }
`;

function link(url: string, label: string) {
  return `<a href="${escapeHtml(url)}" rel="noopener noreferrer">${escapeHtml(label)}</a>`;
}

function reviewReuseMetadata(report: ScanReportV5) {
  const reuse = report.review_reuse;
  if (reuse === undefined) return "";
  const sources =
    reuse.source_report_ids.length === 0
      ? "none"
      : reuse.source_report_ids
          .map((reportId) => `<code>${escapeHtml(reportId)}</code>`)
          .join(" &middot; ");
  return `<dt>Review provenance</dt><dd>${escapeHtml(reuse.groups.fresh)} fresh / ${escapeHtml(reuse.groups.reused)} reused groups &middot; ${escapeHtml(reuse.candidates.fresh)} fresh / ${escapeHtml(reuse.candidates.reused)} reused candidates</dd>
        <dt>Review source reports</dt><dd>${sources}</dd>`;
}

function reviewBatchMetadata(report: ScanReportV5) {
  const batches = report.review_batches;
  if (batches === undefined) return "";
  if (batches.length === 0)
    return "<dt>Review batching</dt><dd>0 model calls &middot; all eligible groups reused</dd>";
  const retryCalls = batches.filter(({ attempt }) => attempt > 1).length;
  const oversizedCalls = batches.filter(
    ({ over_budget }) => over_budget,
  ).length;
  const maximumGroups = Math.max(
    0,
    ...batches.map(({ group_count }) => group_count),
  );
  const maximumCandidates = Math.max(
    0,
    ...batches.map(({ candidate_count }) => candidate_count),
  );
  return `<dt>Review batching</dt><dd>${escapeHtml(batches.length)} model call${batches.length === 1 ? "" : "s"} &middot; up to ${escapeHtml(maximumGroups)} groups and ${escapeHtml(maximumCandidates)} candidates per call &middot; ${escapeHtml(retryCalls)} retry call${retryCalls === 1 ? "" : "s"} &middot; ${escapeHtml(oversizedCalls)} over-budget singleton call${oversizedCalls === 1 ? "" : "s"}</dd>`;
}

function reviewTriageMetadata(report: ScanReportV5) {
  const triage = report.review_triage;
  if (triage === undefined) return "";
  const actual = triage.model_budget.actual;
  const configured = triage.model_budget.configured;
  return `<dt>Evidence triage</dt><dd>${escapeHtml(triage.candidates.deterministic)} deterministic / ${escapeHtml(triage.candidates.contextual)} contextual candidates &middot; ${escapeHtml(triage.cases.contextual)} contextual / ${escapeHtml(triage.cases.total)} total behavior cases</dd>
        <dt>Model budget</dt><dd>${escapeHtml(actual.provider_calls)} model call${actual.provider_calls === 1 ? "" : "s"} &middot; ${escapeHtml(actual.fresh_behavior_cases)} / ${escapeHtml(configured.max_fresh_behavior_cases)} fresh cases &middot; ${escapeHtml(actual.estimated_input_tokens)} / ${escapeHtml(configured.max_estimated_input_tokens)} estimated input &middot; ${escapeHtml(actual.input_tokens)} / ${escapeHtml(configured.max_actual_input_tokens)} actual input &middot; ${escapeHtml(actual.output_tokens)} / ${escapeHtml(configured.max_actual_output_tokens)} output tokens</dd>`;
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

function assessmentAdvisoryItem(
  candidate: ScanReportV5["candidates"][number],
  assessment: ScanReportV5["assessments"][number],
) {
  return {
    ...assessment,
    file_role: candidate.file_role,
    origin: candidate.origin,
    rule_id: candidate.rule_id,
    category: candidate.category,
    title: candidate.title,
    explanation: candidate.explanation,
  };
}

function observationAdvisoryItem(
  report: ScanReportV5,
  observation: ScanReportV5["observations"][number],
) {
  const candidatesById = new Map(
    report.candidates.map((candidate) => [candidate.candidate_id, candidate]),
  );
  const candidates = observation.related_candidate_ids
    .map((candidateId) => candidatesById.get(candidateId))
    .filter((candidate) => candidate !== undefined);
  const completeRelatedSet =
    candidates.length === observation.related_candidate_ids.length;
  const shippedRelatedSet =
    completeRelatedSet &&
    candidates.every(({ file_role }) =>
      ["production", "generated", "vendored"].includes(file_role),
    );
  return {
    ...observation,
    file_role: shippedRelatedSet
      ? ("production" as const)
      : ("unknown" as const),
    origin: candidates.some(({ origin }) => origin === "osv-scanner")
      ? "osv-scanner"
      : candidates.map(({ origin }) => origin).join(" "),
    rule_id: candidates.map(({ rule_id }) => rule_id).join(" "),
    category: candidates.map(({ category }) => category).join(" "),
    title: [observation.title, ...candidates.map(({ title }) => title)].join(
      " ",
    ),
    explanation: candidates.map(({ explanation }) => explanation).join(" "),
  };
}

export function deriveReportAdvisory(report: ScanReportV5): ProjectAdvisory {
  const assessmentByCandidate = new Map(
    report.assessments.map((assessment) => [
      assessment.candidate_id,
      assessment,
    ]),
  );
  return deriveProjectAdvisory([
    ...report.candidates.map((candidate) =>
      assessmentAdvisoryItem(
        candidate,
        assessmentByCandidate.get(candidate.candidate_id)!,
      ),
    ),
    ...report.observations.map((observation) =>
      observationAdvisoryItem(report, observation),
    ),
  ]);
}

function contextualFinding(
  report: ScanReportV5,
  candidate: ScanReportV5["candidates"][number],
  assessment: ScanReportV5["assessments"][number],
) {
  const advisory = deriveProjectAdvisory([
    assessmentAdvisoryItem(candidate, assessment),
  ]);
  const risk = advisory.risk;
  const label =
    risk === "high"
      ? `Immediate danger — ${dangerBasisLabel(advisory.dangerBasis)}`
      : risk === "material"
        ? "Material concern"
        : assessment.disposition === "expected_behavior"
          ? "Expected behavior"
          : "Minor caution";
  return `<article class="finding risk-${escapeHtml(risk)}">
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

function deterministicTechnicalEvidence(
  report: ScanReportV5,
  item: {
    candidate: ScanReportV5["candidates"][number];
    assessment: ScanReportV5["assessments"][number];
  },
) {
  const { candidate, assessment } = item;
  const reason =
    "triage_reason_code" in assessment
      ? assessment.triage_reason_code
      : "historical-policy";
  return `<li>
    <p><strong>${escapeHtml(candidate.title)}</strong> &middot; ${escapeHtml(candidate.origin)} ${escapeHtml(candidate.scanner_version)}</p>
    <p>${escapeHtml(assessment.layman_explanation)}</p>
    <p><strong>Policy reason:</strong> <code>${escapeHtml(reason)}</code> &middot; <strong>Execution scope:</strong> ${escapeHtml(candidate.execution_scope ?? "not recorded")}</p>
    <p><strong>Source:</strong> ${link(githubLocation(report, candidate), location(candidate))}</p>
  </li>`;
}

function contextualObservation(
  report: ScanReportV5,
  observation: ScanReportV5["observations"][number],
) {
  const advisory = deriveProjectAdvisory([
    observationAdvisoryItem(report, observation),
  ]);
  const risk = advisory.risk;
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
  return `<article class="finding risk-${escapeHtml(risk)}">
    <h3>${escapeHtml(observation.title)}</h3>
    <p><strong>${escapeHtml(risk === "high" ? `Immediate danger — ${dangerBasisLabel(advisory.dangerBasis)}` : `${risk} risk`)}</strong> &middot; ${escapeHtml(observation.confidence)} confidence</p>
    <p>${escapeHtml(observation.layman_explanation)}</p>
    <details><summary>Technical assessment</summary>
      <p>${escapeHtml(observation.technical_explanation)}</p>
      <p><strong>Impact:</strong> ${escapeHtml(observation.impact)} &middot; <strong>Exploitability:</strong> ${escapeHtml(observation.exploitability)}</p>
      <p><strong>Developer action:</strong> ${escapeHtml(observation.developer_action)}</p>
      <p><strong>Sources:</strong></p><ul>${sources}</ul>
    </details>
  </article>`;
}

function javascriptCoverage(report: ScanReportV5) {
  const coverage = report.coverage.javascript_analysis;
  if (coverage === undefined) return "";
  const unresolved =
    coverage.unresolved.length === 0
      ? ""
      : `<h4>Unresolved JavaScript stages</h4><ul class="limitations">${coverage.unresolved
          .map(
            (item) =>
              `<li><code>${escapeHtml(item.path)}</code> &mdash; ${escapeHtml(item.stage)} / ${escapeHtml(item.reason)}${item.recovered ? " (recovered elsewhere)" : ""}</li>`,
          )
          .join("")}</ul>`;
  const warningFamilies =
    coverage.warning_occurrences === undefined ||
    coverage.warning_families === undefined
      ? ""
      : `<dt>X-Ray review families</dt><dd>${escapeHtml(coverage.warning_occurrences)} warning occurrences compacted to ${escapeHtml(coverage.warning_families)} evidence-preserving review families</dd>`;
  return `<h3>JavaScript coverage</h3>
      <dl class="metadata coverage-summary">
        <dt>Status</dt><dd>${escapeHtml(coverage.status === "complete" ? "Complete" : "Incomplete")}</dd>
        <dt>Candidates</dt><dd>${escapeHtml(coverage.candidates)} files &middot; ${escapeHtml(coverage.candidate_bytes)} bytes</dd>
        ${warningFamilies}
        <dt>Representations</dt><dd>${escapeHtml(coverage.representations.raw)} raw &middot; ${escapeHtml(coverage.representations.decoded)} decoded &middot; ${escapeHtml(coverage.representations.normalized)} normalized &middot; ${escapeHtml(coverage.representations.bundle_modules)} bundle modules</dd>
        <dt>Stage scans</dt><dd>${escapeHtml(coverage.stages.raw_signatures)} raw signatures &middot; ${escapeHtml(coverage.stages.raw_ast)} raw AST &middot; ${escapeHtml(coverage.stages.raw_opengrep)} raw OpenGrep &middot; ${escapeHtml(coverage.stages.derived_signatures)} derived signatures &middot; ${escapeHtml(coverage.stages.derived_ast)} derived AST &middot; ${escapeHtml(coverage.stages.derived_opengrep)} derived OpenGrep</dd>
      </dl>
      ${unresolved}`;
}

export function renderReportV5Html(input: unknown) {
  const report = sanitizeReportV5(input);
  const commitUrl = `${report.canonical_url}/commit/${report.target_sha}`;
  const historyUrl = `${SITE_ROOT}reports/github/${report.repository_id}/history/`;
  const assessmentByCandidate = new Map(
    report.assessments.map((assessment) => [
      assessment.candidate_id,
      assessment,
    ]),
  );
  const advisory = deriveReportAdvisory(report);
  const risk = advisory.risk;
  const summary = projectAdvisorySummary(advisory);
  const rendered = report.candidates.map((candidate) => ({
    candidate,
    assessment: assessmentByCandidate.get(candidate.candidate_id)!,
  }));
  const policy5 = report.contextual_review_policy_version === "5";
  const individualRisk = ({
    candidate,
    assessment,
  }: (typeof rendered)[number]) =>
    deriveProjectAdvisory([assessmentAdvisoryItem(candidate, assessment)]).risk;
  const deterministicTechnical = policy5
    ? rendered.filter(
        ({ assessment, ...item }) =>
          "assessment_source" in assessment &&
          assessment.assessment_source === "deterministic-policy" &&
          assessment.disposition !== "minor_weakness" &&
          individualRisk({ ...item, assessment }) === "low",
      )
    : [];
  const concerning = rendered.filter(
    ({ candidate, assessment }) =>
      deriveProjectAdvisory([assessmentAdvisoryItem(candidate, assessment)])
        .risk !== "low",
  );
  const concerningObservations = report.observations.filter(
    (observation) =>
      deriveProjectAdvisory([observationAdvisoryItem(report, observation)])
        .risk !== "low",
  );
  const relatedObservations = report.observations.filter(
    (observation) =>
      deriveProjectAdvisory([observationAdvisoryItem(report, observation)])
        .risk === "low",
  );
  const cautions = rendered.filter(
    ({ candidate, assessment }) =>
      assessment.disposition !== "expected_behavior" &&
      deriveProjectAdvisory([assessmentAdvisoryItem(candidate, assessment)])
        .risk === "low" &&
      (!policy5 ||
        !("assessment_source" in assessment) ||
        assessment.assessment_source !== "deterministic-policy" ||
        assessment.disposition === "minor_weakness"),
  );
  const expected = rendered.filter(
    ({ assessment }) =>
      assessment.disposition === "expected_behavior" &&
      (!policy5 ||
        !("assessment_source" in assessment) ||
        assessment.assessment_source === "contextual-model"),
  );
  const reviewItems = (items: typeof rendered) =>
    [...items]
      .sort((left, right) => {
        const order = { high: 0, material: 1, low: 2 };
        return (
          order[
            deriveProjectAdvisory([
              assessmentAdvisoryItem(left.candidate, left.assessment),
            ]).risk
          ] -
            order[
              deriveProjectAdvisory([
                assessmentAdvisoryItem(right.candidate, right.assessment),
              ]).risk
            ] ||
          left.candidate.candidate_id.localeCompare(
            right.candidate.candidate_id,
          )
        );
      })
      .map(({ candidate, assessment }) =>
        contextualFinding(report, candidate, assessment),
      )
      .join("\n");
  const primaryFindings = [
    ...concerning.map((item) => ({
      id: item.candidate.candidate_id,
      risk: deriveProjectAdvisory([
        assessmentAdvisoryItem(item.candidate, item.assessment),
      ]).risk,
      html: contextualFinding(report, item.candidate, item.assessment),
    })),
    ...concerningObservations.map((observation) => ({
      id: observation.observation_id,
      risk: deriveProjectAdvisory([
        observationAdvisoryItem(report, observation),
      ]).risk,
      html: contextualObservation(report, observation),
    })),
  ]
    .sort((left, right) => {
      const order = { high: 0, material: 1, low: 2 };
      return (
        order[left.risk] - order[right.risk] || left.id.localeCompare(right.id)
      );
    })
    .map((item) => item.html)
    .join("\n");

  return `<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="description" content="Advisory TavernKeeper scan report for ${escapeHtml(report.repository)} at commit ${escapeHtml(shortSha(report.target_sha))}.">
  <meta http-equiv="Content-Security-Policy" content="${escapeHtml(SCRIPT_FREE_CSP)}">
  ${FAVICON_LINKS}
  <title>TavernKeeper scan report &middot; ${escapeHtml(report.repository)}</title>
  <style>${SITE_STYLES}${REPORT_STYLES}</style>
</head>
<body>
  ${renderSiteHeader()}
  <main class="page-shell report-page">
    <header class="report-heading">
      <p class="eyebrow">TavernKeeper Scan Report</p>
      <h1>${link(report.canonical_url, report.repository)}</h1>
      <p class="report-identity-line">
        <span>Commit ${link(commitUrl, shortSha(report.target_sha))}</span>
        <span>Reviewed <time datetime="${escapeHtml(report.completed_at)}">${escapeHtml(formatPublicDate(report.completed_at))}</time></span>
      </p>
    </header>

    <section class="assessment-summary surface risk-mark risk-${risk}" aria-labelledby="assessment-summary-title">
      <h2 id="assessment-summary-title">${escapeHtml(summary)}</h2>
      <p>This advisory report describes what the named tools and review process found at one exact commit. Unknown or unobserved behavior may still exist.</p>
      <p class="risk-counts">
        <span>${escapeHtml(advisory.counts.high)} immediate danger</span>
        <span>${escapeHtml(advisory.counts.material)} material</span>
        <span>${escapeHtml(advisory.counts.low)} low</span>
      </p>
    </section>

    <section class="report-section" aria-labelledby="assessment-title">
      <h2 id="assessment-title">What this review found</h2>
      ${primaryFindings.length === 0 ? "<p>No material or immediate-danger item was identified.</p>" : primaryFindings}
    ${cautions.length === 0 ? "" : `<h3>Minor cautions</h3>${reviewItems(cautions)}`}
    ${
      deterministicTechnical.length === 0
        ? ""
        : `<details class="expected">
      <summary>Deterministic technical evidence (${escapeHtml(deterministicTechnical.length)})</summary>
      <ul class="technical-evidence-list">${deterministicTechnical.map((item) => deterministicTechnicalEvidence(report, item)).join("\n")}</ul>
    </details>`
    }
    ${
      policy5 && expected.length === 0
        ? ""
        : `<details class="expected">
      <summary>${policy5 ? "Contextual expected matches" : "Expected scanner matches"} (${escapeHtml(expected.length)})</summary>
      ${expected.length === 0 ? "<p>None.</p>" : reviewItems(expected)}
    </details>`
    }
    </section>

    ${relatedObservations.length === 0 ? "" : `<section class="report-section"><h2>Related contextual observations</h2>${relatedObservations.map((observation) => contextualObservation(report, observation)).join("\n")}</section>`}

    <section class="report-section" aria-labelledby="coverage-title">
      <h2 id="coverage-title">Coverage and limitations</h2>
      <dl class="metadata coverage-summary">
      <dt>Inventory</dt><dd>${escapeHtml(report.coverage.inventory.files)} files &middot; ${escapeHtml(report.coverage.inventory.bytes)} bytes</dd>
      <dt>Contextual coverage</dt><dd>${escapeHtml(report.review_coverage.completed)} of ${escapeHtml(report.review_coverage.required)} candidates assessed</dd>
      </dl>
      ${javascriptCoverage(report)}
      <h3>Tools</h3>
      <ul class="tools">${report.coverage.tools.map((tool) => `<li>${escapeHtml(tool.name)} ${escapeHtml(tool.version)} &mdash; ${escapeHtml(tool.status)}</li>`).join("")}</ul>
      <h3>Limitations</h3>
      <ul class="limitations">${report.limitations.map((item) => `<li>${escapeHtml(item)}</li>`).join("")}</ul>
    </section>

    <details class="technical-identity surface">
      <summary>Technical scan identity</summary>
      <dl class="metadata">
        <dt>Full commit</dt><dd>${link(commitUrl, report.target_sha)}</dd>
        <dt>Completed</dt><dd><time datetime="${escapeHtml(report.completed_at)}">${escapeHtml(formatPublicDate(report.completed_at))}</time></dd>
        <dt>History depth</dt><dd>${escapeHtml(report.history.commits)} commit${report.history.commits === 1 ? "" : "s"}</dd>
        <dt>Method</dt><dd>Deterministic evidence with contextual review</dd>
        <dt>Reviewer</dt><dd>${report.contextual_reviewer === undefined ? "Not used &mdash; deterministic policy" : `${escapeHtml(report.contextual_reviewer.provider)} &middot; ${escapeHtml(report.contextual_reviewer.model)}`}</dd>
        <dt>Scanner</dt><dd>${escapeHtml(report.scanner_version)}</dd>
        <dt>Scanner policy</dt><dd>${escapeHtml(report.scanner_policy_version)}</dd>
        <dt>Rule catalog</dt><dd>${escapeHtml(report.rule_catalog_version)}</dd>
        <dt>Contextual policy</dt><dd>${escapeHtml(report.contextual_review_policy_version)}</dd>
        <dt>Ecosystem context</dt><dd>${escapeHtml(report.ecosystem_context_version)}</dd>
        <dt>Prompt</dt><dd>${escapeHtml(report.prompt_version)}</dd>
        <dt>Assessment schema</dt><dd>${escapeHtml(report.assessment_schema_version)}</dd>
        ${reviewReuseMetadata(report)}
        ${reviewTriageMetadata(report)}
        ${reviewBatchMetadata(report)}
        <dt>Review usage</dt><dd>${escapeHtml(report.review_usage.input_tokens)} input &middot; ${escapeHtml(report.review_usage.output_tokens)} output &middot; ${escapeHtml(report.review_usage.cache_read_tokens)} cache read &middot; ${escapeHtml(report.review_usage.reasoning_tokens)} reasoning tokens</dd>
        <dt>Report</dt><dd><code>${escapeHtml(report.report_id)}</code></dd>
      </dl>
    </details>

    <footer class="report-footer">
      ${link(historyUrl, "View scan history")}
      ${link(SITE_ROOT, "Browse reports")}
      ${link(TAVERNARY_URL, "Return to Tavernary")}
    </footer>
  </main>
</body>
</html>
`;
}
