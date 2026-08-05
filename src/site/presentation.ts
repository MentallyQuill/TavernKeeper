import type {
  ContextualCountsV5,
  ReportIndexEntryV5,
} from "../contracts/reports-v5.js";
import type {
  ContextualAssessment,
  ContextualObservation,
} from "../model/contextual-review-contract.js";

export type RiskLevel = "low" | "material" | "high";
export type DangerBasis =
  "malicious_or_compromised" | "critical_exploitable_vulnerability" | "mixed";

type AdvisoryItem = Pick<
  ContextualAssessment | ContextualObservation,
  | "disposition"
  | "impact"
  | "exploitability"
  | "confidence"
  | "recommended_risk"
>;

export interface ProjectAdvisory {
  risk: RiskLevel;
  dangerBasis: DangerBasis | null;
  counts: { high: number; material: number; low: number };
}

type RecommendedRiskCounts = ContextualCountsV5["recommended_risk"];

export const SITE_ROOT = "https://mentallyquill.github.io/TavernKeeper/";
export const TAVERNARY_URL = "https://tavernary.org/";

export const FAVICON_LINKS = [
  `<link rel="icon" href="${SITE_ROOT}assets/favicon.svg" type="image/svg+xml">`,
  `<link rel="icon" href="${SITE_ROOT}assets/favicon.ico" sizes="any">`,
  `<link rel="icon" href="${SITE_ROOT}assets/favicon-32.png" type="image/png" sizes="32x32">`,
  `<link rel="icon" href="${SITE_ROOT}assets/favicon-16.png" type="image/png" sizes="16x16">`,
  `<link rel="apple-touch-icon" href="${SITE_ROOT}assets/apple-touch-icon.png" sizes="180x180">`,
  `<link rel="icon" href="${SITE_ROOT}assets/favicon-192.png" type="image/png" sizes="192x192">`,
  `<link rel="icon" href="${SITE_ROOT}assets/favicon-512.png" type="image/png" sizes="512x512">`,
].join("\n  ");

export const SCRIPT_FREE_CSP = [
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

export const SITE_STYLES = `
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
  * { box-sizing: border-box; }
  html { min-width: 320px; background: var(--canvas); color-scheme: dark; }
  body {
    margin: 0;
    background: var(--canvas);
    color: var(--text);
    font-family: Inter, system-ui, sans-serif;
    line-height: 1.55;
  }
  a { color: var(--link); text-underline-offset: 2px; }
  a:hover { color: var(--link-hover); }
  a:focus-visible,
  button:focus-visible,
  input:focus-visible,
  select:focus-visible,
  summary:focus-visible {
    outline: 2px solid var(--focus);
    outline-offset: 2px;
  }
  code { overflow-wrap: anywhere; }
  .site-header { border-bottom: 1px solid var(--border); background: var(--header); }
  .site-header-inner,
  .page-shell { width: min(calc(100% - 32px), 1040px); margin-inline: auto; }
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
  .brand:hover { color: var(--functional); }
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
  .site-nav a { color: var(--text); text-decoration: none; }
  .site-nav a:hover { color: var(--link-hover); }
  .page-shell { padding-block: 42px 64px; }
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
    overflow-wrap: anywhere;
  }
  h1 { font-size: clamp(2rem, 5vw, 3.25rem); letter-spacing: -0.035em; }
  h2 { margin-top: 0; font-size: 1.5rem; }
  .surface {
    border: 1px solid var(--border);
    border-radius: var(--radius);
    background: var(--surface);
    box-shadow: 0 1px 2px rgb(0 0 0 / 24%), 0 4px 12px rgb(0 0 0 / 12%);
  }
  .secondary { color: var(--text-secondary); }
  .risk-low { --risk: var(--link); }
  .risk-material { --risk: var(--warning); }
  .risk-high { --risk: var(--danger); }
  .risk-mark { border-left: 4px solid var(--risk); }
  .metadata {
    display: grid;
    grid-template-columns: minmax(9rem, auto) 1fr;
    gap: 0.45rem 1rem;
  }
  .metadata dt { color: var(--muted); }
  .metadata dd {
    min-width: 0;
    margin: 0;
    overflow-wrap: anywhere;
  }
  details > summary { cursor: pointer; font-weight: 700; }
  @media (max-width: 640px) {
    .site-header-inner {
      align-items: flex-start;
      flex-direction: column;
      gap: 14px;
      padding-block: 14px;
    }
    .site-nav { justify-content: flex-start; }
    .page-shell { padding-top: 28px; }
    .metadata { grid-template-columns: 1fr; gap: 0.15rem; }
    .metadata dd { margin-bottom: 0.65rem; }
  }
  @media (prefers-reduced-motion: no-preference) {
    a,
    button,
    input,
    select {
      transition: border-color 150ms ease, color 150ms ease, background 150ms ease;
    }
  }
`;

export function highestRisk(counts: RecommendedRiskCounts): RiskLevel {
  if (counts.high > 0) return "high";
  if (counts.material > 0) return "material";
  return "low";
}

export function assessmentSummary(counts: RecommendedRiskCounts) {
  if (counts.high > 0)
    return `${counts.high} immediate-danger concern${counts.high === 1 ? "" : "s"} identified.`;
  if (counts.material > 0)
    return `${counts.material} material concern${counts.material === 1 ? "" : "s"} identified.`;
  return "No material or immediate-danger concern was identified in this review.";
}

function immediateDangerBasis(item: AdvisoryItem): DangerBasis | null {
  if (
    item.disposition === "credible_malicious_behavior" &&
    item.confidence === "high"
  )
    return "malicious_or_compromised";
  if (
    item.disposition === "material_vulnerability" &&
    item.impact === "critical" &&
    item.exploitability === "readily_exploitable" &&
    item.confidence === "high"
  )
    return "critical_exploitable_vulnerability";
  return null;
}

export function deriveProjectAdvisory(
  items: readonly AdvisoryItem[],
): ProjectAdvisory {
  let malicious = false;
  let exploitable = false;
  const counts = { high: 0, material: 0, low: 0 };
  for (const item of items) {
    const basis = immediateDangerBasis(item);
    if (basis !== null) {
      counts.high += 1;
      malicious ||= basis === "malicious_or_compromised";
      exploitable ||= basis === "critical_exploitable_vulnerability";
    } else if (
      item.disposition === "material_vulnerability" ||
      item.disposition === "credible_malicious_behavior" ||
      item.recommended_risk !== "low"
    ) {
      counts.material += 1;
    } else {
      counts.low += 1;
    }
  }
  const dangerBasis =
    malicious && exploitable
      ? "mixed"
      : malicious
        ? "malicious_or_compromised"
        : exploitable
          ? "critical_exploitable_vulnerability"
          : null;
  return {
    risk:
      dangerBasis !== null ? "high" : counts.material > 0 ? "material" : "low",
    dangerBasis,
    counts,
  };
}

export function deriveIndexedProjectAdvisory(
  entry: ReportIndexEntryV5,
): ProjectAdvisory {
  const published = entry.counts.recommended_risk;
  if (entry.contextual_review_policy_version !== "2")
    return {
      risk: published.high + published.material > 0 ? "material" : "low",
      dangerBasis: null,
      counts: {
        high: 0,
        material: published.high + published.material,
        low: published.low,
      },
    };
  const malicious = entry.counts.disposition.credible_malicious_behavior;
  const dangerBasis: DangerBasis | null =
    published.high === 0
      ? null
      : malicious === 0
        ? "critical_exploitable_vulnerability"
        : published.high > malicious
          ? "mixed"
          : "malicious_or_compromised";
  return {
    risk:
      dangerBasis !== null
        ? "high"
        : published.material > 0
          ? "material"
          : "low",
    dangerBasis,
    counts: { ...published },
  };
}

export function dangerBasisLabel(basis: DangerBasis | null) {
  if (basis === "malicious_or_compromised")
    return "Malicious or compromised behavior";
  if (basis === "critical_exploitable_vulnerability")
    return "Critical, readily exploitable vulnerability";
  if (basis === "mixed")
    return "Malicious or compromised behavior and a critical, readily exploitable vulnerability";
  return "No immediate-danger basis";
}

export function projectAdvisorySummary(advisory: ProjectAdvisory) {
  if (advisory.risk === "high")
    return `Immediate danger: ${dangerBasisLabel(advisory.dangerBasis)}.`;
  return assessmentSummary(advisory.counts);
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

export function escapeHtml(value: string | number) {
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

export function renderSiteHeader() {
  return `<header class="site-header">
    <div class="site-header-inner">
      <a class="brand" href="${SITE_ROOT}">
        TavernKeeper
        <small>Advisory reports for Tavernary</small>
      </a>
      <nav class="site-nav" aria-label="Site navigation">
        <a href="${SITE_ROOT}#reports">Reports</a>
        <a href="${SITE_ROOT}#how-it-works">How it works</a>
        <a href="${TAVERNARY_URL}">Return to Tavernary</a>
      </nav>
    </div>
  </header>`;
}
