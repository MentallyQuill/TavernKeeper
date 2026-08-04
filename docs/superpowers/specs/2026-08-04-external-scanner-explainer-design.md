# External Scanner Explainer Design

## Goal

Expand the public landing page's "How it works" section so visitors can understand why TavernKeeper uses credible, specialized scanning tools. The explainer covers only externally maintained scanners; TavernKeeper's built-in static rules remain implementation detail for this section.

## Scope

Add an "External scanners" subsection below the existing four-step process. It will contain one compact explanatory card per required external scanner:

- [Gitleaks](https://github.com/gitleaks/gitleaks): detects exposed secrets and credential-like values, including relevant repository history.
- [OpenGrep](https://github.com/opengrep/opengrep): applies static-analysis rules to identify suspicious code patterns.
- [OSV-Scanner](https://github.com/google/osv-scanner): checks declared dependency inputs against known vulnerability advisories.
- [zizmor](https://github.com/zizmorcore/zizmor): analyzes GitHub Actions workflows for workflow-security problems.
- [malcontent](https://github.com/chainguard-dev/malcontent): analyzes project artifacts for suspicious or malicious behavior.

Each card will state what the tool detects, how TavernKeeper applies it to the exact repository commit, and link the tool name to its official repository. The section will say that scanners are version-pinned and are run against project contents as untrusted data. It will also preserve the existing limitation that a report is advisory evidence, not a safety certification.

## Presentation

Keep the existing four ordered steps unchanged. Render the scanner cards as a responsive grid using the existing site visual language: dark surfaces, existing borders, teal links, and compact readable typography. On narrow screens the cards stack in a single column. The links open the official repositories and use descriptive accessible link text.

Avoid claiming that any scanner proves intent, catches every vulnerability, or certifies a repository. Tool descriptions should distinguish specialized coverage from TavernKeeper's overall assessment.

## Data and implementation boundary

The scanner descriptions are static site copy in `src/site/render-landing.ts`; no report schema, scanner execution, or generated report contract changes are required. The five tools and their roles must match `config/scanners.v1.json` and `src/scanners/run-scanners.ts`. The page may mention conditional applicability where relevant: OSV-Scanner, zizmor, and malcontent run when the inventory contains applicable inputs, while Gitleaks and OpenGrep are part of the required scanner sequence.

## Verification

- Add or update site presentation/build assertions so all five official repository links and tool descriptions appear in the generated landing page.
- Run the focused site tests.
- Run the project check and site build.
- Inspect the generated HTML for the five links, the responsive scanner layout, and the existing advisory/limitations language.
