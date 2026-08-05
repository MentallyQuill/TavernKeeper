# TavernKeeper Reports Site Design

## Purpose

Bring TavernKeeper's public landing, report, and history pages into the same
visual family as Tavernary while making the service understandable to two equal
audiences:

- nontechnical visitors deciding how much significance to give a scan; and
- project developers deciding whether TavernKeeper is invasive, useful, or
  misleading.

The site must remain a restrained static publication surface. Usability comes
from clear hierarchy and progressive disclosure, not additional panels,
dashboards, or decoration.

## Product principles

1. **Plain language first.** State the conclusion, scope, and limitations before
   scanner or policy details.
2. **Technical truth remains available.** Developers can inspect exact commit,
   tools, evidence locations, model provider, policy versions, and limitations
   without leaving the report.
3. **Reports are advisory evidence, not safety certificates.** TavernKeeper
   describes its completed technical review; Tavernary independently produces
   the public project assessment and freshness state.
4. **No hidden invasiveness.** Explain that target code is never executed, but
   bounded candidate context is sent to the named configured model provider.
5. **Less is more.** Prefer one strong content column, short labels, native
   disclosure controls, and a small number of actions.

## Information architecture

The public site has three page types with one shared header:

- **Landing and report directory** at `/TavernKeeper/`
- **Repository scan history** at each existing history URL
- **Technical report** at each immutable report URL

The header contains only the TavernKeeper wordmark, the subtitle "Advisory
reports for Tavernary," a Reports link, a How it works link, and a Return to
Tavernary link. No separate sidebar, category navigation, or decorative hero
art is introduced.

## Landing page

The landing page uses this order:

1. A compact hero: "Technical security reports for Tavernary projects."
2. Two short paragraphs explaining exact-commit scans, the advisory boundary,
   and Tavernary's separate public assessment.
3. The searchable report directory.
4. A concise "How it works" ordered list.
5. A two-column-at-desktop, stacked-on-mobile "What it does / What it never
   does" explanation.
6. A final limitations paragraph and links to Tavernary and the machine-readable
   report index.

The operations copy states that TavernKeeper inventories an exact commit,
runs required deterministic scanners without executing target code, sends
bounded candidate context to the configured model provider for structured
contextual assessment, validates complete coverage, and publishes a sanitized
immutable report. It states that dependencies, scripts, builds, tests, Actions,
and target executables are never run.

## Searchable reports

The directory is pre-rendered from the sanitized V5 report index. It remains
readable when JavaScript is unavailable. A small self-hosted script progressively
adds instant filtering without network requests.

There are only two controls:

- a search field covering repository name, commit SHA, and displayed assessment
  terms; and
- a native risk filter for All, Immediate danger, Material, and Low/no material
  concern.

The filter uses TavernKeeper's deterministic project advisory. Immediate
danger requires either high-confidence credible malicious or compromised
behavior, or a high-confidence critical vulnerability that is readily
exploitable in the shipped project. Other material vulnerabilities, including
critical dependency advisories without proven runtime reachability and
attacker control, remain Material. Otherwise the report is Low/no material
concern.

Results are newest first. Each compact result contains repository name, a
plain-language assessment summary, completion date, shortened commit, risk
counts, and links to the report and repository history. Empty search results
show one direct explanation and a Clear search action. Raw report IDs, provider
IDs, byte counts, and policy versions do not appear in the directory.

## Technical report

The report opens with:

- repository identity and short commit;
- a plain-language assessment summary derived deterministically from published
  assessment and observation fields;
- the existing advisory limitation; and
- links to repository history and Tavernary.

Contextual assessments remain the primary content. Material and high items are
expanded as normal cards. Expected scanner matches remain collapsed by default.
Technical evidence remains inside native `<details>` elements.

Coverage, tools, limitations, reviewer identity, policy versions, full commit,
and report ID move below the assessment content. Exact values remain present,
but long hashes wrap safely and ISO timestamps gain a readable visible form
with the exact value retained in `<time datetime>`.

The page does not introduce a score, gauge, certification badge, sticky
navigation, modal, or duplicated summary dashboard.

## Repository history

History is newest first. The page identifies the repository, links back to the
report directory, and renders one compact row per scan containing readable date,
short commit, risk counts, coverage completion, and a View report link. It does
not assign Tavernary's final color or repeat internal report identifiers.

## Tavernary family alignment

Use a small shared TavernKeeper theme based on Tavernary's current semantic
language:

- dark canvas `#0D1117`;
- header `#101820`;
- surface `#182228`;
- borders `#2B3A40` and `#3E535B`;
- primary and secondary text `#E6EDF3` and `#A8B3BA`;
- teal links and focus `#6EE7D8` and `#5EEAD4`;
- orange functional action `#E18A24`;
- material and high risk use Tavernary warning and danger families;
- eight-pixel card radius, restrained shadow, and Inter/system sans typography.

No remote font, logo, image, icon library, or third-party asset is added. Risk
is always expressed with text as well as color.

## Security and publication constraints

- Report and history pages remain script-free.
- Landing search uses one self-hosted script, no fetch calls, no analytics, and
  no third-party code.
- CSP continues to deny remote content, connections, forms, frames, objects,
  and base changes. Only the landing page permits its same-origin search script.
- All dynamic report values remain HTML-escaped.
- Search operates only on sanitized, pre-rendered index fields.
- Report JSON, identity, evidence, and risk contracts are unchanged. The work
  changes presentation only.
- Existing public HTML is regenerated from its committed sanitized JSON so the
  current reports receive the new presentation without changing report IDs or
  evidence.

## Responsive and accessible behavior

- Support widths from 320px upward without horizontal page scrolling.
- Metadata grids collapse to a single column before long values become cramped.
- All controls have visible labels and focus states.
- Native search, select, time, details, summary, lists, headings, and links are
  preferred over custom widgets.
- Search result announcements use a polite live region.
- Motion is limited to short color transitions and respects reduced-motion
  preferences.

## Implementation boundary

Create one shared presentation module for escaped text, theme CSS, header,
date/commit formatting, and count-derived summaries. Add one landing renderer
and one small search-script source. Update the existing site builder, report
renderer, and history renderer to consume those primitives. Do not add a UI
framework, bundler, runtime dependency, image pipeline, or client-side data
store.

## Acceptance criteria

- The landing page explains significance, operation, non-execution, contextual
  model use, publication, and limitations in plain language.
- Current reports are searchable without loading report bodies.
- Landing, report, and history pages visibly share Tavernary's palette,
  typography, spacing, cards, links, and focus treatment.
- The first report viewport prioritizes conclusion and meaning over internal
  identifiers.
- Developers can still find every existing technical identity and limitation.
- Search works by repository and SHA, filters by risk, clears cleanly, and has a
  useful empty state.
- Pages remain useful without JavaScript, contain no remote assets, and preserve
  restrictive CSPs.
- Existing report contracts, sanitized content, and Tavernary risk authority do
  not change.
- Focused rendering tests, site-build tests, the full unit suite, typecheck,
  formatting, workflow policy, production site build, and desktop/mobile
  rendered checks pass.
