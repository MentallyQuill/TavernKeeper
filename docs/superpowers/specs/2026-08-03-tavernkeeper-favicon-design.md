# TavernKeeper favicon set design

## Goal

Create a complete favicon family from the supplied `scan.svg`, using the
TavernKeeper functional orange (`#E18A24`) and preserving the source mark's
transparent, monochrome treatment.

## Approved visual treatment

The scan/refresh mark remains unchanged geometrically. Its visible path is
recolored to `#E18A24`; the SVG background remains transparent. PNG and ICO
outputs use the same transparent orange mark, with no dark tile, border, or
additional lettering.

## Asset family

The canonical source and generated derivatives live together under
`src/site/assets/` and are copied into the Pages artifact's `assets/`
directory:

- `favicon.svg` — scalable source mark;
- `favicon-16.png`, `favicon-32.png`, and `favicon-48.png` — browser tab and
  legacy shortcut sizes;
- `apple-touch-icon.png` — 180px touch icon;
- `favicon-192.png` and `favicon-512.png` — installable/PWA-compatible sizes;
- `favicon.ico` — ICO container with 16px, 32px, and 48px entries.

All raster outputs are square RGBA images with transparent backgrounds and
the orange scan mark rendered from the canonical SVG.

## Site integration

The shared HTML presentation layer declares the icon family with relative
URLs so the same generated markup works at the root, report, and history
paths of the GitHub Pages project site. The metadata includes the SVG icon,
ICO fallback, 32px and 16px PNG fallbacks, Apple touch icon, and 192/512px
PNG icons. The static-site builder copies the allowlisted asset directory
into every generated Pages artifact.

## Verification

Focused tests will verify the orange SVG source, the metadata emitted by each
HTML renderer, and the favicon files included by `buildSite`. The generated
`.site` artifact will be rebuilt and checked for every expected asset and
relative metadata URL. The change will also run the repository typecheck,
build, and full test suite.

## Scope boundaries

- Do not alter the scan mark's geometry.
- Do not add a new color token or change the existing site palette.
- Do not add a manifest, service worker, remote asset, icon library, or UI
  redesign.
- Do not modify the unrelated untracked `TavernKeeper/` directory.
