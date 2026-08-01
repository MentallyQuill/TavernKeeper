# Hostile repository fixture

This directory is reserved for inert fixtures that exercise TavernKeeper's
fail-closed repository boundary. Fixture names and contents may represent
links, traversal paths, Unicode controls, oversized input, archive bombs,
install hooks, prompt injection, and fake credentials, but tests must never
execute target-owned code or make network requests.

Seeded secrets must be synthetic and must never appear in logs, cache records,
published report JSON, or generated HTML.
