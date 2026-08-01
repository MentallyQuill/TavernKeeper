# Public Rule Documentation

TavernKeeper findings may link to a canonical public rule page. These pages explain what a rule observes, why it warrants review, and common benign explanations. They do not reproduce matched source, secrets, or payloads.

- `credential-exfiltration`: credential-like access and an outbound network sink in the same file
- `network-install-hook`: a package installation lifecycle hook containing a network-capable command
- `unicode-bidi-control`: a bidirectional Unicode control character that can disguise displayed source ordering

The Pages build publishes only `docs/rules`, report artifacts, and schemas. Public rule pages are static, script-free HTML with a restrictive content security policy.
