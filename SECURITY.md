# Security Policy

## Reporting a TavernKeeper vulnerability

Please use GitHub's private vulnerability-reporting or security-advisory channel for the `MentallyQuill/TavernKeeper` repository. Do not publish exploitable details, credentials, live malicious payloads, or private repository content in a public Issue.

Include the affected TavernKeeper commit, the relevant component or workflow, the smallest inert reproduction you can provide, and the security impact. Never include a real API key. TavernKeeper staff will coordinate validation and disclosure privately.

## Disputing a published finding

A project owner may use the repository's false-positive appeal Issue Form and
provide the immutable report URL plus finding identity. An appeal does not start
a scan, change scanner inputs, dismiss a finding, or gate publication. Evidence
may reveal a defect in global scanner, context, prompt, or assessment policy.
Any correction is made through ordinary code review as a versioned global
policy change, followed by an automatic complete rescan. Existing report URLs
and history remain unchanged.

## Scan requests and operational incidents

Public scan requests are not accepted. Only Tavernary staff can initiate a
targeted scan through Tavernary's protected GitHub-URL Action. Only TavernKeeper
staff can initiate retry, policy-campaign, provider-check, pause, resume, or
recovery operations through protected GitHub environments. Scanner and provider
failures are handled internally and do not notify external repository owners.

## Result meaning

TavernKeeper reports are advisory technical observations about one exact commit
under documented scanner and contextual-review policies. Deterministic findings
are candidate signals, not conclusions; every candidate must receive a complete
evidence-bound contextual assessment. Tavernary independently assigns the final
public risk grade. Neither result is certification, endorsement, malware
prevention, or a guarantee of safety. Incomplete scans publish no report.
