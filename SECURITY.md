# Security policy

## Supported versions

Security fixes are currently evaluated for the latest code on `main` and the upcoming
0.10.0 public-preview line. Historical tags are retained for evidence and are not
promised maintenance branches. OMIV is pre-1.0 and this scope may change with a
documented release policy.

## Reporting a vulnerability

The R1F baseline is private; live GitHub visibility and security-control read-back are
authoritative after any later transaction. GitHub documents Private Vulnerability
Reporting for public repositories, so the channel is not currently verified or
claimed active at the private baseline. Immediately after a separately authorized
change to public visibility, the controlled R1F transaction must enable and
independently re-read the channel. If that fails, successful publication
classification is blocked. Once live state verifies it, use the repository's
**Security → Report a vulnerability** flow.

`ENABLE_AND_VERIFY_GITHUB_PRIVATE_VULNERABILITY_REPORTING_IMMEDIATELY_AFTER_PUBLIC_VISIBILITY`

The private-baseline status endpoint returned an undifferentiated not-found response,
so the baseline state is `API_STATE_UNAVAILABLE`, not enabled. See the
[GitHub publication controls](docs/github-publication-controls.md). A later live
read is required; documentation alone does not establish the control state. If the
**Report a vulnerability** control is unavailable, do not disclose sensitive details
through a public issue or another public fallback.

Do not put vulnerability or exploit details in a public issue. A public issue may
ask maintainers to enable or confirm the private reporting channel, but it must not
contain reproduction steps, credentials, customer data, private payloads, signed
URLs, or other details of an unpatched vulnerability.

Do not send credentials, access tokens, cookies, private keys, customer data,
production prompts or outputs, private model metadata, or model/tokenizer payloads.
Use minimal synthetic reproduction material and remove signed URLs and raw HTTP
headers. No response or remediation SLA is promised.

OMIV evidence validates explicitly recorded properties. A successful parse,
signature check, or policy result is not a safety certification and does not establish
that a model is secure, authentic, production-ready, or suitable for regulated use.
