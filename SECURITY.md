# Security policy

## Supported versions

Security fixes are currently evaluated for the latest code on `main` and the upcoming
0.10.0 public-preview line. Historical tags are retained for evidence and are not
promised maintenance branches. OMIV is pre-1.0 and this scope may change with a
documented release policy.

## Reporting a vulnerability

The repository is currently private. GitHub documents Private Vulnerability
Reporting for public repositories, so the channel is not currently verified or
claimed active and R1E must not attempt to enable it while the repository is private.
Immediately after a separately authorized change to public visibility, R1F
must enable and independently re-read the channel. If that fails, successful
publication classification is blocked. Once verified, use the repository's **Security →
Report a vulnerability** flow.

`ENABLE_AND_VERIFY_GITHUB_PRIVATE_VULNERABILITY_REPORTING_IMMEDIATELY_AFTER_PUBLIC_VISIBILITY`

The R1E implementation-time status endpoint returned an undifferentiated not-found
response, so the current state is `API_STATE_UNAVAILABLE`, not enabled. See the
[GitHub publication controls](docs/github-publication-controls.md). A later live
read is required; documentation alone does not establish the control state.

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
