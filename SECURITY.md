# Security policy

## Supported versions

Security fixes are currently evaluated for the latest code on `main` and the upcoming
0.10.0 public-preview line. Historical tags are retained for evidence and are not
promised maintenance branches. OMIV is pre-1.0 and this scope may change with a
documented release policy.

## Reporting a vulnerability

Before or immediately with public publication, the repository owner must enable
GitHub private vulnerability reporting. Once enabled, use the repository's
**Security → Report a vulnerability** flow.

`ENABLE_GITHUB_PRIVATE_VULNERABILITY_REPORTING_BEFORE_OR_IMMEDIATELY_WITH_PUBLICATION`

Do not put exploit details in a public issue. A public issue may ask maintainers to
enable or confirm the private reporting channel, but it must not contain reproduction
steps for an unpatched vulnerability.

Do not send credentials, access tokens, cookies, private keys, customer data,
production prompts or outputs, private model metadata, or model/tokenizer payloads.
Use minimal synthetic reproduction material and remove signed URLs and raw HTTP
headers. No response or remediation SLA is promised.

OMIV evidence validates explicitly recorded properties. A successful parse,
signature check, or policy result is not a safety certification and does not establish
that a model is secure, authentic, production-ready, or suitable for regulated use.
