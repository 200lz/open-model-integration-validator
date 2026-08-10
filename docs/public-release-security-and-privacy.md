# Public-release security and privacy record

This record describes the upcoming 0.10.0 public-preview candidate. It contains no
credentials, complete author email, or approved absolute path.

## Approved historical disclosures

The owner approved the repository's one reviewed historical non-noreply author
identity:

`AUTHOR_EMAIL_PUBLICATION_APPROVED_BY_OWNER`

The owner also approved exactly these reviewed historical machine-path fingerprints:

- `5ba5e619bbec7b9f`
- `8c8ba75aa027ee39`
- `449183090d324eb6`
- `f807b9e7bf9968a8`
- `5b3b9cf7f8eeca6`

`HISTORICAL_MACHINE_PATH_DISCLOSURE_APPROVED_BY_OWNER`

The approval does not extend to another identity or path. The readiness tool compares
only safe digests and counts; it does not print an email or absolute path. Current
source must not add a machine-specific default.

## Audit boundary

The release audit checks reachable history, common credential patterns, repository
blob sizes, forbidden payload extensions, legal/public files, package metadata,
workflow permissions and pinning, and ignored local material. Synthetic secret markers
used by negative tests are not credentials. The audit is defense in depth, not proof
that no undiscoverable sensitive value exists.

Ignored local raw captures, virtual environments, caches, and downloaded artifacts are
outside the public Git object set and must remain untracked. Public fixtures contain
only bounded evidence described in [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md).
No default CI path enables network integration or downloads model/tokenizer payloads.

The R1F baseline is private; live GitHub visibility is authoritative after any later
transaction. R1E applied and verified the reviewed profile, topics, and supported
private Dependabot controls. GitHub documents Private Vulnerability Reporting for
public repositories, so it is not verified at the private baseline. After a
separately authorized public visibility change, R1F must immediately enable and
re-read private reporting, secret scanning, push protection, and the exact reviewed
branch protection in the order defined by the
[R1F final-publication audit](r1f-final-publication-audit.md). Failure of any required
post-public control blocks successful publication classification and keeps
announcement, tag, GitHub release, and PyPI operations prohibited. This
implementation does not change any GitHub setting.
