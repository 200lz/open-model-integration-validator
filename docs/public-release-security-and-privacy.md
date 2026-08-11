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

## Public identity classification

The history audit keeps commit authors, commit committers, and annotated-tag taggers
independently observable across every local branch, remote-tracking branch, pull ref,
tag, and other Git ref. It hashes each exact name/address pair with the
domain-separated `omiv.identity.v1` SHA-256 construction and emits only the digest,
role, and reachable-ref classification.

The only accepted human record is the existing owner-approved fingerprint. The human
invariant remains exactly one; a platform identity cannot satisfy it. Two additional
fingerprints were reviewed after private CI exposed the open Dependabot branch:

- one `AUTHOR` fingerprint is limited to `GITHUB_DEPENDABOT_UPDATE_AUTHOR` on a
  `REMOTE_AUTOMATION_BRANCH`;
- one distinct `COMMITTER` fingerprint is limited to
  `GITHUB_WEB_FLOW_SIGNED_DEPENDABOT_COMMITTER` on that same ref class.

GitHub's REST commit response associated the author with a `Bot` actor and the
committer with the web commit-signing actor, and reported the commit signature as
present, valid, and verified. The review also used GitHub's documentation for
[Dependabot-signed commits](https://docs.github.com/en/code-security/concepts/supply-chain-security/dependabot-security-updates),
[REST commit actor and verification fields](https://docs.github.com/en/rest/commits/commits),
and the documented
[web commit-signing service account](https://docs.github.com/en/enterprise-server@3.21/admin/configuring-settings/configuring-user-applications-for-your-enterprise/configuring-web-commit-signing).
Those reviewed API and documentation facts are provenance for the exact fingerprints;
the audit does not infer trust from a `[bot]` suffix, a noreply address, a branch name,
or a login-like string.

The fail-closed taxonomy is:

- `OWNER_APPROVED_HUMAN_IDENTITY`
- `VERIFIED_PLATFORM_SERVICE_IDENTITY`
- `SYNTHETIC_TEST_IDENTITY`
- `UNKNOWN_HUMAN_IDENTITY`
- `UNKNOWN_AUTOMATION_IDENTITY`
- `INVALID_IDENTITY_RECORD`

Unknown or invalid records fail readiness. Platform service identities remain in the
public-exposure inventory, but confer no owner, publisher, maintainer, release, or
repository authority and do not establish publisher authenticity. Synthetic test
identities require an explicit test-only fingerprint and are never inferred from
their spelling.

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
public repositories, so it is not verified at the private baseline.

One controlled attempt was publicly readable for approximately 5 hours 39 minutes on
2026-08-10. Its pre-public exposure audit detected no secret or privacy finding. PVR,
secret scanning, and push protection were enabled while public, but branch protection
was never applied because its request returned HTTP 422. The authorized rollback to
PRIVATE succeeded. Returning PRIVATE cannot erase prior observation, indexing,
links, caches, copies, watchers, forks, or repository-network effects, and no claim is
made that no third party observed or copied the repository. No tag, GitHub Release,
PyPI publication, or announcement occurred. The three public-only controls now have
`API_STATE_UNAVAILABLE` private API state rather than a claimed enabled or disabled
state. The prior visibility and rollback authorizations were consumed; another
attempt requires a new visibility authorization and a new rollback-policy choice.

After a newly authorized public visibility change, R1F must immediately enable and
re-read private reporting, secret scanning, push protection, and the corrected
checks-only reviewed branch protection in the order defined by the
[R1F final-publication audit](r1f-final-publication-audit.md). Failure of any required
post-public control blocks successful publication classification and keeps
announcement, tag, GitHub release, and PyPI operations prohibited. This
implementation does not change any GitHub setting.
