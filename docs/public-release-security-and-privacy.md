# Public-release security and privacy record

This record describes the 0.10.0 Alpha public preview and its remaining release gates. It contains no
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
invariant remains exactly one; a platform identity cannot satisfy it. Three additional
fingerprints are reviewed for exact platform-generated occurrences only:

- one `AUTHOR` fingerprint is limited to `GITHUB_DEPENDABOT_UPDATE_AUTHOR` on a
  `REMOTE_DEPENDABOT_BRANCH` and its exact PR #1 head/merge ancestry;
- one distinct `COMMITTER` fingerprint is limited to
  `GITHUB_WEB_FLOW_SIGNED_DEPENDABOT_COMMITTER` on that exact commit and to a
  verified PR #2 synthetic merge;
- one distinct `AUTHOR` fingerprint is limited to the verified PR #2 synthetic merge
  created for the reviewed release branch.

The reviewed REST records bind repository ID `1316060005`, Dependabot actor ID
`49699333`, the owner actor ID `145014769`, and web commit-signing actor ID `19864447`
to the exact commits, roles, and PRs. GitHub reported each reviewed platform-generated
commit signature as present, valid, and verified. The embedded commit signatures use
the reviewed GitHub signing key ID `B5690EEEBB952194`. The review also used GitHub's
documentation for
[Dependabot-signed commits](https://docs.github.com/en/code-security/concepts/supply-chain-security/dependabot-security-updates),
[REST commit actor and verification fields](https://docs.github.com/en/rest/commits/commits),
and the documented
[web commit-signing service account](https://docs.github.com/en/enterprise-server@3.21/admin/configuring-settings/configuring-user-applications-for-your-enterprise/configuring-web-commit-signing).
Those reviewed API and documentation facts are provenance for the exact fingerprints.
For an ordinary GitHub Actions `pull_request` run, GitHub documents `GITHUB_REF` as
`refs/pull/<number>/merge` and `GITHUB_SHA` as the last merge commit on that ref in
[Events that trigger workflows](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows).
The audit therefore treats `GITHUB_SHA` as the current checkout identity only after
binding it to the expected hidden merge ref, detached local `HEAD`, an available commit
object, and exactly two ordered parents matching the event base and head. GitHub's
[pull-request REST documentation](https://docs.github.com/en/rest/pulls/pulls) separately
describes `merge_commit_sha` as a test merge that GitHub creates while computing
mergeability. An event or API test-merge SHA may consequently differ from the current
Actions checkout. The audit records that exact discrepancy without calling it equality,
continuity, or historical identity, and accepts it only after every stronger checkout,
repository, PR, ref, parent, actor, role, signature, signer, and scope invariant verifies.
All other current-checkout or provenance mismatches remain fail-closed. The bounded REST
checks still establish public PR association, actors, and verified-valid signature
provenance; a differing test-merge SHA establishes none of those facts. It does not
infer trust from a `[bot]` suffix, a noreply address, a branch name, a generic verified
signature, or a login-like string, and it never accepts `REMOTE_OTHER_BRANCH` globally.

PR-evidence construction reports a typed status (`AVAILABLE`, `NOT_AVAILABLE`,
`INVALID`, or `INDETERMINATE`), a stable reason code, and bounded boolean/count facts.
It emits the verified evidence record only for `AVAILABLE`; failures do not serialize
the event payload, identity text, email addresses, environment paths, request headers,
tokens, or credential-bearing URLs. This diagnostic surface does not grant trust: any
missing, invalid, or indeterminate provenance needed by a reviewed platform occurrence
continues to fail the identity gate.

The fail-closed taxonomy is:

- `OWNER_APPROVED_HUMAN_IDENTITY`
- `VERIFIED_PLATFORM_SERVICE_IDENTITY`
- `SYNTHETIC_TEST_IDENTITY`
- `UNVERIFIED_PLATFORM_SERVICE_CLAIM`
- `UNKNOWN_HUMAN_IDENTITY`
- `UNKNOWN_AUTOMATION_IDENTITY`
- `INVALID_IDENTITY`

Unknown or invalid records fail readiness. Platform service identities remain in the
public-exposure inventory, but confer no owner, publisher, maintainer, release, or
repository authority and do not establish publisher authenticity. Synthetic test
identities require an explicit test-only fingerprint and are never inferred from
their spelling. A platform service has no owner, maintainer, publisher, tagger,
release-signing, repository, or PyPI authority.

## Audit boundary

The release audit checks reachable history, common credential patterns, repository
blob sizes, forbidden payload extensions, legal/public files, package metadata,
workflow permissions and pinning, and ignored local material. Synthetic secret markers
used by negative tests are not credentials. The audit is defense in depth, not proof
that no undiscoverable sensitive value exists.

Ignored local raw captures, virtual environments, caches, and downloaded artifacts are
outside the public Git object set and must remain untracked. Public fixtures contain
only bounded evidence described in [THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md).
The only default-CI identity network read is the bounded public GitHub REST provenance
check described above; no default CI path accesses model providers or downloads
model/tokenizer payloads.

Live GitHub visibility is authoritative. R1E applied and verified the reviewed
profile, topics, and supported Dependabot controls; the controlled R1F transaction
verified the public-only controls and exact main enforcement. This record does not
turn those controls into a safety certification.

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

The public controls were verified by the controlled R1F transaction. A future release
still requires the signed tag, exact artifact chain, GitHub Pre-release, and PyPI
Trusted Publisher gates described in [release notes](v0.10.0-release-notes.md) and
[releasing](releasing.md). This documentation does not claim PyPI availability or
release completion.
