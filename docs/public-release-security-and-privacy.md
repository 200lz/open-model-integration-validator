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

The only accepted historical human record is the existing owner-approved fingerprint.
The human invariant remains exactly one; a platform-mediated account or service
identity cannot satisfy it. Three additional fingerprints are reviewed for exact
platform-mediated occurrences only:

- one `AUTHOR` fingerprint is limited to `GITHUB_DEPENDABOT_UPDATE_AUTHOR` on a
  `REMOTE_DEPENDABOT_BRANCH` and its exact PR #1 head/merge ancestry;
- one distinct service `COMMITTER` fingerprint is limited to
  `GITHUB_WEB_FLOW_SIGNED_DEPENDABOT_COMMITTER` on that exact commit and to a
  verified PR #2 synthetic merge, or to its exact reviewed role in an authoritative-main
  GitHub-signed squash identity pair;
- one distinct platform-mediated account `AUTHOR` fingerprint is limited to the
  verified PR #2 synthetic merge or to the corresponding author role in that exact
  authoritative-main squash identity pair.

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
mergeability; mergeability may temporarily be `null` while that computation runs. An
event or API test-merge SHA may consequently be absent, `null`, or differ from the
current Actions checkout. The audit records those cases as
`EVENT_TEST_MERGE_SHA_NOT_RECORDED` or
`EVENT_TEST_MERGE_SHA_DIFFERS_FROM_CURRENT_CHECKOUT` without calling either equality,
continuity, or historical identity. It accepts an absent, null, or differing advisory
test-merge field only after every stronger checkout, repository, PR, ref, parent, actor,
role, signature, signer, and scope invariant verifies. A present matching advisory field
is recorded as `EVENT_TEST_MERGE_SHA_MATCHES_CURRENT_CHECKOUT`.
All other current-checkout or provenance mismatches remain fail-closed. The bounded REST
checks still establish public PR association, actors, and verified-valid signature
provenance; a differing test-merge SHA establishes none of those facts. It does not
infer trust from a `[bot]` suffix, a noreply address, a branch name, a generic verified
signature, or a login-like string, and it never accepts `REMOTE_OTHER_BRANCH` globally.

Authoritative-main squash identity evidence is intentionally separate from current
pull-request event evidence. The offline classifier requires the exact repository,
`LOCAL_MAIN` or `REMOTE_MAIN` reachability, a one-parent squash-style commit, the
reviewed author/committer fingerprint pairing in non-interchangeable roles, supporting
`(#<positive PR number>)` subject syntax, and cryptographic verification against the
reviewed GitHub signer fingerprint and the bounded public key profile stored in
`docs/security/github-web-flow-signing-key.asc`. This is a forward-safe role, signer,
repository, branch-class, and topology policy: it is not an allowlist for one commit
SHA or tree. The reviewed actor IDs remain provenance metadata because they are not
cryptographically present in offline Git objects; an offline run reports that live
actor observation was not supplied.

That offline evidence establishes only that an observed Git identity occurrence fits
the reviewed GitHub-mediated account or service role. It does not prove pull-request
approval, required checks, branch protection, merge authorization, real-world human
identity, or owner, publisher, tag, release, repository, or PyPI authority. A separate
`PROTECTED_PULL_REQUEST_SQUASH_MERGE_EVIDENCE` model can validate authenticated PR,
actor, check, tree, result-parent, signature, merge-method, and protection observations
when they are explicitly supplied. Static CI does not call GitHub for that stronger
process evidence and reports it as `NOT_SUPPLIED`; it is never inferred from a subject
or signature alone.

PR-evidence construction reports a typed status (`AVAILABLE`, `NOT_AVAILABLE`,
`INVALID`, or `INDETERMINATE`), a stable reason code, bounded boolean/count facts, and
sorted field-name-only lists for missing or null required and advisory event fields.
Repository identity, a positive PR number, base/head refs and SHAs, event actor, Actions
ref/SHA, local commit object and ordered parents, signer, signature, and reviewed role
remain mandatory. Current-event role policy is forward-safe but not global: it applies
only while those event, environment, Git, and authenticated REST bindings all agree for
the current `pull_request` merge ref. Historical PR #2 policy remains exact. Neither
internal field agreement nor a similarly spelled identity independently authorizes an
occurrence.
It emits the verified evidence record only for `AVAILABLE`; failures do not serialize
the event payload, identity text, email addresses, environment paths, request headers,
tokens, or credential-bearing URLs. This diagnostic surface does not grant trust: any
missing, invalid, or indeterminate provenance needed by a reviewed platform occurrence
continues to fail the identity gate.

The fail-closed taxonomy is:

- `OWNER_APPROVED_HUMAN_IDENTITY`
- `VERIFIED_PLATFORM_MEDIATED_ACCOUNT_IDENTITY`
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

The public controls were verified by the controlled R1F transaction. The signed
`v0.10.0` tag, exact GitHub asset chain, and pre-release now exist, but the first PyPI
Trusted Publishing run stopped at tag verification because the runner had no public
signing key. The [publication recovery record](v0.10.0-publication-recovery.md) and
[release process](releasing.md) define the fail-closed correction. This documentation
does not claim PyPI availability, software safety, model authenticity, or release
completion.
