# GitHub publication controls

This document defines the reviewable repository state required before OMIV can
become public. It is Release Track configuration, not OMIV evidence and not a
security certification. The machine-readable companion is
[`.github/publication-policy.json`](../.github/publication-policy.json).

The R1F baseline is **PRIVATE**; live GitHub visibility is authoritative after any
later transaction. Version 0.10.0 remains an untagged and unreleased public-preview
candidate, with no GitHub release or PyPI publication. This document does not
authorize a visibility or settings change.

## Controlled public attempt rolled back

A separately authorized attempt made the repository public from
`2026-08-10T17:23:08Z` until the successful return to PRIVATE at
`2026-08-10T23:02:08Z`, approximately 5 hours 39 minutes. PVR, secret scanning, and
push protection verified while public, but the branch-protection PUT failed with
HTTP 422 because the request mixed incompatible `contexts` and app-bound `checks`
schema variants. Branch protection was never applied. The pre-public exposure audit
found no secret or privacy finding, but returning PRIVATE cannot erase observation,
indexing, links, caches, copies, stars, watchers, forks, or repository-network
effects, and this record does not claim that no third party observed or copied it.

No tag, GitHub Release, PyPI publication, or announcement occurred. The public-only
control APIs became `API_STATE_UNAVAILABLE` after rollback and are not described as
enabled or disabled while private. The prior visibility authorization was consumed;
the prior rollback authorization was consumed and executed. A new visibility
authorization and a new rollback selection are mandatory before another attempt.

## Desired repository profile

The profile applied and verified by R1E, and required to remain unchanged through a
separately authorized visibility transaction, is deterministic:

- description: `Offline-first evidence and verification framework for AI model artifacts, transformations, runtime identity, and provenance.`
- topics, in policy order: `ai-supply-chain`, `model-provenance`,
  `artifact-verification`, `model-integrity`, `supply-chain-security`, `mlops`,
  `llm`, `gguf`, `safetensors`, `offline-first`
- homepage: empty until an independent project site exists
- default branch: `main`
- issues: enabled
- wiki: disabled
- discussions: disabled for the initial preview; no moderation plan exists
- projects: preserve the currently enabled state
- archived: false
- template repository: false

Topics use only lowercase letters, digits, and hyphens, are unique, are no more
than 50 characters each, and remain below GitHub's topic-count limit. They describe
the project without claiming certification, production readiness, provider
affiliation, or provable inference.

## State vocabulary

Remote controls use one of these exact states:

| State | Meaning |
| --- | --- |
| `ENABLED_AND_VERIFIED` | An authenticated read returned the enabled/configured state. |
| `DISABLED` | The endpoint explicitly reported disabled. |
| `NOT_CONFIGURED` | The endpoint explicitly reported no configuration, or the prerequisite configuration is absent. |
| `UNAVAILABLE_FOR_CURRENT_VISIBILITY_OR_PLAN` | The endpoint explicitly tied availability to a plan upgrade or public visibility. |
| `API_STATE_UNAVAILABLE` | The endpoint did not provide enough information to distinguish states. |
| `DEFERRED_TO_R1F` | A reviewed manual decision is required during the final publication audit. |
| `DEFERRED_TO_SEPARATE_POST_PUBLIC_CHANGE` | Launch does not depend on this control; it requires a later protected review. |
| `INVALID` | The observed state conflicts with policy or cannot be safely interpreted. |

A 403, 404, or 422 is interpreted only with its endpoint-specific message and
documented operation. An error is never converted into an enabled state.

Application timing is separate from control state:

- `CONFIGURED_NOW`
- `PROPOSED_FOR_R1E_RELEASE`
- `REQUIRED_IMMEDIATELY_BEFORE_PUBLIC_VISIBILITY`
- `REQUIRED_IMMEDIATELY_AFTER_VISIBILITY_CHANGE`
- `UNAVAILABLE_FOR_CURRENT_VISIBILITY_OR_PLAN`
- `MANUALLY_DEFERRED`
- `R1F_IMMEDIATELY_AFTER_PUBLIC_VISIBILITY`

## Read-only R1F baseline after R1E

The following normalized summary was reconstructed with authenticated read-only
GitHub API calls. No raw response, token, header, actor email, webhook URL, secret
name, environment name, installation identifier, or signed URL is retained.

| Surface | Observed state |
| --- | --- |
| Repository | `200lz/open-model-integration-validator`, PRIVATE, default `main` |
| Description, homepage, topics | Exact reviewed description and ten-topic set applied; homepage empty |
| Features | Issues and projects enabled; wiki and discussions disabled; not archived or a template |
| Actions | Enabled; default workflow permission `read`; workflow approval disabled |
| Workflows | One tracked CI workflow on GitHub-hosted Ubuntu for Python 3.11–3.14; GitHub also reports the managed Dependabot Updates and Dependency Graph workflows as active |
| Private vulnerability reporting | `API_STATE_UNAVAILABLE`; the private-repository status endpoint returned undifferentiated not-found, while reviewed official GitHub documentation limits enablement to public repositories |
| Dependabot alerts | `ENABLED_AND_VERIFIED`; status endpoint returned HTTP 204 |
| Dependabot security updates | `ENABLED_AND_VERIFIED`; automated security fixes reported enabled true and paused false |
| Secret scanning | `API_STATE_UNAVAILABLE` after return to PRIVATE; not classifiable as enabled or disabled |
| Push protection | `API_STATE_UNAVAILABLE` after return to PRIVATE; not classifiable as enabled or disabled |
| Code scanning | `NOT_CONFIGURED`; endpoint explicitly reported no configuration |
| Rulesets | `UNAVAILABLE_FOR_CURRENT_VISIBILITY_OR_PLAN` |
| Branch protection | `UNAVAILABLE_FOR_CURRENT_VISIBILITY_OR_PLAN` |
| Deploy keys, webhooks | Zero observed |
| Actions secrets, variables, environments | Zero observed; names were not requested or retained |
| Releases | Zero observed |
| Packages | Repository-scoped package state was not exposed by the inspected endpoint; `API_STATE_UNAVAILABLE` |
| Open pull requests, open issues | One open pull request and zero open issues observed; no content was retained |

This is an implementation-time observation, not a continuously refreshed claim.
R1F must re-read every mutable state before and after any authorized visibility
change.

## Security-control matrix

| Control | R1E observation | Required timing |
| --- | --- | --- |
| Private vulnerability reporting | `API_STATE_UNAVAILABLE` | `DEFERRED_TO_R1F`; enable and verify immediately after separately authorized public visibility |
| Dependabot alerts | `ENABLED_AND_VERIFIED` | Re-read before and after visibility; stop if the state is lost |
| Dependabot security updates | `ENABLED_AND_VERIFIED` | Re-read before and after visibility; stop if the state is lost |
| Secret scanning | `API_STATE_UNAVAILABLE` | Enable and verify immediately after public visibility makes it available |
| Push protection | `API_STATE_UNAVAILABLE` | Enable after secret scanning and verify immediately after visibility change |
| Code scanning | `NOT_CONFIGURED` | `DEFERRED_TO_SEPARATE_POST_PUBLIC_CHANGE`; no launch-time CodeQL workflow |
| Rulesets | `UNAVAILABLE_FOR_CURRENT_VISIBILITY_OR_PLAN` | Keep unconfigured; branch protection is the sole selected initial mechanism |
| Branch protection | `UNAVAILABLE_FOR_CURRENT_VISIBILITY_OR_PLAN` | Apply the exact reviewed payload immediately after visibility change |
| Actions default permissions | `ENABLED_AND_VERIFIED` | Preserve read-only default and no PR-approval permission |
| Action pinning | `ENABLED_AND_VERIFIED` | Preserve every official Action at a full commit SHA |
| Force-push protection | Unavailable with branch enforcement | Deny immediately after visibility change |
| Branch deletion protection | Unavailable with branch enforcement | Deny immediately after visibility change |

The private-repository 404 for private vulnerability reporting remains ambiguous: it
does not prove enabled, disabled, or public-only eligibility. The eligibility boundary
comes from [reviewed official GitHub documentation](https://docs.github.com/en/code-security/how-tos/report-and-fix-vulnerabilities/configure-vulnerability-reporting/configure-for-a-repository),
which describes owners and administrators enabling the feature for public
repositories. R1E therefore must not attempt this control while OMIV remains private.

Only the reviewed repository profile, topics, Dependabot alerts, and Dependabot
security updates are in the R1E private mutation set. Private vulnerability reporting,
secret scanning, push protection, branch/ruleset enforcement, force-push protection,
branch-deletion protection, and code scanning are outside that set. Public-only
required controls are applied immediately after a separately authorized visibility
change. An unavailable control is not enabled, and no plan restriction may be bypassed.

## Contribution ownership and dependency updates

[CODEOWNERS](../.github/CODEOWNERS) assigns all repository paths to `@200lz` and
contains no email address. It identifies the responsible reviewer; it does not by
itself enforce review.

[Dependabot configuration](../.github/dependabot.yml) covers only `pip` and
`github-actions`, targets `main`, and runs monthly with bounded open-PR limits. It
does not configure registries, credentials, private feeds, automatic merge, review
bypass, or CI bypass. An Action version proposal must still be reviewed and resolved
to an immutable full commit SHA before merge.

Merging the configuration may cause GitHub to begin monthly dependency checks and
open update pull requests; it does not approve or merge a dependency change. No
cross-ecosystem grouping is configured. The open-pull-request limits bound the two
streams to three pip and two Actions proposals at once, avoiding an unbounded update
burst while keeping each ecosystem independently reviewable.

Issue forms accept privacy-safe bug and feature reports. The issue chooser routes
security questions to [SECURITY.md](../SECURITY.md). GitHub private vulnerability
reporting is not currently verified or active and cannot be claimed before public
visibility. R1F must enable and read it back immediately after separately authorized
public visibility. Public issues must never contain vulnerability or exploit details,
credentials, customer data, private payloads, signed URLs, or unpatched reproduction
details. No email, funding link, or sales link is supplied.

## Workflow security

The tracked CI workflow has repository-level `contents: read` permissions. It uses
only GitHub-hosted `ubuntu-24.04` runners, has no `pull_request_target` trigger, does
not reference repository secrets, and pins official Actions to full 40-character
commit SHAs. Checkout does not persist credentials.

No workflow may gain write permissions or execute untrusted pull-request code with a
privileged event. Publication automation, if separately designed later, must not hold
write credentials while evaluating untrusted code.

## Public-main enforcement policy

After public visibility, normal changes to `main` require a pull request and the
successful Python 3.11, 3.12, 3.13, and 3.14 CI matrix. R1F selects branch protection
as the sole initial mechanism. It must not add an overlapping ruleset.

The exact required check names produced by the tracked workflow are `Python 3.11`,
`Python 3.12`, `Python 3.13`, and `Python 3.14`. R1F must re-read the check names from
the exact public-main CI run before applying protection; a renamed or missing check
is a stop condition.

The corrected write uses `APP_BOUND_CHECKS_WITH_CONTEXTS_OMITTED`: the request
contains `strict: true` and the four exact `checks` objects bound to GitHub Actions
App ID `15368`, and omits the `contexts` member entirely. Both PUT and GET explicitly
send `Accept: application/vnd.github+json` and
`X-GitHub-Api-Version: 2022-11-28`. GitHub may return a derived `contexts` list, but
that list must match the four names and cannot prove App binding; only returned
`checks[].app_id` does. Combining `contexts` and `checks`, falling back to contexts
alone, changing the version, or substituting a ruleset fails closed.

The enforcement must:

- deny force pushes and branch deletion;
- require linear history where supported;
- require zero approving reviews while `@200lz` is the sole maintainer, because an
  author cannot approve their own pull request and a one-review rule would make
  owner-authored changes impossible to merge;
- keep CODEOWNERS visible for ownership but do not require code-owner review until a
  second eligible maintainer exists;
- require conversation resolution where supported;
- keep administrator bypass emergency-only with a public audit trail;
- preserve read-only workflow permissions;
- prohibit self-hosted runners and `pull_request_target` for this workflow;
- require review and CI for Dependabot proposals.

The pull-request rule and four CI checks still gate normal changes. The zero-review
setting is not a claim of independent review. `@200lz` may inspect and merge a green
Dependabot pull request, but no update is automatic. Administrator bypass remains an
emergency-only exception with a public audit trail; it is not the normal merge path.
If another eligible maintainer is added, a later separately reviewed policy may raise
the approval count and enable required code-owner review.

Future release tags must be cryptographically signed under the release policy. The
nine legacy unsigned tags remain
`LEGACY_UNSIGNED_TAGS_ACCEPTED_WITH_LIMITATION`; they are not rewritten. A signature
authenticates a tag under a key but does not certify model safety, authenticity, or
evidence truth.

## Publication ordering

R1E first releases the reviewed files to private `main`, verifies the exact private CI
run, and may then apply and independently re-read only the four private-repository
mutations listed below. R1E cannot change visibility or execute any R1F control.

The later R1F visibility transaction has this mandatory order:

1. Verify private `main` at the exact green R1F commit.
2. Verify no concurrent remote-state change.
3. Verify separate explicit owner visibility authorization.
4. Verify one explicit owner rollback-authority decision.
5. Capture normalized pre-change remote state.
6. Change visibility from PRIVATE to PUBLIC.
7. Read back PUBLIC visibility immediately.
8. Enable Private Vulnerability Reporting.
9. Read back its enabled state.
10. Enable secret scanning.
11. Read back its enabled state.
12. Enable push protection.
13. Read back its enabled state.
14. Apply the exact reviewed `main` branch protection.
15. Read back every enforcement field and required check name.
16. Re-read repository profile, topics, Actions permissions, and Dependabot controls.
17. Verify no tag, release, or package was created.
18. Run an unauthenticated public-read smoke check.
19. Classify success only after every required read-back passes.

No tag, GitHub release, or PyPI operation may occur in this transaction. Each remains
a separate later operation requiring explicit authorization.

R1F must use live read-only API inspection and compare normalized state with the
policy. It must not rely solely on this document or on a prior successful run.

## R1E private controls applied

These reviewed operations were applied after the R1E private-main commit and exact CI
run succeeded, then independently read back. They are retained as a bounded historical
record, not executable policy data and not authorization to repeat a write. No token
value belongs in a command, file, log, or report.

| Control | Proposed command and request | Expected/read-back | Side effect, failure, and safe rollback |
| --- | --- | --- | --- |
| Description and feature profile | `gh api --method PATCH repos/200lz/open-model-integration-validator -f description='Offline-first evidence and verification framework for AI model artifacts, transformations, runtime identity, and provenance.' -f homepage='' -F has_issues=true -F has_wiki=false -F has_discussions=false` | HTTP 200; GET the repository and compare the exact five fields. Repeating the same request is idempotent. | Changes public-facing metadata even while private. Any non-200 or mismatch is `METADATA_MUTATION_FAILED`. Safe rollback to the observed state uses the same PATCH with empty description/homepage, issues true, wiki false, and discussions false. Projects are deliberately omitted and preserved. |
| Topics | `gh api --method PUT repos/200lz/open-model-integration-validator/topics -f 'names[]=ai-supply-chain' -f 'names[]=model-provenance' -f 'names[]=artifact-verification' -f 'names[]=model-integrity' -f 'names[]=supply-chain-security' -f 'names[]=mlops' -f 'names[]=llm' -f 'names[]=gguf' -f 'names[]=safetensors' -f 'names[]=offline-first'` | HTTP 200; GET `/topics` and compare the exact ordered set. Replacing with the same set is idempotent. | Replaces all topics. Any mismatch is `METADATA_MUTATION_FAILED`. The observed empty set can be restored with `printf '{"names":[]}' | gh api --method PUT repos/200lz/open-model-integration-validator/topics --input -`, but only when the prior empty state remains certain. |
| Dependabot alerts | `gh api --method PUT repos/200lz/open-model-integration-validator/vulnerability-alerts` | HTTP 204, then GET must return HTTP 204. Repeating PUT is idempotent. | Enables the dependency graph and vulnerability alerts. Failure is `SECURITY_CONTROL_MUTATION_FAILED`. A verified operation can be rolled back with `gh api --method DELETE repos/200lz/open-model-integration-validator/vulnerability-alerts`, but doing so also disables the dependency graph and requires explicit rollback authorization. |
| Dependabot security updates | `gh api --method PUT repos/200lz/open-model-integration-validator/automated-security-fixes` | HTTP 204, then GET must return HTTP 200 with `enabled: true`. Repeating PUT is idempotent. | May create future security-update pull requests; it does not approve or merge them. Apply only after alerts. A verified enable can be rolled back with `gh api --method DELETE repos/200lz/open-model-integration-validator/automated-security-fixes` under explicit rollback authorization. |

This is the complete R1E mutation set: PATCH the repository profile, PUT repository
topics, PUT Dependabot alerts, and PUT automated security fixes. R1E must not attempt
visibility, private vulnerability reporting, secret scanning, push protection,
branch protection, rulesets, force-push protection, branch-deletion protection, or
code scanning. The current private-reporting 404 remains
`API_STATE_UNAVAILABLE`; it is not reclassified as enabled or disabled.

## Controlled R1F and post-public plan

The [R1F final-publication audit](r1f-final-publication-audit.md) is the complete
reviewed operator procedure. It is not authorization and contains no reusable
mutation program. It requires exact green private `main`, separate visibility
authorization, and one explicit rollback-authority choice before the visibility
request. Branch protection is the selected sole initial enforcement mechanism.

Private Vulnerability Reporting, secret scanning, push protection, and branch
protection occur only after PUBLIC visibility reads back. Each write has its own
immediate read-back, and every failure preserves the normalized applied/unapplied
state. CodeQL is `CODEQL_DEFERRED_TO_SEPARATE_POST_PUBLIC_CHANGE`; current CI does not
replace CodeQL, and no unvalidated workflow is added for launch optics.

## Partial-application classifications

GitHub settings are not atomic. A future authorized operator must record one of
these fail-closed outcomes when the complete sequence does not verify:

| Classification | Meaning and required behavior |
| --- | --- |
| `FINAL_PRIVATE_AUDIT_FAILED` | No visibility write begins; correct only under separate authorization. |
| `VISIBILITY_AUTHORIZATION_MISSING` | Stop before visibility because implementation or audit permission is not publication permission. |
| `ROLLBACK_AUTHORITY_UNSPECIFIED` | Stop before visibility until exactly one owner choice is explicit. |
| `CONCURRENT_REMOTE_STATE_CHANGE` | Stop when any field differs from the pre-write snapshot or approved request; do not overwrite another actor's change. |
| `AUTHENTICATION_EXPIRED` | Stop without retrying writes under another identity; reauthorization is separate. |
| `VISIBILITY_MUTATION_FAILED` | Preserve private state and stop all later transaction operations. |
| `PUBLIC_VISIBILITY_READ_BACK_FAILED` | Treat visibility as ambiguous and do not apply public controls without verified PUBLIC state. |
| `PRIVATE_VULNERABILITY_REPORTING_ENABLE_FAILED` | Stop and record the public control as unapplied. |
| `SECRET_SCANNING_ENABLE_FAILED` | Stop and record secret scanning and its dependent controls as unapplied. |
| `PUSH_PROTECTION_ENABLE_FAILED` | Stop and record push protection and branch enforcement as unapplied. |
| `MAIN_ENFORCEMENT_APPLICATION_FAILED` | Stop without substituting an unreviewed ruleset or weaker payload. |
| `REQUIRED_CHECK_CONTEXT_MISMATCH` | Stop when any exact Python job context is absent, renamed, or extra in enforcement. |
| `PUBLIC_READ_BACK_VERIFICATION_FAILED` | Preserve exact normalized read-back and do not infer successful publication. |
| `UNAUTHENTICATED_PUBLIC_READ_FAILED` | Stop because public accessibility was not independently demonstrated. |
| `PUBLIC_VISIBILITY_CHANGED_REQUIRED_PUBLIC_CONTROL_FAILED` | Visibility is public but one or more required public controls did not verify; stop, do not announce/tag/release/publish, and preserve exact applied/unapplied read-back. |
| `VISIBILITY_ROLLBACK_FAILED` | Stop further mutation and preserve the exact externally observable state. |
| `PARTIAL_PUBLICATION_STATE` | Some writes applied but the final contract did not verify; no publication success may be claimed. |

Every partial outcome keeps tag creation, GitHub release creation, and PyPI
publication and announcement prohibited. No rollback is pre-authorized. Before the
first visibility write the owner must explicitly choose one of
`ROLLBACK_TO_PRIVATE_ON_REQUIRED_CONTROL_FAILURE_AUTHORIZED`,
`LEAVE_PUBLIC_AND_STOP_FOR_MANUAL_REMEDIATION`, or
`ROLLBACK_AUTHORITY_NOT_GRANTED`. The audit tool cannot choose. A return to private
cannot erase prior public observation, shared or indexed URLs, or changes to stars,
watchers, forks, repository networks, and security-control state.

## Stop and rollback conditions

Stop publication if repository identity, baseline, default branch, visibility,
description, topics, features, Actions permissions, CI, vulnerability reporting,
secret scanning, push protection, dependency security, or branch enforcement differs
from policy. Also stop for any secret, local path, private payload, unsafe workflow,
unreviewed bypass, or ambiguous API response.

If a post-public control cannot be applied, do not tag, create a release, or publish
to PyPI. Preserve evidence of the normalized failure without sensitive raw data and
request separate owner direction. A visibility rollback is itself a GitHub setting
mutation and requires explicit authorization; R1E does not authorize it.

Return to the [documentation index](README.md), [release process](releasing.md),
[security policy](../SECURITY.md), or [roadmap](roadmap.md).
