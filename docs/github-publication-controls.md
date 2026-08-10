# GitHub publication controls

This document defines the reviewable repository state required before OMIV can
become public. It is Release Track configuration, not OMIV evidence and not a
security certification. The machine-readable companion is
[`.github/publication-policy.json`](../.github/publication-policy.json).

The repository is still **PRIVATE**. Version 0.10.0 is untagged and unreleased;
there is no GitHub release or PyPI publication. This document does not authorize a
visibility or settings change.

## Desired repository profile

The profile to apply immediately before a separately authorized visibility change
is deterministic:

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

## Read-only state observed during R1E

The following normalized summary was reconstructed with authenticated read-only
GitHub API calls. No raw response, token, header, actor email, webhook URL, secret
name, environment name, installation identifier, or signed URL is retained.

| Surface | Observed state |
| --- | --- |
| Repository | `200lz/open-model-integration-validator`, PRIVATE, default `main` |
| Description, homepage, topics | Empty; desired values are proposed, not applied |
| Features | Issues and projects enabled; wiki and discussions disabled; not archived or a template |
| Actions | Enabled; default workflow permission `read`; workflow approval disabled |
| Workflows | One active workflow; GitHub-hosted Ubuntu runner; Python 3.11–3.14 |
| Private vulnerability reporting | `API_STATE_UNAVAILABLE`; the private-repository status endpoint returned undifferentiated not-found, while reviewed official GitHub documentation limits enablement to public repositories |
| Dependabot alerts | `DISABLED`; endpoint explicitly reported disabled |
| Dependabot security updates | `DISABLED`; automated security fixes reported false |
| Secret scanning | `DISABLED`; endpoint explicitly reported disabled |
| Push protection | `NOT_CONFIGURED`; secret scanning prerequisite is disabled |
| Code scanning | `NOT_CONFIGURED`; endpoint explicitly reported no configuration |
| Rulesets | `UNAVAILABLE_FOR_CURRENT_VISIBILITY_OR_PLAN` |
| Branch protection | `UNAVAILABLE_FOR_CURRENT_VISIBILITY_OR_PLAN` |
| Deploy keys, webhooks | Zero observed |
| Actions secrets, variables, environments | Zero observed; names were not requested or retained |
| Releases | Zero observed |
| Packages | Repository-scoped package state was not exposed by the inspected endpoint; `API_STATE_UNAVAILABLE` |
| Open pull requests, open issues | Zero observed |

This is an implementation-time observation, not a continuously refreshed claim.
R1F must re-read every mutable state before and after any authorized visibility
change.

## Security-control matrix

| Control | R1E observation | Required timing |
| --- | --- | --- |
| Private vulnerability reporting | `API_STATE_UNAVAILABLE` | `DEFERRED_TO_R1F`; enable and verify immediately after separately authorized public visibility |
| Dependabot alerts | `DISABLED` | Enable and verify immediately before public visibility |
| Dependabot security updates | `DISABLED` | Enable after alerts and verify immediately before public visibility |
| Secret scanning | `DISABLED` | Enable and verify immediately after public visibility makes it available |
| Push protection | `NOT_CONFIGURED` | Enable with secret scanning and verify immediately after visibility change |
| Code scanning | `NOT_CONFIGURED` | `DEFERRED_TO_R1F`; explicitly review language, queries, events, and permissions |
| Rulesets | `UNAVAILABLE_FOR_CURRENT_VISIBILITY_OR_PLAN` | Apply immediately after visibility change |
| Branch protection | `UNAVAILABLE_FOR_CURRENT_VISIBILITY_OR_PLAN` | Use as the equivalent enforcement path if rulesets cannot express the policy |
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
successful Python 3.11, 3.12, 3.13, and 3.14 CI matrix. The preferred mechanism is a
repository ruleset; equivalent branch protection is acceptable if it expresses the
same policy.

The exact required check names produced by the tracked workflow are `Python 3.11`,
`Python 3.12`, `Python 3.13`, and `Python 3.14`. R1F must re-read the check names from
the exact public-main CI run before applying protection; a renamed or missing check
is a stop condition.

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

1. Complete the final private-state R1F audit.
2. Obtain explicit owner authorization for the visibility change.
3. Record the exact pre-change remote state.
4. Change visibility from PRIVATE to PUBLIC.
5. Immediately enable and verify Private Vulnerability Reporting.
6. Immediately enable and verify secret scanning.
7. Immediately enable and verify push protection.
8. Immediately apply and verify the reviewed `main` branch rule or protection.
9. Re-read visibility, default branch, metadata, topics, Actions permissions,
   vulnerability reporting, dependency controls, secret scanning, push protection,
   and branch enforcement.
10. Only after every required control verifies may R1F classify the repository as
    public-launch ready.

No tag, GitHub release, or PyPI operation may occur in this transaction. Each remains
a separate later operation requiring explicit authorization.

R1F must use live read-only API inspection and compare normalized state with the
policy. It must not rely solely on this document or on a prior successful run.

## Unexecuted R1E mutation plan

These commands are a review plan, not executable policy data and not authorization.
They must be run only by a separately authorized R1E release operation after the
private-main commit and exact CI run succeed. Each write needs repository
Administration permission; classic tokens need `repo`. No token value belongs in a
command, file, log, or report.

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

## Deferred R1F and post-public plan

This plan is not authorization and R1E cannot execute it. R1F must first complete the
private-state audit, obtain explicit owner authorization, record the pre-change state,
and use `PATCH /repos/200lz/open-model-integration-validator` with
`{"visibility":"public"}`. Expect HTTP 200, then re-read exact `PUBLIC` visibility.
The write needs repository Administration permission, exposes the repository, and is
not treated as safely reversible by default. Before issuing it, the R1F instruction
must explicitly decide whether a later rollback to PRIVATE is authorized.

Only after visibility reads back as PUBLIC, R1F performs these bounded operations in
order, before any tag, release, or PyPI action:

1. Enable Private Vulnerability Reporting with
   `PUT /repos/200lz/open-model-integration-validator/private-vulnerability-reporting`
   using Administration write permission. Expect HTTP 204, then require GET of the
   same endpoint to return HTTP 200 with `enabled: true`. Its private-repository 404
   remains an ambiguous prior observation; reviewed official GitHub documentation is
   the authority for public-only eligibility. A failed write or read-back is
   `PUBLIC_VISIBILITY_CHANGED_REQUIRED_PUBLIC_CONTROL_FAILED`.

2. Enable `security_and_analysis.secret_scanning.status=enabled` with
   `PATCH /repos/200lz/open-model-integration-validator` using Administration write
   permission. Expect HTTP 200 and re-read secret scanning as enabled before
   proceeding. This request is idempotent for the same fields; failure is
   `PUBLIC_VISIBILITY_CHANGED_REQUIRED_PUBLIC_CONTROL_FAILED`.

   ```bash
   gh api --method PATCH repos/200lz/open-model-integration-validator --input - <<'JSON'
   {"security_and_analysis":{"secret_scanning":{"status":"enabled"}}}
   JSON
   ```

3. Enable push protection with the same official repository PATCH field and require
   read-back of `secret_scanning_push_protection.status=enabled`. This must follow
   verified secret scanning.
   Failure is `PUBLIC_VISIBILITY_CHANGED_REQUIRED_PUBLIC_CONTROL_FAILED`.

   ```bash
   gh api --method PATCH repos/200lz/open-model-integration-validator --input - <<'JSON'
   {"security_and_analysis":{"secret_scanning_push_protection":{"status":"enabled"}}}
   JSON
   ```

4. Apply `PUT /repos/200lz/open-model-integration-validator/branches/main/protection`
   with required status checks `Python 3.11` through `Python 3.14`, strict checks,
   pull requests required, zero approving reviews, code-owner reviews false,
   conversation resolution true, linear history true, force pushes false, deletion
   false, and restrictions null. Expect HTTP 200 and verify every returned field.
   Administrator enforcement remains false solely for the documented emergency
   bypass. If a repository ruleset can express all fields, a reviewed equivalent
   active ruleset may be used instead; never configure both ambiguously.

   ```bash
   gh api --method PUT repos/200lz/open-model-integration-validator/branches/main/protection --input - <<'JSON'
   {"required_status_checks":{"strict":true,"contexts":["Python 3.11","Python 3.12","Python 3.13","Python 3.14"]},"enforce_admins":false,"required_pull_request_reviews":{"dismiss_stale_reviews":false,"require_code_owner_reviews":false,"required_approving_review_count":0,"require_last_push_approval":false},"restrictions":null,"required_linear_history":true,"allow_force_pushes":false,"allow_deletions":false,"required_conversation_resolution":true}
   JSON
   ```
5. Re-read rulesets, branch protection, visibility, default branch, profile, topics,
   features, Actions
   permissions, secret scanning, push protection, private reporting, Dependabot
   alerts, and security updates. A missing or different field stops publication.
6. Decide separately whether to add CodeQL. No CodeQL workflow is currently
   configured. R1F must review languages, queries, events, runner, permissions, and
   false-positive handling before any implementation.

The required read-back must verify Private Vulnerability Reporting, secret scanning,
push protection, and branch enforcement before public-launch readiness. Branch
enforcement is applied immediately after visibility because the current endpoint
explicitly requires GitHub Pro or public visibility. No plan or visibility workaround
is permitted. A control failure stops immediately: do not announce, tag, create a
GitHub release, or publish to PyPI; record applied and unapplied controls and preserve
the exact normalized read-back.

## Partial-application classifications

GitHub settings are not atomic. A future authorized operator must record one of
these fail-closed outcomes when the complete sequence does not verify:

| Classification | Meaning and required behavior |
| --- | --- |
| `LOCAL_OR_CI_FAILURE_BEFORE_REMOTE_MUTATION` | No remote writes begin; correct only under separate authorization. |
| `METADATA_MUTATION_FAILED` | Stop remaining metadata/security writes unless an explicitly reviewed continuation is safer; report exact applied and unapplied fields. |
| `SECURITY_CONTROL_MUTATION_FAILED` | Stop before visibility, tag, release, or PyPI; do not claim the control enabled. |
| `PARTIAL_REMOTE_APPLICATION` | Preserve normalized read-back, avoid ambiguous destructive rollback, and request separate correction authorization. |
| `READ_BACK_VERIFICATION_FAILED` | Treat the write as ambiguous even if its response succeeded; do not infer the resulting state. |
| `CONCURRENT_REMOTE_STATE_CHANGE` | Stop when any field differs from the pre-write snapshot or approved request; do not overwrite another actor's change. |
| `UNEXPECTED_VISIBILITY_CHANGE` | Stop immediately; do not mutate further controls or attempt an unauthorized visibility rollback. |
| `PUBLIC_VISIBILITY_CHANGED_REQUIRED_PUBLIC_CONTROL_FAILED` | Visibility is public but one or more required public controls did not verify; stop, do not announce/tag/release/publish, and preserve exact applied/unapplied read-back. |
| `PLAN_RESTRICTED_CONTROL` | Record the exact endpoint limitation; apply only at its approved post-public phase or stop if still unavailable. |
| `AUTHENTICATION_EXPIRED` | Stop without retrying writes under another identity; reauthorization is separate. |

Every partial outcome keeps tag creation, GitHub release creation, and PyPI
publication prohibited. A rollback is a new mutation: perform it only when the prior
and current states are unambiguous, the rollback is safe, and the owner separately
authorizes it. R1E does not silently authorize a future visibility rollback. The R1F
instruction must decide rollback authority before changing visibility because a
second visibility change may itself be externally observable.

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
