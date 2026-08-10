# R1F final-publication audit and visibility transaction

This is a deterministic operator contract for a future, separately authorized OMIV
visibility transaction. It is Release Track configuration, not OMIV evidence, not a
security certification, and not authorization to mutate GitHub.

The R1F baseline is private. Live GitHub visibility is authoritative after any later
transaction. Public availability would not tag or release version 0.10.0, publish a
package to PyPI, implement Phase 6F, or establish that every security risk is covered.

## Preconditions and owner decisions

Before a visibility request, the operator must verify all of the following:

- private `main` equals the exact reviewed R1F release commit;
- the exact push-triggered R1F CI run is green for `Python 3.11`, `Python 3.12`,
  `Python 3.13`, and `Python 3.14`;
- repository identity, default branch, profile, topics, features, Actions permissions,
  Dependabot controls, releases, and public-only security controls match policy;
- no concurrent remote-state change occurred;
- the owner separately and explicitly authorized `PRIVATE` to `PUBLIC` visibility;
- the owner explicitly selected exactly one rollback choice below.

Implementation, audit, private release, or an earlier metadata-control authorization
does not satisfy the visibility-authorization requirement.

The allowed rollback choices are:

- `ROLLBACK_TO_PRIVATE_ON_REQUIRED_CONTROL_FAILURE_AUTHORIZED`
- `LEAVE_PUBLIC_AND_STOP_FOR_MANUAL_REMEDIATION`
- `ROLLBACK_AUTHORITY_NOT_GRANTED`

There is no default. No script or auditor may choose one. A rollback can occur only
when the future transaction instruction selected the first choice before visibility
changed and the live state remains sufficiently unambiguous for that authorized
operation.

A rollback does not erase exposure. Public observation may already have occurred;
URLs may have been shared or indexed; stars, watchers, forks, and repository-network
relationships may change; Actions history may have become visible; Pages or packages
may have been exposed; links or announcements may have propagated; and security-control
state may not revert automatically.

## Final public-state contract

A successful transaction must independently read back this complete state:

| Surface | Required state |
| --- | --- |
| Repository | `200lz/open-model-integration-validator` |
| Visibility | `PUBLIC` |
| Default branch | `main` |
| Main identity | Exact R1F release commit |
| Description | Exact description in `.github/publication-policy.json` |
| Homepage | Empty |
| Topics | Exact reviewed ten-topic set |
| Features | Issues/projects enabled; wiki/discussions disabled |
| Actions | Default token `read`; workflow PR approval disabled |
| CI | Exact R1F `main` SHA, push event, all four Python jobs successful |
| Dependabot | Alerts and automated security updates enabled and verified |
| Private Vulnerability Reporting | Enabled and verified after PUBLIC read-back |
| Secret scanning | Enabled and verified after PUBLIC read-back |
| Push protection | Enabled and verified after secret scanning |
| Main enforcement | Exact branch protection enabled and verified |
| Force push / deletion | Both prohibited |
| Releases | Zero |
| PyPI | Not published |
| Phase 6F | Planned, not implemented |

Every remote setting is established by live read-back, not by documentation. No tag,
GitHub release, package publication, or announcement is part of this transaction.

## Exact controlled transaction

The future operator must execute these steps in order and stop on the first failed or
ambiguous write/read-back:

1. Verify private `main` at the exact green R1F commit.
2. Verify no concurrent remote-state change.
3. Verify explicit owner visibility authorization.
4. Verify one explicit owner rollback-authority decision.
5. Capture normalized pre-change remote state without tokens, headers, emails, secret
   names, webhook URLs, environment names, signed URLs, or raw API bodies.
6. Change visibility from `PRIVATE` to `PUBLIC` using only the repository visibility
   field.
7. Read back `PUBLIC` visibility immediately.
8. Enable Private Vulnerability Reporting through its official repository endpoint.
9. Read back `enabled: true` from that control.
10. Enable `security_and_analysis.secret_scanning.status=enabled`.
11. Read back secret scanning as enabled.
12. Enable `security_and_analysis.secret_scanning_push_protection.status=enabled`.
13. Read back push protection as enabled.
14. Apply the exact reviewed `main` branch-protection payload below.
15. Read back every enforcement field, the four exact required check names, and the
    GitHub Actions App binding on each check.
16. Re-read repository profile, topics, features, Actions permissions, Dependabot
    alerts, and automated security updates.
17. Verify that no tag, GitHub release, or package was created.
18. From an unauthenticated context, verify that the repository and root README are
    publicly readable without following a signed or credential-bearing URL.
19. Classify public-launch readiness only after all required read-backs pass.

Private Vulnerability Reporting must follow verified PUBLIC visibility. Secret
scanning must follow the reporting read-back; push protection must follow secret
scanning; main enforcement must follow push protection. Reordering is invalid.

### Reviewed remote requests — do not execute without separate authorization

These are the exact reviewed operator requests, not an executable script or present
authorization. Each write requires repository Administration permission. Stop after
any non-success response or read-back mismatch; do not broaden token permissions,
substitute an endpoint, or continue to a dependent control.

**Visibility.** Change only the visibility field, expect HTTP 200, then require repository GET to
   return exact `PUBLIC` visibility before continuing:

   ```bash
   printf '{"visibility":"public"}' | gh api --method PATCH \
     repos/200lz/open-model-integration-validator --input -
   gh api repos/200lz/open-model-integration-validator --jq .visibility
   ```

   A write failure is `VISIBILITY_MUTATION_FAILED`; a read-back mismatch is
   `PUBLIC_VISIBILITY_READ_BACK_FAILED`. Visibility rollback is not implicit.

**Private reporting.** Only after PUBLIC read-back, enable and verify Private Vulnerability Reporting;
   expect HTTP 204 from PUT and HTTP 200 with `enabled: true` from GET:

   ```bash
   gh api --method PUT \
     repos/200lz/open-model-integration-validator/private-vulnerability-reporting
   gh api repos/200lz/open-model-integration-validator/private-vulnerability-reporting \
     --jq .enabled
   ```

   Failure is `PRIVATE_VULNERABILITY_REPORTING_ENABLE_FAILED` and also
   `PUBLIC_VISIBILITY_CHANGED_REQUIRED_PUBLIC_CONTROL_FAILED`.

**Secret scanning.** Only after the reporting read-back, enable secret scanning, expect HTTP 200, and
   require repository GET to report the exact enabled state:

   ```bash
   printf '{"security_and_analysis":{"secret_scanning":{"status":"enabled"}}}' | \
     gh api --method PATCH repos/200lz/open-model-integration-validator --input -
   gh api repos/200lz/open-model-integration-validator \
     --jq .security_and_analysis.secret_scanning.status
   ```

   Failure is `SECRET_SCANNING_ENABLE_FAILED` and blocks push protection.

**Push protection.** Only after secret-scanning read-back, enable push protection, expect HTTP 200,
   and require repository GET to report the exact enabled state:

   ```bash
   printf '{"security_and_analysis":{"secret_scanning_push_protection":{"status":"enabled"}}}' | \
     gh api --method PATCH repos/200lz/open-model-integration-validator --input -
   gh api repos/200lz/open-model-integration-validator \
     --jq .security_and_analysis.secret_scanning_push_protection.status
   ```

   Failure is `PUSH_PROTECTION_ENABLE_FAILED` and blocks main enforcement.

**Main enforcement.** Only after push-protection read-back, apply the branch-protection request below,
   expect HTTP 200, and GET the same branch-protection endpoint to compare every
   reviewed field and every check/app binding. Failure is
   `MAIN_ENFORCEMENT_APPLICATION_FAILED`; a check source/name mismatch is
   `REQUIRED_CHECK_CONTEXT_MISMATCH`.

## Selected main enforcement

R1F selects branch protection, not a ruleset, as the sole initial mechanism. The
official operation is `PUT` on the `main` branch-protection endpoint with this exact
request body:

```json
{
  "required_status_checks": {
    "strict": true,
    "contexts": [],
    "checks": [
      {"context": "Python 3.11", "app_id": 15368},
      {"context": "Python 3.12", "app_id": 15368},
      {"context": "Python 3.13", "app_id": 15368},
      {"context": "Python 3.14", "app_id": 15368}
    ]
  },
  "enforce_admins": false,
  "required_pull_request_reviews": {
    "dismiss_stale_reviews": false,
    "require_code_owner_reviews": false,
    "required_approving_review_count": 0,
    "require_last_push_approval": false
  },
  "restrictions": null,
  "required_linear_history": true,
  "allow_force_pushes": false,
  "allow_deletions": false,
  "required_conversation_resolution": true
}
```

The exact check names match the matrix job names observed on the green R1E CI run and
the tracked workflow declaration. The Checks API reported every one of those runs as
originating from the GitHub Actions App with ID `15368`. Binding each required check
to that observed app prevents another status provider with write access from
satisfying the same context name. The endpoint schema still requires `contexts`, so
it is an explicit empty array; the four app-bound requirements live only in `checks`
and are not duplicated as unbound contexts. The future operator must re-verify both the names
and app identity against the exact green R1F run before applying this payload; a
renamed or missing check, an app mismatch, or an unbound/extra required context is
`REQUIRED_CHECK_CONTEXT_MISMATCH`. The numeric ID is repository policy only because
it was read from the official Checks API; it must not be guessed or silently updated.

Zero approving reviews and disabled required code-owner review are necessary for the
initial single-maintainer preview: `@200lz` cannot provide independent approval for
their own change. Pull requests, strict required CI, conversation resolution, and
linear history still govern normal changes. `enforce_admins: false` leaves an
emergency administrator bypass; it is not routine review evidence, and any use needs
a public audit trail. CODEOWNERS remains ownership metadata.

Do not configure an overlapping ruleset. If branch protection cannot be applied and
read back exactly, stop with `MAIN_ENFORCEMENT_APPLICATION_FAILED`; do not substitute
an unreviewed mechanism or weaker payload.

## Failure and partial-publication behavior

These exact classifications are fail closed:

- `FINAL_PRIVATE_AUDIT_FAILED`
- `VISIBILITY_AUTHORIZATION_MISSING`
- `ROLLBACK_AUTHORITY_UNSPECIFIED`
- `CONCURRENT_REMOTE_STATE_CHANGE`
- `AUTHENTICATION_EXPIRED`
- `VISIBILITY_MUTATION_FAILED`
- `PUBLIC_VISIBILITY_READ_BACK_FAILED`
- `PRIVATE_VULNERABILITY_REPORTING_ENABLE_FAILED`
- `SECRET_SCANNING_ENABLE_FAILED`
- `PUSH_PROTECTION_ENABLE_FAILED`
- `MAIN_ENFORCEMENT_APPLICATION_FAILED`
- `REQUIRED_CHECK_CONTEXT_MISMATCH`
- `PUBLIC_READ_BACK_VERIFICATION_FAILED`
- `UNAUTHENTICATED_PUBLIC_READ_FAILED`
- `PUBLIC_VISIBILITY_CHANGED_REQUIRED_PUBLIC_CONTROL_FAILED`
- `VISIBILITY_ROLLBACK_FAILED`
- `PARTIAL_PUBLICATION_STATE`

Every failure stops subsequent non-remediation operations, prohibits announcement,
tag, GitHub release, and PyPI publication, records applied and unapplied controls,
retains exact normalized read-back, avoids a false success classification, and
requires separate remediation authority.

If visibility is public and a required public control fails, also classify
`PUBLIC_VISIBILITY_CHANGED_REQUIRED_PUBLIC_CONTROL_FAILED`. A rollback is attempted
only if it was explicitly authorized before visibility changed. Otherwise leave the
exact state unchanged and stop for owner-directed remediation. Never broaden token
permissions, switch endpoints, or infer a successful write from a response alone.

## Security reporting boundary

The private baseline does not have a verified Private Vulnerability Reporting
channel. After PUBLIC visibility, the channel must be enabled and read back before
publication can succeed. If **Security → Report a vulnerability** is unavailable, do
not place vulnerability or exploit details, credentials, customer data, private
payloads, signed URLs, raw headers, or reproduction details in a public issue. There
is no email fallback and no response-time promise.

## CodeQL decision

`CODEQL_DEFERRED_TO_SEPARATE_POST_PUBLIC_CHANGE`

Code scanning is unavailable under the current private plan, and an unvalidated
workflow is not added for launch optics. Existing Ruff, Mypy, compileall, and Python
3.11–3.14 tests provide useful but different coverage and do not replace CodeQL. A
later protected public pull request may review languages, queries, triggers,
permissions, runner isolation, false-positive handling, and alert response.

## Audit and package boundary

`tools/audit_r1f_publication_readiness.py` is offline, read-only, deterministic, and
contains no GitHub mutation executor. It validates repository-controlled policy and
documentation only; live remote state requires a separate read-only operator audit.
The policy and operator documentation may enter the source distribution according to
existing package rules, but workflow files, tests, and audit utilities are not runtime
package modules. No API response or security-setting snapshot is packaged.

Return to the [documentation index](README.md), [GitHub publication controls](github-publication-controls.md),
[security policy](../SECURITY.md), [release process](releasing.md), or
[roadmap](roadmap.md).
