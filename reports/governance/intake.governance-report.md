# OMIV Governance Report

- Report: `governance_report_edf5a06fa193d6c4c6a3561fa181372f`
- Subject: `subject_08991da9b911f652087ec5813dfb65e8`
- Artifact digest: `80ffb3927d28091d7dcdba9bc5913f87008d8a2742ed9b82e6df71174240454f`
- Policy: `omiv.governance-policy.team_artifact_intake.v1` (`2e4284a54638e8c5823fd9e6b8c6b14c335c49449f615d43c864aebfff4554b7`)
- Policy decision: **ALLOW_WITH_LIMITATIONS** under the selected policy
- Approval status: request `approval_request_bbb3c631d8f23f8425d3d83e2d6dd33d`; records=1; rejections=0
- Logical promotion permission: **PROMOTION_ALLOWED_WITH_CONDITIONS**
- Logical target: `target_ed3310f198fc897385e62d13099f1734`
- Conditions: Approval record remains applicable: approval_6f531c7f19e6859f0681db4bd50b4500
- Promotion performed: **NO**
- Registry write: **NOT_PERFORMED**
- Security evidence: **NOT_CHECKED**
- Deployment performed: **NOT_PERFORMED**
- Runtime observation: **NOT_CHECKED**

A policy decision proves only that supplied evidence was evaluated against the named policy. It does not independently prove underlying claims. Promotion permission does not prove upload, deployment, or runtime observation.

## Evidence requirements

| Requirement | Category | Outcome | Blocking |
|---|---|---|---|
| `requirement_3346551c587510b5ecd702feef2b9e8a` | SECURITY_INSPECTION | NOT_CHECKED | NO |
| `requirement_33b2578a9d68d525a2008db5463ccf31` | STRUCTURAL_VALIDATION | SATISFIED_WITH_LIMITATIONS | NO |
| `requirement_411fb249b90b4ea60be0b31c1e4f14a9` | ARTIFACT_IDENTITY | SATISFIED | NO |
| `requirement_6ce5dacac4a2594c6b3cb0cf9716fed7` | SIGNATURE_TRUST | SATISFIED | NO |
| `requirement_86d31fce4c18d74633619677de82c912` | ACQUISITION_ATTESTATION | SATISFIED | NO |
| `requirement_b24d857c248fa5e80ab96bb0fd5599da` | IMMUTABLE_REVISION | SATISFIED | NO |
| `requirement_f6ea7624ca946661a18b0ab3419d2ae2` | CUSTODY_INTEGRITY | SATISFIED | NO |

## Blockers

- None

## Missing evidence

- SECURITY_INSPECTION: NOT_CHECKED; Phase 5F must provide verifiable artifact security evidence.

## Limitations

- Approval status is scoped; it is not a security or deployment assertion.
- Policy evaluation does not prove security, deployment, or runtime state.
- Policy satisfaction does not independently prove underlying claims.
- Promotion allowed means policy permission only; no upload or deployment occurred.
- Promotion permission does not prove upload, deployment, or runtime observation.
- Structural validation does not prove payload integrity or security.
- This record does not execute promotion, registry upload, or deployment.
