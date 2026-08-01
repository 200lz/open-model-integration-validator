# OMIV Governance Report

- Report: `governance_report_87d75594a599a51f094050d1d23633f7`
- Subject: `subject_08991da9b911f652087ec5813dfb65e8`
- Artifact digest: `80ffb3927d28091d7dcdba9bc5913f87008d8a2742ed9b82e6df71174240454f`
- Policy: `omiv.governance-policy.personal_local_use.v1` (`8b7e0822647149987e36c11f3d1ea9e042241fcdab759600734c9f86f5aa03db`)
- Policy decision: **ALLOW_WITH_LIMITATIONS** under the selected policy
- Approval status: NOT_EVALUATED
- Logical promotion permission: **NOT_EVALUATED**
- Logical target: `NONE`
- Conditions: NONE
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

## Blockers

- None

## Missing evidence

- SECURITY_INSPECTION: NOT_CHECKED; Phase 5F must provide verifiable artifact security evidence.

## Limitations

- Approval status is scoped; it is not a security or deployment assertion.
- Policy evaluation does not prove security, deployment, or runtime state.
- Policy satisfaction does not independently prove underlying claims.
- Promotion permission does not prove upload, deployment, or runtime observation.
- Structural validation does not prove payload integrity or security.
