# OMIV Governance Report

- Report: `governance_report_7df36159dd1d1a5a27bcb27a11319ef3`
- Subject: `subject_08991da9b911f652087ec5813dfb65e8`
- Artifact digest: `80ffb3927d28091d7dcdba9bc5913f87008d8a2742ed9b82e6df71174240454f`
- Policy: `omiv.governance-policy.regulated_production_release.v1` (`7683cb1c7c983e041c90cf9103f20a1d35f790d7085ccb6d0812daaddc9c8130`)
- Policy decision: **DENY** under the selected policy
- Approval status: NOT_EVALUATED
- Logical promotion permission: **NOT_EVALUATED**
- Logical target: `NONE`
- Conditions: NONE
- Promotion performed: **NO**
- Registry write: **NOT_PERFORMED**
- Security evidence: **MISSING**
- Deployment performed: **NOT_PERFORMED**
- Runtime observation: **NOT_CHECKED**

A policy decision proves only that supplied evidence was evaluated against the named policy. It does not independently prove underlying claims. Promotion permission does not prove upload, deployment, or runtime observation.

## Evidence requirements

| Requirement | Category | Outcome | Blocking |
|---|---|---|---|
| `requirement_2d8ed8e14c49e55b3db92eb7a666cec6` | SECURITY_INSPECTION | MISSING | YES |
| `requirement_33b2578a9d68d525a2008db5463ccf31` | STRUCTURAL_VALIDATION | SATISFIED_WITH_LIMITATIONS | NO |
| `requirement_411fb249b90b4ea60be0b31c1e4f14a9` | ARTIFACT_IDENTITY | SATISFIED | NO |
| `requirement_55768c863afaf6d7de173a310a54697e` | RUNTIME_OBSERVATION | MISSING | YES |
| `requirement_6ce5dacac4a2594c6b3cb0cf9716fed7` | SIGNATURE_TRUST | SATISFIED | NO |
| `requirement_86d31fce4c18d74633619677de82c912` | ACQUISITION_ATTESTATION | SATISFIED | NO |
| `requirement_b24d857c248fa5e80ab96bb0fd5599da` | IMMUTABLE_REVISION | SATISFIED | NO |
| `requirement_bda759b101f89f28adb5e3131ced8867` | PAYLOAD_INTEGRITY | MISSING | YES |
| `requirement_f6ea7624ca946661a18b0ab3419d2ae2` | CUSTODY_INTEGRITY | SATISFIED | NO |

## Blockers

- `requirement_2d8ed8e14c49e55b3db92eb7a666cec6`
- `requirement_55768c863afaf6d7de173a310a54697e`
- `requirement_bda759b101f89f28adb5e3131ced8867`

## Missing evidence

- SECURITY_INSPECTION: MISSING; Phase 5F must provide verifiable artifact security evidence.
- RUNTIME_OBSERVATION: MISSING; Provide runtime observation evidence in Phase 5G.
- PAYLOAD_INTEGRITY: MISSING; Provide payload integrity evidence in a later phase.

## Limitations

- Approval status is scoped; it is not a security or deployment assertion.
- Policy evaluation does not prove security, deployment, or runtime state.
- Policy satisfaction does not independently prove underlying claims.
- Promotion permission does not prove upload, deployment, or runtime observation.
- Structural validation does not prove payload integrity or security.
