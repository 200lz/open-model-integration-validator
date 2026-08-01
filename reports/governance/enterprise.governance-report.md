# OMIV Governance Report

- Report: `governance_report_6496ba912733c642ca36d103464ac609`
- Subject: `subject_08991da9b911f652087ec5813dfb65e8`
- Artifact digest: `80ffb3927d28091d7dcdba9bc5913f87008d8a2742ed9b82e6df71174240454f`
- Policy: `omiv.governance-policy.enterprise_registry_promotion.v1` (`0872e0bf876556a2ef6ff3f2d938bd452d1388d52ec4cf84f4773d89de217e55`)
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
| `requirement_6ce5dacac4a2594c6b3cb0cf9716fed7` | SIGNATURE_TRUST | SATISFIED | NO |
| `requirement_86d31fce4c18d74633619677de82c912` | ACQUISITION_ATTESTATION | SATISFIED | NO |
| `requirement_b24d857c248fa5e80ab96bb0fd5599da` | IMMUTABLE_REVISION | SATISFIED | NO |
| `requirement_f6ea7624ca946661a18b0ab3419d2ae2` | CUSTODY_INTEGRITY | SATISFIED | NO |

## Blockers

- `requirement_2d8ed8e14c49e55b3db92eb7a666cec6`

## Missing evidence

- SECURITY_INSPECTION: MISSING; Phase 5F must provide verifiable artifact security evidence.

## Limitations

- Approval status is scoped; it is not a security or deployment assertion.
- Policy evaluation does not prove security, deployment, or runtime state.
- Policy satisfaction does not independently prove underlying claims.
- Promotion permission does not prove upload, deployment, or runtime observation.
- Structural validation does not prove payload integrity or security.
