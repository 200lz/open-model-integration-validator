# Artifact Attestation: ACQUISITION

This is an integrity-checked structured claim. It is not a cryptographic signature or proof of issuer identity.

## Claim Summary

| Item | Result |
| --- | --- |
| Attestation | `att_495f2df4d5d3b25e86c7b281771813fc` |
| Claim | `ARTIFACT_OBTAINED` |
| Input formats | safetensors |
| Output formats | safetensors |
| Assertion origin | **DERIVED_FROM_VERIFIED_EVIDENCE** |
| Authenticity | **EVIDENCE_LINKED** |
| Issuer | **UNAVAILABLE** |
| Issuer authentication | **UNVERIFIED** |
| Actor authenticity | **UNVERIFIED** |
| Evidence linkage | **FULLY_VERIFIED** |
| Execution verification | **NOT_APPLICABLE** |
| Execution record integrity | **NOT_AVAILABLE** |
| Cryptographic signature | **NOT_AVAILABLE** |
| Attestation boundary | **UNSIGNED** |
| Artifact continuity | **VALID** |
| Provenance strength | **EVIDENCE_LINKED_PROVENANCE** |
| Custody materialization | **ELIGIBLE** |
| Custody event | `ARTIFACT_ACQUISITION_RECORDED` |
| Payload correctness | **NOT_CHECKED** |
| Numerical fidelity | **NOT_CHECKED** |
| Security | **NOT_CHECKED** |
| Runtime behavior | **NOT_CHECKED** |

A verified execution record links declared inputs, tool, configuration, and outputs. It does not prove numerical correctness, security, or runtime behavior.

## Limitations

- No issuer signature or actor authentication is present.
- The synthetic digest evidence links source and destination identities.

## Next Evidence Required

- issuer identity evidence
- payload or numerical fidelity evidence
- signed attestation (future phase)

## Integrity

- Attestation digest: `09e8c7f6709e6497052d88b92de9d021cd979f84a14119d8a2f430fed2ff4162`
- Report digest: `9cefefb6d6ef296fcce390bc5417c2ee62821b995d3f14feca7266cf342d8698`
