# Artifact Attestation: ACQUISITION

This is an integrity-checked structured claim. It is not a cryptographic signature or proof of issuer identity.

## Claim Summary

| Item | Result |
| --- | --- |
| Attestation | `att_4f1bdb5f184f99c81341c00d55b6a2b4` |
| Claim | `ARTIFACT_OBTAINED` |
| Input formats | safetensors |
| Output formats | safetensors |
| Assertion origin | **USER_DECLARED** |
| Authenticity | **DECLARED** |
| Issuer | **UNAVAILABLE** |
| Issuer authentication | **UNVERIFIED** |
| Actor authenticity | **UNVERIFIED** |
| Evidence linkage | **UNAVAILABLE** |
| Execution verification | **NOT_APPLICABLE** |
| Execution record integrity | **NOT_AVAILABLE** |
| Cryptographic signature | **NOT_AVAILABLE** |
| Attestation boundary | **UNSIGNED** |
| Artifact continuity | **VALID** |
| Provenance strength | **DECLARED_PROVENANCE** |
| Custody materialization | **ELIGIBLE** |
| Custody event | `ARTIFACT_ACQUISITION_RECORDED` |
| Payload correctness | **NOT_CHECKED** |
| Numerical fidelity | **NOT_CHECKED** |
| Security | **NOT_CHECKED** |
| Runtime behavior | **NOT_CHECKED** |

A verified execution record links declared inputs, tool, configuration, and outputs. It does not prove numerical correctness, security, or runtime behavior.

## Declared Acquisition Boundary

Acquisition claim recorded.

- Claim basis: **USER_DECLARED**
- Evidence status: **UNAVAILABLE**
- Custody event authenticity: **UNATTESTED**
- Payload equality: **NOT_CHECKED**

## Limitations

- Payload equality was not checked.
- The acquisition action is user-declared and not independently observed.

## Next Evidence Required

- fully reconstructable claim evidence
- issuer identity evidence
- payload or numerical fidelity evidence
- signed attestation (future phase)

## Integrity

- Attestation digest: `5d7a5b8b479cd34d398dfa923dc1965ed0216e97d15ec078af6647157a741267`
- Report digest: `ac19db80c85b5c5223ba25b1338d842355348740340c76c47fa36e93425b953a`
