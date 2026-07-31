# Artifact Attestation: TRANSFORMATION

This is an integrity-checked structured claim. It is not a cryptographic signature or proof of issuer identity.

## Claim Summary

| Item | Result |
| --- | --- |
| Attestation | `att_4a6efa7aad56fc20f2b840688c0756db` |
| Claim | `ARTIFACT_CONVERTED` |
| Input formats | safetensors |
| Output formats | gguf |
| Assertion origin | **VERIFIED_EXECUTION_RECORD** |
| Authenticity | **EXECUTION_VERIFIED** |
| Issuer | **UNAVAILABLE** |
| Issuer authentication | **UNVERIFIED** |
| Actor authenticity | **UNVERIFIED** |
| Evidence linkage | **FULLY_VERIFIED** |
| Execution verification | **VERIFIED** |
| Execution record integrity | **VERIFIED** |
| Cryptographic signature | **NOT_AVAILABLE** |
| Attestation boundary | **UNSIGNED** |
| Artifact continuity | **VALID** |
| Provenance strength | **ARTIFACT_SPECIFIC_PROVENANCE** |
| Custody materialization | **ELIGIBLE** |
| Custody event | `TRANSFORMATION_RECORDED` |
| Payload correctness | **NOT_CHECKED** |
| Numerical fidelity | **NOT_CHECKED** |
| Security | **NOT_CHECKED** |
| Runtime behavior | **NOT_CHECKED** |

A verified execution record links declared inputs, tool, configuration, and outputs. It does not prove numerical correctness, security, or runtime behavior.

## Limitations

- Numerical fidelity was not checked.
- Payload correctness was not checked.
- Runtime compatibility was not checked.
- The execution record is unsigned and does not authenticate an issuer.

## Next Evidence Required

- issuer identity evidence
- payload or numerical fidelity evidence
- signed attestation (future phase)

## Integrity

- Attestation digest: `ef3d56a52e87bfaeea3d5f5c6e64a719c590897fe9580349bdcb58177d833024`
- Report digest: `0d782ccfc7014d8d14c304b6e0b3ce2cd23fef25fdfe39dd05738880b36c9635`
