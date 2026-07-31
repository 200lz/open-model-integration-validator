# Artifact Attestation: QUANTIZATION

This is an integrity-checked structured claim. It is not a cryptographic signature or proof of issuer identity.

## Claim Summary

| Item | Result |
| --- | --- |
| Attestation | `att_0dfa726b17bed80c3ea2a3ec271a6624` |
| Claim | `ARTIFACT_QUANTIZED` |
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
| Custody event | `QUANTIZATION_RECORDED` |
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

- Attestation digest: `3e1e9fe71025dd22e571cf3a4e4b59c08176a8174611522e0afe638e3e63a0a8`
- Report digest: `5c84e4fc92027ca22ae1611a07037f85a8c5a7f9c5b7558ceeed0c03cf6129cd`
