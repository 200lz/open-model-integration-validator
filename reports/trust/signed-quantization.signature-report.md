# OMIV Signed Object Trust Report

- Object: `ARTIFACT_ATTESTATION` / `att_0dfa726b17bed80c3ea2a3ec271a6624`
- Canonical object digest: `ab2dc92765d977a73ccc4eec245201554528dbc4750c336777fa29a55cc39c9c`
- Policy: `omiv.trust-policy.project_maintainer_release.v1` / `c23e4a5b3efda351fc3b8c0f4cebdbc73f4e3b6e5b3d101db1e6df55e926dfe1`
- Trust bundle: `tb_2f473c8d4f367c0a89aa0d00e0f3d552` / `c761ca00f9365d19057579c52e24f96f70fac72d6b7acbba3ddd54f5ff191f88`
- Overall signed-object status: **TRUSTED_SIGNATURE_WITH_LIMITATIONS**
- Accepted signatures: 1

## Layered results

### Signature `sig_a0b4df74edc33027d53488f11784898d`

- Signature integrity: **VALID**
- Trusted by selected policy: **YES**
- Key identity/status: `key_ed39d828050734934fcf309c611f5d9b` / **KNOWN**
- Signer identity: **DECLARED**
- Signer identity verification: **UNVERIFIED**
- Signer/key binding: **VERIFIED_BY_TRUST_BUNDLE**
- Delegation: **DIRECT_ROOT**
- Revocation: **NOT_REVOKED**
- Expiration: **UNAVAILABLE**
- Policy trust: **TRUSTED_BY_POLICY**

## Claim-strength boundary

- Underlying claim: `{&quot;assertion_origin&quot;: &quot;VERIFIED_EXECUTION_RECORD&quot;, &quot;authenticity&quot;: &quot;EXECUTION_VERIFIED&quot;, &quot;evidence_linkage&quot;: &quot;FULLY_VERIFIED&quot;, &quot;execution_verification&quot;: &quot;VERIFIED&quot;, &quot;provenance_strength&quot;: &quot;ARTIFACT_SPECIFIC_PROVENANCE&quot;}`
- Underlying claim authenticity: **EXECUTION_VERIFIED**
- Underlying provenance strength: **ARTIFACT_SPECIFIC_PROVENANCE**
- Claim content independently proven: **NO**
- Payload integrity: **NOT_CHECKED**
- Numerical fidelity: **NOT_CHECKED**
- Security: **NOT_CHECKED**
- Runtime: **NOT_CHECKED**
- Approval: **NOT_AVAILABLE**
- Lifecycle completeness: **NOT_APPLICABLE**

A valid signature proves that the holder of the corresponding private key signed a specific canonical OMIV object. It does not by itself prove the underlying real-world claim is true.

## Limitations

- A valid signature proves that the corresponding private-key holder signed this canonical object; it does not prove the underlying claim is true.
- No payload, fidelity, security, runtime, approval, deployment, or complete-custody claim is created by signing.

Report digest: `1d58510ae703c0856c6977da18338bd446f59ecc3ce5237abd5b77bf225f7747`
