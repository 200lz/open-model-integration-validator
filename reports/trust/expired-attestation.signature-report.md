# OMIV Signed Object Trust Report

- Object: `ARTIFACT_ATTESTATION` / `att_4a6efa7aad56fc20f2b840688c0756db`
- Canonical object digest: `c3978007ace5620f1b324a2577c3063f6d4b3d329e58e76afd8795414c03216a`
- Policy: `omiv.trust-policy.enterprise_offline_release.v1` / `79e162e42d59c96fa265b0187d1617dc687b82d3f595dc03d5049435d21f7e16`
- Trust bundle: `tb_5d6ca713cb2245f8482449bad5b5532a` / `b952e2888e78d9cfa042316a45772e11643796a4e081a81c95cd9cbea4277760`
- Overall signed-object status: **EXPIRED**
- Accepted signatures: 0

## Layered results

### Signature `sig_a53b630ba387f24d456da5e48431da5c`

- Signature integrity: **VALID**
- Trusted by selected policy: **NO**
- Key identity/status: `key_ed39d828050734934fcf309c611f5d9b` / **EXPIRED**
- Signer identity: **DECLARED**
- Signer identity verification: **UNVERIFIED**
- Signer/key binding: **VERIFIED_BY_TRUST_BUNDLE**
- Delegation: **DIRECT_ROOT**
- Revocation: **NOT_REVOKED**
- Expiration: **EXPIRED**
- Policy trust: **PARTIALLY_TRUSTED**

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

Report digest: `c671a0ab99a5cd6c52a5d0a676f0912e6faab4d60d5d411fca13f85ada7616c5`
