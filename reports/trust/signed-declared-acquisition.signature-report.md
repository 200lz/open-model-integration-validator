# OMIV Signed Object Trust Report

- Object: `ARTIFACT_ATTESTATION` / `att_4f1bdb5f184f99c81341c00d55b6a2b4`
- Canonical object digest: `a3c7bac4b65e134b20a749c0780a764305d628c7128bee87218de2ade24fdb47`
- Policy: `omiv.trust-policy.project_maintainer_release.v1` / `c23e4a5b3efda351fc3b8c0f4cebdbc73f4e3b6e5b3d101db1e6df55e926dfe1`
- Trust bundle: `tb_2f473c8d4f367c0a89aa0d00e0f3d552` / `c761ca00f9365d19057579c52e24f96f70fac72d6b7acbba3ddd54f5ff191f88`
- Overall signed-object status: **TRUSTED_SIGNATURE_WITH_LIMITATIONS**
- Accepted signatures: 1

## Layered results

### Signature `sig_67d3029b216690619e4d179f2d870932`

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

- Underlying claim: `{&quot;assertion_origin&quot;: &quot;USER_DECLARED&quot;, &quot;authenticity&quot;: &quot;DECLARED&quot;, &quot;evidence_linkage&quot;: &quot;UNAVAILABLE&quot;, &quot;execution_verification&quot;: &quot;NOT_APPLICABLE&quot;, &quot;provenance_strength&quot;: &quot;DECLARED_PROVENANCE&quot;}`
- Underlying claim authenticity: **DECLARED**
- Underlying provenance strength: **DECLARED_PROVENANCE**
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

Report digest: `b73aaedb238fb59adf02ddcd6ac7e8a1e1cd5fd65176e2cd549d7665d7d7417a`
