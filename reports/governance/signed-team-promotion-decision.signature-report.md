# OMIV Signed Object Trust Report

- Object: `PROMOTION_DECISION` / `promotion_92b2b841a5dc7f07b470482080eb38c8`
- Canonical object digest: `52f5a6efc9165a42fe2141b2028c2b573e1faf54767db08d960d5bc61bf968ca`
- Policy: `omiv.trust-policy.team_release.v1` / `b86750f437390cd8457d0fbc4f2447127ef3f968a2545111f95af2417b2a742e`
- Trust bundle: `tb_e676b0ccb52d9a293c802687d90b86b4` / `fa8a0468dd88779a4b1698bad6f43946eff8362bba25069182c42986cc6f5e47`
- Overall signed-object status: **TRUSTED_SIGNATURE_WITH_LIMITATIONS**
- Accepted signatures: 1

## Layered results

### Signature `sig_991cbb57760329a12b5dbb558de5fd8e`

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

- Underlying claim: `{&quot;deployment_performed&quot;: false, &quot;promotion_outcome&quot;: &quot;PROMOTION_ALLOWED_WITH_CONDITIONS&quot;, &quot;promotion_performed&quot;: false}`
- Underlying claim authenticity: **NOT_APPLICABLE**
- Underlying provenance strength: **NOT_APPLICABLE**
- Claim content independently proven: **NO**
- Payload integrity: **NOT_CHECKED**
- Numerical fidelity: **NOT_CHECKED**
- Security: **NOT_CHECKED**
- Runtime: **NOT_CHECKED**
- Approval: **NOT_AVAILABLE**
- Lifecycle completeness: **INCOMPLETE**

A valid signature proves that the holder of the corresponding private key signed a specific canonical OMIV object. It does not by itself prove the underlying real-world claim is true.

## Limitations

- A valid signature proves that the corresponding private-key holder signed this canonical object; it does not prove the underlying claim is true.
- No payload, fidelity, security, runtime, approval, deployment, or complete-custody claim is created by signing.

Report digest: `d08531245e0942a9e90e798e22077338928c6f76e7fe43b4efa72e5da647157b`
