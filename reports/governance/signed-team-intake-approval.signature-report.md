# OMIV Signed Object Trust Report

- Object: `APPROVAL_RECORD` / `approval_6f531c7f19e6859f0681db4bd50b4500`
- Canonical object digest: `be907dcc45306b9ce6da0570d7d3c0c86838b3f205db305a4f0c7d626f05ad82`
- Policy: `omiv.trust-policy.team_release.v1` / `b86750f437390cd8457d0fbc4f2447127ef3f968a2545111f95af2417b2a742e`
- Trust bundle: `tb_e676b0ccb52d9a293c802687d90b86b4` / `fa8a0468dd88779a4b1698bad6f43946eff8362bba25069182c42986cc6f5e47`
- Overall signed-object status: **TRUSTED_SIGNATURE_WITH_LIMITATIONS**
- Accepted signatures: 1

## Layered results

### Signature `sig_636ebf2b22f2758537d9240bdb14180e`

- Signature integrity: **VALID**
- Trusted by selected policy: **YES**
- Key identity/status: `key_01ff700f954d00c581e5100c77858e6b` / **KNOWN**
- Signer identity: **DECLARED**
- Signer identity verification: **UNVERIFIED**
- Signer/key binding: **VERIFIED_BY_TRUST_BUNDLE**
- Delegation: **DIRECT_ROOT**
- Revocation: **NOT_REVOKED**
- Expiration: **UNAVAILABLE**
- Policy trust: **TRUSTED_BY_POLICY**

## Claim-strength boundary

- Underlying claim: `{&quot;approval_is_deployment&quot;: false, &quot;approval_outcome&quot;: &quot;APPROVED_WITH_CONDITIONS&quot;, &quot;scope&quot;: &quot;team artifact intake under the named policy&quot;}`
- Underlying claim authenticity: **NOT_APPLICABLE**
- Underlying provenance strength: **NOT_APPLICABLE**
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

Report digest: `430eb7df9599013de087460d8d6b225cff637f4f9ce9683afd89edd18c69af7d`
