# OMIV Signed Object Trust Report

- Object: `RELEASE_CANDIDATE` / `candidate_f3ab4b7c6cad855190df70ff53e82166`
- Canonical object digest: `95f6a5e83c131d107d56e774dbe10d644d918f5fd8f36b22598b02f3d4e5a19e`
- Policy: `omiv.trust-policy.team_release.v1` / `b86750f437390cd8457d0fbc4f2447127ef3f968a2545111f95af2417b2a742e`
- Trust bundle: `tb_e676b0ccb52d9a293c802687d90b86b4` / `fa8a0468dd88779a4b1698bad6f43946eff8362bba25069182c42986cc6f5e47`
- Overall signed-object status: **TRUSTED_SIGNATURE_WITH_LIMITATIONS**
- Accepted signatures: 1

## Layered results

### Signature `sig_ab7a837cb8a1df97910e297888886c6a`

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

- Underlying claim: `{&quot;candidate_status&quot;: &quot;GOVERNANCE_OBJECT_ONLY&quot;, &quot;release_occurred&quot;: false}`
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

Report digest: `84ce3f115e980bf569c6508c6a0c2811e9f6f05d0e42470bd9dcc1b66be62b6b`
