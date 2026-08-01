# OMIV Signed Object Trust Report

- Object: `MODEL_PASSPORT` / `mp_ddf7751e32c4635243fd168de6f2f5eb`
- Canonical object digest: `ee1f270749b7e6749d3862eda747b1467e9f13fad7c3c6e65742e491bd1df409`
- Policy: `omiv.trust-policy.project_maintainer_release.v1` / `c23e4a5b3efda351fc3b8c0f4cebdbc73f4e3b6e5b3d101db1e6df55e926dfe1`
- Trust bundle: `tb_2f473c8d4f367c0a89aa0d00e0f3d552` / `c761ca00f9365d19057579c52e24f96f70fac72d6b7acbba3ddd54f5ff191f88`
- Overall signed-object status: **TRUSTED_SIGNATURE_WITH_LIMITATIONS**
- Accepted signatures: 1

## Layered results

### Signature `sig_094bdd0e3401a1890bf36e4462e91467`

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

- Underlying claim: `{&quot;passport_trust_summary&quot;: {&quot;custody_status&quot;: &quot;TRUST_CHAIN_INCOMPLETE&quot;, &quot;identity_status&quot;: &quot;IDENTITY_VERIFIED&quot;, &quot;payload_status&quot;: &quot;NOT_ASSESSED&quot;, &quot;provenance_status&quot;: &quot;EVIDENCE_INCOMPLETE&quot;, &quot;runtime_status&quot;: &quot;NOT_ASSESSED&quot;, &quot;security_status&quot;: &quot;NOT_ASSESSED&quot;, &quot;structural_status&quot;: &quot;STRUCTURALLY_VALIDATED_WITH_LIMITATIONS&quot;}}`
- Underlying claim authenticity: **NOT_APPLICABLE**
- Underlying provenance strength: **NOT_APPLICABLE**
- Claim content independently proven: **NO**
- Payload integrity: **NOT_CHECKED**
- Numerical fidelity: **NOT_CHECKED**
- Security: **NOT_CHECKED**
- Runtime: **NOT_CHECKED**
- Approval: **NOT_AVAILABLE**
- Lifecycle completeness: **TRUST_CHAIN_INCOMPLETE**

A valid signature proves that the holder of the corresponding private key signed a specific canonical OMIV object. It does not by itself prove the underlying real-world claim is true.

## Limitations

- A valid signature proves that the corresponding private-key holder signed this canonical object; it does not prove the underlying claim is true.
- No payload, fidelity, security, runtime, approval, deployment, or complete-custody claim is created by signing.

Report digest: `37cc87acdc541111fed855fe00d4268387747fc294057317fb0a67c3b9cc8b95`
