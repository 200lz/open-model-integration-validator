# OMIV Signed Object Trust Report

- Object: `ARTIFACT_ATTESTATION` / `att_495f2df4d5d3b25e86c7b281771813fc`
- Canonical object digest: `8902d90a7e4056d5bcb0361d6e2f10d775a9ca8759098651fdae2c8708ef6d58`
- Policy: `omiv.trust-policy.project_maintainer_release.v1` / `c23e4a5b3efda351fc3b8c0f4cebdbc73f4e3b6e5b3d101db1e6df55e926dfe1`
- Trust bundle: `tb_2f473c8d4f367c0a89aa0d00e0f3d552` / `c761ca00f9365d19057579c52e24f96f70fac72d6b7acbba3ddd54f5ff191f88`
- Overall signed-object status: **TRUSTED_SIGNATURE_WITH_LIMITATIONS**
- Accepted signatures: 1

## Layered results

### Signature `sig_9954fa262fcaed767425163533b21dd6`

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

- Underlying claim: `{&quot;assertion_origin&quot;: &quot;DERIVED_FROM_VERIFIED_EVIDENCE&quot;, &quot;authenticity&quot;: &quot;EVIDENCE_LINKED&quot;, &quot;evidence_linkage&quot;: &quot;FULLY_VERIFIED&quot;, &quot;execution_verification&quot;: &quot;NOT_APPLICABLE&quot;, &quot;provenance_strength&quot;: &quot;EVIDENCE_LINKED_PROVENANCE&quot;}`
- Underlying claim authenticity: **EVIDENCE_LINKED**
- Underlying provenance strength: **EVIDENCE_LINKED_PROVENANCE**
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

Report digest: `6a459b408ef7ecebf261e901ec2304c88cc07ff4eb800fbe7c861f360cd15b3b`
