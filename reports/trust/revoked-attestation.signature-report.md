# OMIV Signed Object Trust Report

- Object: `ARTIFACT_ATTESTATION` / `att_4a6efa7aad56fc20f2b840688c0756db`
- Canonical object digest: `c3978007ace5620f1b324a2577c3063f6d4b3d329e58e76afd8795414c03216a`
- Policy: `omiv.trust-policy.project_maintainer_release.v1` / `c23e4a5b3efda351fc3b8c0f4cebdbc73f4e3b6e5b3d101db1e6df55e926dfe1`
- Trust bundle: `tb_9554be748f40fee51f9d7687981043b9` / `2dac1ab043347af3bf5e9b1d8f63a92397d5bac9405b0a0098379fd3c4e1f509`
- Overall signed-object status: **REVOKED**
- Accepted signatures: 0

## Layered results

### Signature `sig_394019ac99ffc102ce48b71982ee64dd`

- Signature integrity: **VALID**
- Trusted by selected policy: **NO**
- Key identity/status: `key_ed39d828050734934fcf309c611f5d9b` / **REVOKED**
- Signer identity: **DECLARED**
- Signer identity verification: **UNVERIFIED**
- Signer/key binding: **VERIFIED_BY_TRUST_BUNDLE**
- Delegation: **DIRECT_ROOT**
- Revocation: **REVOKED**
- Expiration: **UNAVAILABLE**
- Policy trust: **PARTIALLY_TRUSTED**

- Revocation record: `revocation_7cc2ef76a0da29efaa49ab80f7588571` / **VALID**
- Revocation authority: **AUTHORIZED_BY_LOCAL_POLICY**
- Revocation scope/status: **KEY** / **REVOKED**
- Revocation reason: **KEY_COMPROMISE**
- Replacement/supersession: `NONE`

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

Report digest: `fb5ce2d183b1c8bc6b7bf1f5641f56d0a9701d8ac8f40af9de4de8af7ba231d6`
