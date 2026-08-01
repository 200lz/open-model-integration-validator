# OMIV Signed Object Trust Report

- Object: `POLICY_DECISION` / `decision_93a6b38fadb966a198e08e8d82db069e`
- Canonical object digest: `2679698880494a1f902f21c127d4b711930e56db4224313c39659cfa9d3959c3`
- Policy: `omiv.trust-policy.team_release.v1` / `b86750f437390cd8457d0fbc4f2447127ef3f968a2545111f95af2417b2a742e`
- Trust bundle: `tb_e676b0ccb52d9a293c802687d90b86b4` / `fa8a0468dd88779a4b1698bad6f43946eff8362bba25069182c42986cc6f5e47`
- Overall signed-object status: **TRUSTED_SIGNATURE_WITH_LIMITATIONS**
- Accepted signatures: 1

## Layered results

### Signature `sig_3ee46f7f274627748e882eaab500d264`

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

- Underlying claim: `{&quot;claim_truth_independently_proven&quot;: false, &quot;decision_outcome&quot;: &quot;ALLOW_WITH_LIMITATIONS&quot;, &quot;policy_id&quot;: &quot;omiv.governance-policy.team_artifact_intake.v1&quot;}`
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

Report digest: `1dfbdd94e52a737396f1e99a21a3769c5756e3351b9784bf34fa3a3bd6b8458b`
