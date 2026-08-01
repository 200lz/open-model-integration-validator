# OMIV Signed Object Trust Report

- Object: `CUSTODY_EVENT` / `ce_ff7454070633a8f266ee460c337e2045`
- Canonical object digest: `b174106be0c0a9116d455479f99f89e0cd6f703fa8d12e211a1618564d67c9dd`
- Policy: `omiv.trust-policy.project_maintainer_release.v1` / `c23e4a5b3efda351fc3b8c0f4cebdbc73f4e3b6e5b3d101db1e6df55e926dfe1`
- Trust bundle: `tb_2f473c8d4f367c0a89aa0d00e0f3d552` / `c761ca00f9365d19057579c52e24f96f70fac72d6b7acbba3ddd54f5ff191f88`
- Overall signed-object status: **TRUSTED_SIGNATURE_WITH_LIMITATIONS**
- Accepted signatures: 1

## Layered results

### Signature `sig_25fbbef91f668736b48c6ccc46357815`

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

- Underlying claim: `{&quot;assertion_origin&quot;: &quot;DERIVED_FROM_VERIFIED_EVIDENCE&quot;, &quot;attestation_status&quot;: &quot;UNATTESTED&quot;, &quot;authenticity&quot;: &quot;EVIDENCE_DERIVED&quot;}`
- Underlying claim authenticity: **EVIDENCE_DERIVED**
- Underlying provenance strength: **NOT_APPLICABLE**
- Claim content independently proven: **NO**
- Payload integrity: **NOT_CHECKED**
- Numerical fidelity: **NOT_CHECKED**
- Security: **NOT_CHECKED**
- Runtime: **NOT_CHECKED**
- Approval: **NOT_AVAILABLE**
- Lifecycle completeness: **NOT_ASSESSED**

A valid signature proves that the holder of the corresponding private key signed a specific canonical OMIV object. It does not by itself prove the underlying real-world claim is true.

## Limitations

- A valid signature proves that the corresponding private-key holder signed this canonical object; it does not prove the underlying claim is true.
- No payload, fidelity, security, runtime, approval, deployment, or complete-custody claim is created by signing.

Report digest: `cd2e546375ab3972705644ad155c66b52c4270b16af1326b39b3088a5bac4a2e`
