# OMIV Signed Object Trust Report

- Object: `CUSTODY_SEGMENT` / `mcoc_3d488470cbfea983ea353763f51a6b3b`
- Canonical object digest: `8c8623b85bbf774c631b34a6bb10a2a8850daccdc1a072f0df990af84c3f2a06`
- Policy: `omiv.trust-policy.team_release.v1` / `8f411512aeed0e2d8cb25198838c587dd8e9af0e62b1164298557361b400fa3d`
- Trust bundle: `tb_43fb7acfdfb2808b423d4d4619c06ef6` / `0b6788915d71781aebc67cf501bdfed7f61f4377770cd5d85bd59283b10d5c9f`
- Overall signed-object status: **TRUSTED_SIGNATURE_WITH_LIMITATIONS**
- Accepted signatures: 1

## Layered results

### Signature `sig_e6cda8ae99884900731ab34f91721e28`

- Signature integrity: **VALID**
- Trusted by selected policy: **YES**
- Key identity/status: `key_01ff700f954d00c581e5100c77858e6b` / **KNOWN**
- Signer identity: **DECLARED**
- Signer identity verification: **UNVERIFIED**
- Signer/key binding: **VERIFIED_BY_TRUST_BUNDLE**
- Delegation: **VALID_DELEGATION**
- Revocation: **NOT_REVOKED**
- Expiration: **UNAVAILABLE**
- Policy trust: **TRUSTED_BY_POLICY**

## Claim-strength boundary

- Underlying claim: `{&quot;event_authenticity&quot;: &quot;EVIDENCE_DERIVED&quot;, &quot;genesis_semantics&quot;: &quot;PORTABLE_SEGMENT_BEGINNING&quot;}`
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

Report digest: `4d30c8500c034f61c5aa3cd29dc5ff81a2a933fa2f6b9b5af6ae8c5b29fad10c`
