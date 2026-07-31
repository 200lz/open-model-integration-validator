# Model Chain of Custody: UD-IQ1_M

This is an integrity-linked lifecycle evidence segment, not a complete enterprise or legal chain-of-custody certification.

## Compact Summary

| Item | Result |
| --- | --- |
| Chain ID | `mcoc_51ddabd5223bccc6ed30070cbe44c60e` |
| Immutable revision | `3d4b61ab4b6789d401191c476cbb4567246db8f5` |
| Artifact-set digest | `1aa8e70e92cda916aa552e468c49410389bc3cf71f1f56163716f68078bb04c7` |
| Events | 6 |
| Ledger integrity | **INTACT** |
| Parent links | **INTACT** |
| Subject continuity | **CONSISTENT** |
| Evidence linkage | **VERIFIED** |
| Event authenticity | **EVIDENCE_DERIVED / UNATTESTED** |
| Selected profile | `evidence_segment` — **COMPLETE** |
| Lifecycle completeness | **INCOMPLETE** |
| Overall custody | **INCOMPLETE** |
| Revocation | **NOT_ASSESSED** |
| Expiration | **NOT_ASSESSED** |

Ledger integrity and lifecycle completeness are separate: this ledger is intact, while required lifecycle events remain missing.

## Event Timeline

| Seq | Event | Action | Authenticity | Evidence |
| ---: | --- | --- | --- | --- |
| 0 | `SOURCE_LOCATOR_RECORDED` | Record the source repository locator as context for the immutable subject. | EVIDENCE_DERIVED / UNATTESTED | validation_inventory |
| 1 | `IMMUTABLE_IDENTITY_ESTABLISHED` | Establish immutable repository and artifact-set identity. | EVIDENCE_DERIVED / UNATTESTED | validation_inventory |
| 2 | `REMOTE_INSPECTION_RECORDED` | Record verified bounded remote inspection evidence. | EVIDENCE_DERIVED / UNATTESTED | validation_inventory |
| 3 | `FORMAT_INSPECTION_COMPLETED` | Record verified GGUF header and split-container inspection. | EVIDENCE_DERIVED / UNATTESTED | validation_inventory |
| 4 | `STRUCTURAL_VALIDATION_COMPLETED` | Record independently verified structural validation evidence. | EVIDENCE_DERIVED / UNATTESTED | validation_inventory |
| 5 | `PASSPORT_ISSUED` | Record issuance of the integrity-linked Model Passport. | EVIDENCE_DERIVED / UNATTESTED | model_passport |

## Missing Lifecycle Events

- `APPROVAL_RECORDED`
- `ARTIFACT_ACQUISITION_RECORDED`
- `DEPLOYMENT_RECORDED`
- `QUANTIZATION_RECORDED`
- `REGISTRY_PROMOTION_RECORDED`
- `RUNTIME_OBSERVATION_RECORDED`
- `SECURITY_INSPECTION_COMPLETED`
- `TRANSFORMATION_RECORDED`

## Profile Completeness

- `enterprise_deployment`: **INCOMPLETE**; missing: APPROVAL_RECORDED, ARTIFACT_ACQUISITION_RECORDED, DEPLOYMENT_RECORDED, REGISTRY_PROMOTION_RECORDED, SECURITY_INSPECTION_COMPLETED, TRANSFORMATION_RECORDED
- `evidence_segment`: **COMPLETE**; missing: none
- `local_model_intake`: **INCOMPLETE**; missing: ARTIFACT_ACQUISITION_RECORDED, SECURITY_INSPECTION_COMPLETED
- `regulated_runtime`: **INCOMPLETE**; missing: APPROVAL_RECORDED, ARTIFACT_ACQUISITION_RECORDED, DEPLOYMENT_RECORDED, QUANTIZATION_RECORDED, REGISTRY_PROMOTION_RECORDED, RUNTIME_OBSERVATION_RECORDED, SECURITY_INSPECTION_COMPLETED, TRANSFORMATION_RECORDED
- `team_release`: **INCOMPLETE**; missing: APPROVAL_RECORDED, ARTIFACT_ACQUISITION_RECORDED, SECURITY_INSPECTION_COMPLETED, TRANSFORMATION_RECORDED

## Authenticity Boundary

Hash linking protects recorded event integrity but does not authenticate an actor or prove that a real-world action occurred.

Every current event is evidence-derived and unattested. No actor identity, signature, occurrence time, approval, deployment, or runtime action is claimed.

## Limitations

- A repository locator is not evidence that artifact acquisition occurred.
- Allowed GGML type transitions do not establish numerical quantization fidelity.
- Converter-code support does not establish which converter produced the published artifact.
- Format inspection does not prove payload values or runtime compatibility.
- Hash linking protects recorded event integrity but does not authenticate an actor or prove that a real-world action occurred.
- Immutable metadata identity does not establish payload-byte integrity.
- No acquisition, transformation, approval, deployment, or runtime event is claimed.
- Passport issuance summarizes evidence; it is not an approval or signature.
- Remote header inspection is not artifact acquisition or payload validation.
- Structural descriptor validation does not establish tensor payload integrity.
- The result supports structural integration acceptance only under profiles that permit these limitations.
- This evidence segment is not a complete enterprise chain of custody.
- Tokenizer arrays, logits, backend execution, and runtime behavior were not compared.

## Integrity

- Ledger digest: `8bc0818732f0fc8d0dc91d84589f1c046c28e68a31f2f4cd831e3372f96141c7`
- Report digest: `04a539421d90cd2e21c4991ccd11d580e6c895ddebc5fc2a02af982b859cee18`
