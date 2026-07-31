# Model Passport with Custody: Kimi K3

This passport links an intact evidence-derived custody segment. The lifecycle record remains incomplete and its events are unattested.

## Compact Summary

| Item | Result |
| --- | --- |
| Model | Kimi K3 |
| Artifact variant | UD-IQ1_M |
| Origin | huggingface / unsloth/Kimi-K3-GGUF |
| Immutable revision | `3d4b61ab4b6789d401191c476cbb4567246db8f5` |
| Format | GGUF |
| Architecture | kimi-k3 |
| Artifact size | 604.31 GiB (648,872,012,448 bytes) |
| Custody ledger availability | **AVAILABLE** |
| Ledger integrity | **INTACT** |
| Subject continuity | **CONSISTENT** |
| Evidence linkage | **VERIFIED** |
| Lifecycle completeness | **INCOMPLETE** |
| Event authenticity | **EVIDENCE_DERIVED / UNATTESTED** |
| Overall custody | **TRUST_CHAIN_INCOMPLETE** |
| Security inspection | **NOT_CHECKED** |
| Runtime verification | **NOT_CHECKED** |

## Custody Boundary

Hash linking proves integrity of the recorded sequence. It does not prove that a real-world action occurred, authenticate an actor, or establish approval.

## Missing Lifecycle Events

- `APPROVAL_RECORDED`
- `ARTIFACT_ACQUISITION_RECORDED`
- `DEPLOYMENT_RECORDED`
- `QUANTIZATION_RECORDED`
- `REGISTRY_PROMOTION_RECORDED`
- `RUNTIME_OBSERVATION_RECORDED`
- `SECURITY_INSPECTION_COMPLETED`
- `TRANSFORMATION_RECORDED`

## Limitations

- Allowed GGML type transitions do not establish numerical quantization fidelity.
- Converter-code support does not establish which converter produced the published artifact.
- Evidence-derived custody events are unattested and do not authenticate actors.
- No custody chain, approval, deployment, or runtime observation is available.
- No security inspection was performed; this passport does not establish safety.
- Payload values and individual artifact bytes have not been verified.
- Structural descriptor validation does not establish tensor payload integrity.
- The custody ledger is intact but lifecycle evidence is incomplete.
- The result supports structural integration acceptance only under profiles that permit these limitations.
- Tokenizer arrays, logits, backend execution, and runtime behavior were not compared.

## Integrity

- Base passport: `mp_4a9b0e3b309c867711782e2075be77c6` / `ee8d3f83fe25ac8997e4e69f1551df35c82d6f4c4166e6be7052e06d417159af`
- Custody chain: `mcoc_51ddabd5223bccc6ed30070cbe44c60e` / `8bc0818732f0fc8d0dc91d84589f1c046c28e68a31f2f4cd831e3372f96141c7`
- Linked passport ID: `mp_bac200de419e75ab7667304638be7e8f`
- Linked passport digest: `3b4c29ef3e05bd9d75e8452d51237ca9687506e0822919bff5ceb5356136b6d4`
