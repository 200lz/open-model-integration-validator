# Model Passport with Custody: Kimi K3

This passport links an intact evidence-derived custody segment. The lifecycle record remains incomplete and its events are unattested.

## Compact Summary

| Item | Result |
| --- | --- |
| Model | Kimi K3 |
| Artifact variant | UD-Q4_K_XL |
| Origin | huggingface / unsloth/Kimi-K3-GGUF |
| Immutable revision | `3d4b61ab4b6789d401191c476cbb4567246db8f5` |
| Format | GGUF |
| Architecture | kimi-k3 |
| Artifact size | 1.37 TiB (1,508,668,683,104 bytes) |
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

- Base passport: `mp_02e689eb3e09de0de341fec3aa90abaf` / `ccaa10f66f533c43e5ae74492f494ea375fa97f4d8d67ae0a8caa01c5347945e`
- Custody chain: `mcoc_03093c611d82fd4b2fd71d47e358eb7a` / `15d57adc5282a074e58f5d8d8e36e88d0bcd636aa5bdfae528ca8577ad5a6445`
- Linked passport ID: `mp_d3acb08b326b2417a06e51c02a10b5af`
- Linked passport digest: `6b97d4ace74fb93cc999bd177881dfa71dce537265b572d2a8858a1373af41fe`
