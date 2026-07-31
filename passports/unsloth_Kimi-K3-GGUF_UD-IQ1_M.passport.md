# Model Passport: Kimi K3

A portable, integrity-linked summary of this artifact's identity, evidence, trust status, and known limitations.

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
| Structural validation | **STRUCTURALLY_VALIDATED_WITH_LIMITATIONS** |
| Provenance | **UNAVAILABLE** |
| Payload | **NOT_CHECKED** |
| Security inspection | **NOT_CHECKED** |
| Custody chain | **NOT_AVAILABLE** |
| Runtime verification | **NOT_CHECKED** |
| Overall usage guidance | **SUITABLE FOR LOCAL EXPERIMENTATION WITH LIMITATIONS** |

## What Is Verified

The artifact identity and structural evidence are integrity-linked and valid within the recorded scope.

## What Is Not Verified

Payload values, numerical fidelity, security behavior, and runtime equivalence have not been established.

This passport does not state that the artifact is safe to execute, numerically equivalent, runtime-compatible, or production approved.

## Trust Dimensions

| Dimension | Result |
| --- | --- |
| Identity | **IDENTITY_VERIFIED** |
| Structural | **STRUCTURALLY_VALIDATED_WITH_LIMITATIONS** |
| Provenance | **EVIDENCE_INCOMPLETE** |
| Payload | **NOT_ASSESSED** |
| Security | **NOT_ASSESSED** |
| Custody | **TRUST_CHAIN_INCOMPLETE** |
| Runtime | **NOT_ASSESSED** |

## Usage Profiles

| Profile | Result | Guidance |
| --- | --- | --- |
| enterprise_structural_review | **REVIEW_REQUIRED** | Structural evidence is available, but additional review evidence is required. |
| local_experimentation | **SUITABLE_WITH_LIMITATIONS** | Suitable within the recorded structural scope; payload, security, and runtime limitations remain visible. |
| regulated_production | **NOT_SUITABLE** | Required evidence is missing or failed; this profile is not satisfied. |
| team_structural_intake | **SUITABLE_WITH_LIMITATIONS** | Suitable within the recorded structural scope; payload, security, and runtime limitations remain visible. |

## Evidence Stages

| Stage | Status | Scope or limitation | Next step |
| --- | --- | --- | --- |
| approval | **NOT_CHECKED** | No approval workflow evidence is included. | Obtain an approval attestation under an applicable policy. |
| artifact_identity | **PASS** | fixed repository and immutable revision | — |
| artifact_specific_provenance | **UNAVAILABLE** | no artifact-specific conversion-run provenance exists | signed conversion-run provenance |
| converter_rule_support | **AVAILABLE** | does not identify the converter run that produced this artifact | artifact-specific conversion provenance |
| custody_chain | **UNAVAILABLE** | No artifact lifecycle custody events are recorded. | Record custody events in a future chain-of-custody implementation. |
| deployment_observation | **NOT_CHECKED** | No deployed-artifact observation is included. | Record deployment and runtime artifact identity in a future phase. |
| format_structure | **PASS** | complete GGUF headers for all shards | — |
| header_integrity | **PASS** | complete GGUF headers for all shards | — |
| payload_integrity | **NOT_CHECKED** | no tensor payload bytes or hashes were accessed | payload digest evidence |
| payload_span_bounds | **PASS** | computed descriptor payload spans fit shard bounds | payload integrity evidence |
| quantization_fidelity | **NOT_CHECKED** | allowed type transitions are not numerical fidelity | numerical quantization comparison |
| repository_layout | **PASS** | 15-file selected split layout | — |
| runtime_parity | **NOT_CHECKED** | no backend execution, logits, or runtime output | runtime parity evidence |
| security_inspection | **NOT_CHECKED** | No security scanner was run in Phase 5A. | Run a future policy-approved security inspection. |
| semantic_mapping | **PASS** | descriptor-level source-to-target assignments | payload relation verification |
| split_container | **PASS** | split identity and descriptor aggregation | — |
| target_ontology | **PASS** | Kimi K3 target ontology | — |
| tokenizer_parity | **NOT_CHECKED** | tokenizer arrays were not compared | tokenizer parity evidence |

## Limitations

- Allowed GGML type transitions do not establish numerical quantization fidelity.
- Converter-code support does not establish which converter produced the published artifact.
- No custody chain, approval, deployment, or runtime observation is available.
- No security inspection was performed; this passport does not establish safety.
- Payload values and individual artifact bytes have not been verified.
- Structural descriptor validation does not establish tensor payload integrity.
- The result supports structural integration acceptance only under profiles that permit these limitations.
- Tokenizer arrays, logits, backend execution, and runtime behavior were not compared.

## Custody Boundary

No Model Chain of Custody ledger has been recorded. This passport claims no acquisition, transformation, validation-attestation, approval, deployment, or runtime-observation custody event.

The validation evidence graph records dependencies between validation artifacts; it is not a custody ledger.

## Evidence References

- `artifact_index` — schema `omiv.validation-artifact-index.v1`, digest `6059d6a460f5d417173c4346f0c4e5d6c26a4887e488ea7c24d5e473ca6094a6`, availability `digest_only`, verification `digest_only_verification`
- `evidence_graph` — schema `omiv.validation-evidence-graph.v1`, digest `ea08a66295a72ebb1331196e9cd3c94845fc21208b08240447828ae77b7db2eb`, availability `digest_only`, verification `digest_only_verification`
- `mapping_policy` — schema `omiv.mapping-policy.digest`, digest `0201db3da3e2e6f47596b1cdb369d8004a34c7340a4ae5bca281004bb6e72f6c`, availability `digest_only`, verification `digest_only_verification`
- `model_pack` — schema `omiv.model-pack-identity.v1`, digest `6f151e70f2b28e367b84c59db6e7ad4184271b1cc7f518320043e3456c3ef288`, availability `digest_only`, verification `digest_only_verification`
- `ontology_policy` — schema `omiv.ontology-policy.digest`, digest `67b767da34ec3e95202266992c1468bef145756b16d9fcbc9f90895c2cea49a0`, availability `digest_only`, verification `digest_only_verification`
- `validation_inventory` — schema `omiv.independent-model-validation.v1`, digest `54b7f52695634878fcde5b9d4d9e89e4c8f6fd4b32060f2be81ebe7876e003c8`, availability `private`, verification `full_verification`

## Passport Integrity

- Passport ID: `mp_4a9b0e3b309c867711782e2075be77c6`
- Passport digest: `ee8d3f83fe25ac8997e4e69f1551df35c82d6f4c4166e6be7052e06d417159af`
- Passport policy digest: `3f03e0855539e05a350a89a49e427437af74a4c7f6d36ea2d0357cb5a0e616dd`
