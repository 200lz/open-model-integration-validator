# Structurally Validating Kimi K3 Split GGUF Releases Without Downloading Tensor Payloads

Repository, split layout, GGUF headers, tensor descriptors, target ontology,
semantic mapping, and cross-quantization structural comparison with OMIV

## Executive summary

Open Model Integration Validator (OMIV) independently inspected
`unsloth/Kimi-K3-GGUF` at immutable revision
`3d4b61ab4b6789d401191c476cbb4567246db8f5`. The selected UD-IQ1_M variant
contains 15 shards totaling 648,872,012,448 bytes; UD-Q4_K_XL contains 32 shards
totaling 1,508,668,683,104 bytes. [CLAIM-001] [CLAIM-002] [CLAIM-003]
[CLAIM-004] [CLAIM-005]

Both variants contain 2,573 verified target tensor descriptors. Their normalized
tensor identities and shapes match completely. The only changed GGML families are
276 packed routed-expert targets: IQ1_S→MXFP4 for 209 tensors, IQ2_XXS→MXFP4 for
56, and IQ3_XXS→MXFP4 for 11. [CLAIM-008] [CLAIM-027] [CLAIM-028] [CLAIM-029]

OMIV accepted zero tensor payload bytes while producing the remote structural
evidence. Both variants are `STRUCTURALLY_VALIDATED_WITH_LIMITATIONS`; their
comparison is `STRUCTURALLY_EQUIVALENT_WITH_QUANTIZATION_DIFFERENCES`.
[CLAIM-006] [CLAIM-024] [CLAIM-025] [CLAIM-026]

Artifact-specific conversion provenance is unavailable. Payload verification,
numerical quantization fidelity, tokenizer parity, and runtime parity were not
checked. [CLAIM-019] [CLAIM-020] [CLAIM-021] [CLAIM-022] [CLAIM-023]

## Why “model supported” needs evidence

Format recognition alone does not show that a release has a complete shard set,
bounded headers, consistent split metadata, the expected target architecture, or a
source-to-target mapping. OMIV separates these questions into independently
verifiable evidence stages. A later stage cannot convert an unsupported earlier
stage into a warning merely to produce a favorable result.

## Scope and non-goals

The scope is the selected text GGUF artifacts under `UD-IQ1_M/*.gguf` and
`UD-Q4_K_XL/*.gguf` at one immutable repository revision. It covers repository
identity, bounded byte-range inspection, complete GGUF headers, split aggregation,
descriptor spans, Kimi K3 target ontology, grouped semantic mapping, independent
validation, and structural comparison.

It does not cover payload values, quantization error, tokenizer behavior, logits,
backend execution, unverified benchmark results, multimodal behavior, or
conversion-run provenance.

## Subject identity and immutable revision

The provider identity, repository name, requested revision, resolved revision, and
selected path prefixes are represented in strict snapshot schemas. Both variants
resolve to the same commit, so the comparison is not silently mixing revisions.
[CLAIM-001]

The Kimi model pack is version 3 with capabilities `checkpoint_schema`,
`checkpoint_ontology`, `gguf_ontology`, and `semantic_mapping`. Its digest is
`6f151e70f2b28e367b84c59db6e7ad4184271b1cc7f518320043e3456c3ef288`.

## Evidence architecture

```text
repository snapshot
  -> bounded prefix and complete-header reads
  -> per-shard header inventories
  -> split inventory and span bounds
  -> Kimi K3 target ontology
  -> grouped semantic mapping
  -> independent validation bundle
  -> cross-quantization structural comparison
```

Each stage has a strict schema, deterministic digest, parent links, typed findings,
and an offline verifier. Unsupported evidence fails closed.

## Phase 4F-1: repository snapshot and bounded Range

Phase 4F-1 resolves `main` to an immutable commit, safely enumerates selected
files, validates the filename split layout, checks exact HTTPS Range semantics,
and accepts the eight-byte GGUF magic/version prefix. It does not claim a complete
header at this stage. [CLAIM-001] [CLAIM-007]

## Phase 4F-2: incremental GGUF header parsing

The complete-header parser incrementally reads binary structures rather than
guessing a fixed header length. Shard 1 is metadata-only in both variants; the
remaining shards carry tensor descriptors. Every request remains bounded, and the
accepted byte boundary ends before tensor payload data. [CLAIM-006] [CLAIM-007]

## Phase 4F-3: split aggregation

Split aggregation establishes ordinal completeness, metadata consistency, global
tensor counts, duplicate/conflict accounting, and descriptor payload-span bounds.
It finds 2,573 descriptors in each variant, with all spans computable, bounded,
non-conflicting, and non-overlapping. This remains structural evidence; no Kimi
semantic classification is asserted yet. [CLAIM-008] [CLAIM-009]

## Phase 4F-4: Kimi K3 target ontology

The target ontology checks 93 layers: 69 KDA and 24 MLA. Layer 0 is dense; layers
1–92 are MoE. Metadata records 896 routed experts, 16 experts used, and shared
expert structure across the 92 MoE layers. It also classifies g_proj
realizations, Attention Residual tensors, routed/shared expert families, and
model-level tensors. [CLAIM-010] [CLAIM-011] [CLAIM-012] [CLAIM-013]
[CLAIM-014]

## Phase 4F-5: grouped semantic mapping

The source inventory contains 497,220 physical records. Every record and every
one of the 2,573 targets has an explicit accounting state. The mapping engine
represents direct, many-to-one packed, fused, split, and logical realization
relations. In particular, 276 complete routed groups map structurally to 276
packed targets. [CLAIM-015] [CLAIM-016] [CLAIM-017] [CLAIM-018]

For each layer/component, the routed packing relation is:

```text
896 expert tensor members + 896 scale-support records
  -> one packed routed-expert target descriptor
```

This relation checks identity, cardinality, descriptor shapes, axes, and permitted
types. It does not check numerical member order or scale association.

## Phase 4F-6: independent validation bundle

The validation bundle composes the repository, Range, header, split, ontology, and
mapping evidence into a typed dependency graph. Community structural acceptance
is satisfied. Vendor and enterprise structural profiles carry warnings because
artifact-specific provenance is unavailable. The regulated full-deployment
profile is not satisfied because provenance, payload, quantization, tokenizer,
and runtime evidence are absent. [CLAIM-019] [CLAIM-020] [CLAIM-021]
[CLAIM-022] [CLAIM-023] [CLAIM-024] [CLAIM-025]

## Phase 4F-7: cross-quantization structural comparison

The directional baseline/candidate comparison checks repository identity,
revision compatibility, metadata policy categories, complete tensor identities,
family-aware normalized shapes, GGML type transitions, encoded spans, ontology
structure, semantic mapping, and validation profiles. Shard-count differences are
physical-layout changes rather than automatic structural failures. [CLAIM-026]
[CLAIM-027]

## MXFP4 support and fail-closed behavior

The first Q4 attempt stopped with 276 unsupported spans. Its ontology therefore
remained invalid, and OMIV emitted no mapping, validation bundle, or canonical
comparison. The missing primary-source evidence was then added from
`llama.cpp@cf67f0d24511864d2d3da0769108fd6fc16d00d1`:

- `ggml/include/ggml.h`: type code 39;
- `ggml/src/ggml-common.h`: 32 elements per block, one E8M0 scale byte, and
  16 packed-data bytes, for 17 encoded bytes;
- `ggml/src/ggml.c`: row divisibility and encoded row-size calculation;
- `src/llama-quant.cpp`: converter-side MXFP4 MoE placement.

The checked span formula is `(ne[0] / 32) * 17 * product(ne[1:])`, with
`ne[0] % 32 == 0` and overflow/bounds checks. MXFP4 is permitted only for packed
routed-expert gate, up, and down families. The complete evidence chain was
regenerated before comparison. This validates byte-span structure, not numerical
MXFP4 fidelity. [CLAIM-030] [CLAIM-021]

## IQ1_M versus Q4 structural comparison

### Variant repository summary

| Variant | Revision | Shards | Repository bytes | Metadata-only | Tensor-bearing | Descriptors | Payload bytes accepted | Validation result |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| UD-IQ1_M | `3d4b61ab4b6789d401191c476cbb4567246db8f5` | 15 | 648,872,012,448 | 1 | 14 | 2,573 | 0 | STRUCTURALLY_VALIDATED_WITH_LIMITATIONS |
| UD-Q4_K_XL | `3d4b61ab4b6789d401191c476cbb4567246db8f5` | 32 | 1,508,668,683,104 | 1 | 31 | 2,573 | 0 | STRUCTURALLY_VALIDATED_WITH_LIMITATIONS |

### Tensor type distribution

| GGML type | UD-IQ1_M | UD-Q4_K_XL |
| --- | ---: | ---: |
| F32 | 1,181 | 1,181 |
| Q8_0 | 1,116 | 1,116 |
| IQ1_S | 209 | 0 |
| IQ2_XXS | 56 | 0 |
| IQ3_XXS | 11 | 0 |
| MXFP4 | 0 | 276 |

### Directional type transitions

| Baseline type | Candidate type | Count | Approved families | Structural status | Numerical status |
| --- | --- | ---: | --- | --- | --- |
| F32 | F32 | 1,181 | recorded families | allowed | not checked |
| Q8_0 | Q8_0 | 1,116 | recorded families | allowed | not checked |
| IQ1_S | MXFP4 | 209 | packed routed gate/up/down | allowed | not checked |
| IQ2_XXS | MXFP4 | 56 | packed routed gate/up | allowed | not checked |
| IQ3_XXS | MXFP4 | 11 | packed routed down | allowed | not checked |

### Physical storage difference

Baseline repository bytes are 648,872,012,448; candidate repository bytes are
1,508,668,683,104. Candidate divided by baseline is the exact ratio
`4285990577 / 1843386399`, approximately `2.325063578274`.

Baseline encoded tensor bytes are 648,864,913,792; candidate encoded tensor bytes
are 1,508,661,582,208. Candidate divided by baseline is
`11786418611 / 5069257139`, approximately `2.325078071168`.

These are physical and encoded storage ratios, not measures of accuracy,
efficiency, or model quality. [CLAIM-031] [CLAIM-032]

## What was verified

- Immutable repository identity and selected shard layouts;
- bounded Range behavior and complete GGUF headers;
- split metadata, descriptor completeness, and span bounds;
- complete Kimi K3 target ontology classification;
- complete source and target structural accounting;
- descriptor-level semantic mapping and converter-rule support;
- equal normalized tensor identity and shape sets across both variants;
- family-scoped structural GGML type transitions. [CLAIM-009] [CLAIM-010]
  [CLAIM-016] [CLAIM-017] [CLAIM-027] [CLAIM-030]

## What was not verified

Artifact-specific conversion provenance remains unavailable. Payload values,
expert packing order, numerical scale association, quantization error, tokenizer
behavior, logits, backend execution, and runtime parity remain unverified or not
checked. [CLAIM-019] [CLAIM-020] [CLAIM-021] [CLAIM-022] [CLAIM-023]

## Evidence-stage matrix

| Stage | IQ1_M | Q4 | Comparison | Evidence status | Limitation |
| --- | --- | --- | --- | --- | --- |
| Repository through mapping | PASS | PASS | checked | structural | descriptor evidence |
| Converter-rule support | AVAILABLE | AVAILABLE | equal | available | not artifact provenance |
| Artifact-specific provenance | UNAVAILABLE | UNAVAILABLE | unavailable | unavailable | conversion run not established |
| Payload integrity | NOT_CHECKED | NOT_CHECKED | not checked | not checked | payload bytes not read |
| Quantization fidelity | NOT_CHECKED | NOT_CHECKED | not checked | not checked | no numerical comparison |
| Tokenizer parity | NOT_CHECKED | NOT_CHECKED | not checked | not checked | no tokenizer comparison |
| Runtime parity | NOT_CHECKED | NOT_CHECKED | not checked | not checked | no backend execution |

## Acceptance-profile matrix

| Profile | IQ1_M | Q4 | Comparison | Reason |
| --- | --- | --- | --- | --- |
| Community structural | SATISFIED | SATISFIED | — | structural stages pass |
| Vendor release structural | SATISFIED_WITH_WARNINGS | SATISFIED_WITH_WARNINGS | — | provenance warning |
| Enterprise offline structural | SATISFIED_WITH_WARNINGS | SATISFIED_WITH_WARNINGS | — | provenance warning |
| Structural equivalence | — | — | SATISFIED_WITH_WARNINGS | provenance warning |
| Quantization layout | — | — | SATISFIED | descriptor and span evidence complete |
| Release consistency | — | — | SATISFIED_WITH_WARNINGS | provenance warning |
| Regulated/full numerical | NOT_SATISFIED | NOT_SATISFIED | NOT_SATISFIED | downstream evidence absent |

## Source accounting

| State | Count |
| --- | ---: |
| Directly mapped | 1,693 |
| Packed group member | 494,592 |
| Fused mapping member | 374 |
| Logical realization source | 393 |
| Source-only auxiliary | 168 |
| Unsupported / invalid / unclassified | 0 |
| Total | 497,220 |

## Target accounting

| State | Count |
| --- | ---: |
| Directly realized | 1,693 |
| Packed group target | 276 |
| Fused target | 187 |
| Logical realization target | 417 |
| Unsupported / invalid / unclassified | 0 |
| Total | 2,573 |

## Reproduction

The evidence and article package verify offline:

```bash
omiv independent-validation-inventory-verify \
  --input validations/unsloth_Kimi-K3-GGUF_UD-IQ1_M.validation.inventory.json
omiv independent-validation-inventory-verify \
  --input validations/unsloth_Kimi-K3-GGUF_UD-Q4_K_XL.validation.inventory.json
omiv structural-comparison-inventory-verify \
  --input comparisons/unsloth_Kimi-K3-GGUF_UD-IQ1_M_vs_UD-Q4_K_XL.comparison.inventory.json
omiv article-preflight \
  --root . \
  --article articles/validating-kimi-k3-gguf-with-omiv.md
```

The full command ordering and expected digests are in
`articles/evidence/kimi-k3-gguf-validation.reproducibility.json`.

## Commercial and audit implications

Model publishers can use the graph to release integrity-linked structural
evidence. Framework and hardware teams can separate descriptor compatibility
from runtime readiness. Quantization vendors can register physical type policies
without presenting them as numerical results. Enterprise, financial, healthcare,
and air-gapped deployment teams can verify the checked-in bundle offline.

Acceptance profiles keep community structural review, vendor release review,
enterprise offline review, and regulated deployment requirements distinct. The
regulated profile remains unsatisfied when provenance and downstream numerical
or runtime evidence are absent.

## Limitations

This work covers two selected text GGUF variants at one repository revision. It
does not cover every Kimi K3 release artifact, model behavior, multimodal
behavior, quality, safety, or deployment fitness. The pinned llama.cpp revision
supports the recorded structural relations; it is not evidence that the published
files were produced by that exact converter revision.

## Claims not made

The following statements are explicitly **not claimed**:

- The weights are correct.
- The conversion is numerically correct.
- The published artifact was generated by the pinned converter revision.
- The expert packing order is correct.
- The scale records are numerically associated correctly.
- MXFP4 is more accurate.
- Q4 is better than IQ1_M.
- IQ1_M is worse than Q4.
- The quantization preserves model quality.
- The tokenizer is equivalent.
- The logits are equivalent.
- Runtime outputs are equivalent.
- The model is production certified.
- The artifact is fully verified.
- The model payload is intact.
- The validation proves benchmark performance.
- The validation proves safety.
- The validation proves multimodal behavior.
- The validation proves the full Kimi K3 release, beyond the selected text GGUF
  artifact set.

## Limitations and future work

Future phases may add independently scoped payload integrity, numerical
quantization, tokenizer, and runtime evidence. Those stages should remain separate
and fail closed until their own policies and artifacts exist.

## Acknowledgements

Moonshot AI developed and released the Kimi K3 architecture. Unsloth published
the compared GGUF variants. llama.cpp and GGML maintainers provide the format,
conversion, and quantization infrastructure used as pinned rule evidence. The
broader open-model community supplies review and interoperability feedback.
Acknowledgement does not imply endorsement of OMIV or this report.

## Evidence and artifact index

- Evidence manifest:
  `articles/evidence/kimi-k3-gguf-validation.evidence-manifest.json`
- Public claim registry:
  `articles/evidence/kimi-k3-gguf-validation.claim-registry.json`
- Reproducibility manifest:
  `articles/evidence/kimi-k3-gguf-validation.reproducibility.json`
- Article artifact index:
  `articles/evidence/kimi-k3-gguf-validation.article-artifact-index.json`
- IQ1_M validation:
  `validations/unsloth_Kimi-K3-GGUF_UD-IQ1_M.validation.inventory.json`
- Q4 validation:
  `validations/unsloth_Kimi-K3-GGUF_UD-Q4_K_XL.validation.inventory.json`
- Structural comparison:
  `comparisons/unsloth_Kimi-K3-GGUF_UD-IQ1_M_vs_UD-Q4_K_XL.comparison.inventory.json`
