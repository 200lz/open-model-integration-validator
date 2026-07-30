# Kimi K3 semantic mapping report

- Inventory digest: `f380d9b9ee8060cf205eef4c69e58353608f148f2ea59ba680e7af522e034afb`
- Source inventory digest: `15a6757becb69c56492fdb630d6853696082a9ec6109bcea05f387a5052ea469`
- Target split inventory digest: `1aa8e70e92cda916aa552e468c49410389bc3cf71f1f56163716f68078bb04c7`
- Target ontology inventory digest: `13a81e3f75b71266473bd1ab7588c6be3d47033245a2b96a80fb102d1ca1081f`
- Model pack: `kimi-k3` v3 `6f151e70f2b28e367b84c59db6e7ad4184271b1cc7f518320043e3456c3ef288`
- Model-pack capabilities: `checkpoint_ontology, checkpoint_schema, gguf_ontology, semantic_mapping`
- Mapping policy digest: `0201db3da3e2e6f47596b1cdb369d8004a34c7340a4ae5bca281004bb6e72f6c`
- Converter evidence revision: `cf67f0d24511864d2d3da0769108fd6fc16d00d1`
- Artifact-specific provenance: `unavailable`
- Payload verification: `not_checked`

## Accounting

| Side | Accounted | Total | Unresolved |
|---|---:|---:|---:|
| Source | 497220 | 497220 | 0 |
| Target | 2573 | 2573 | 0 |

### Source states

| State | Count |
|---|---:|
| `directly_mapped` | 1693 |
| `packed_group_member` | 494592 |
| `fused_mapping_member` | 374 |
| `logical_realization_source` | 393 |
| `source_only_auxiliary` | 168 |
| `intentionally_excluded` | 0 |
| `unsupported` | 0 |
| `invalid` | 0 |
| `unclassified` | 0 |

### Target states

| State | Count |
|---|---:|
| `directly_realized` | 1693 |
| `packed_group_target` | 276 |
| `fused_target` | 187 |
| `logical_realization_target` | 417 |
| `target_only_auxiliary` | 0 |
| `unsupported` | 0 |
| `invalid` | 0 |
| `unclassified` | 0 |

## Mapping denominators

| Domain | Numerator | Denominator |
|---|---:|---:|
| Routed source groups | 276 | 276 |
| Routed packed targets | 276 | 276 |
| Routed expert records | 247296 | 247296 |
| Routed scale records | 247296 | 247296 |
| Shared physical mappings | 276 | 276 |
| Direct target mappings | 1693 | 1693 |
| Fused targets | 187 | 187 |
| Logical source records | 393 | 393 |
| Logical target records | 417 | 417 |

## Source auxiliary families

| Family | Count | Reason |
|---|---:|---|
| `mm_projector.post_norm.weight` | 1 | text-only converter intentionally excludes multimodal auxiliary |
| `mm_projector.proj.0.weight` | 1 | text-only converter intentionally excludes multimodal auxiliary |
| `mm_projector.proj.2.weight` | 1 | text-only converter intentionally excludes multimodal auxiliary |
| `vision_tower.encoder.blocks.{block}.mlp.fc0.weight` | 27 | text-only converter intentionally excludes multimodal auxiliary |
| `vision_tower.encoder.blocks.{block}.mlp.fc1.weight` | 27 | text-only converter intentionally excludes multimodal auxiliary |
| `vision_tower.encoder.blocks.{block}.norm0.weight` | 27 | text-only converter intentionally excludes multimodal auxiliary |
| `vision_tower.encoder.blocks.{block}.norm1.weight` | 27 | text-only converter intentionally excludes multimodal auxiliary |
| `vision_tower.encoder.blocks.{block}.wo.weight` | 27 | text-only converter intentionally excludes multimodal auxiliary |
| `vision_tower.encoder.blocks.{block}.wqkv.weight` | 27 | text-only converter intentionally excludes multimodal auxiliary |
| `vision_tower.encoder.final_layernorm.weight` | 1 | text-only converter intentionally excludes multimodal auxiliary |
| `vision_tower.patch_embed.pos_emb.weight` | 1 | text-only converter intentionally excludes multimodal auxiliary |
| `vision_tower.patch_embed.proj.weight` | 1 | text-only converter intentionally excludes multimodal auxiliary |

## Family coverage

| Family | Coverage |
|---|---:|
| Router / router bias | 92 / 92 |
| Latent MoE up / down / norm | 92 / 92 / 92 |
| Dense layer 0 gate / up / down | 1 / 1 / 1 |
| Attention norm / FFN norm / output norm | 93 / 93 / 1 |
| Attention output | 93 |
| KDA direct / logical transform | 552 / 276 |
| MLA direct / split sources / split targets | 120 / 24 / 48 |
| Attention Residual fused members / targets | 374 / 187 |
| g_proj KDA / MLA / total | 69 / 24 / 93 |
| Model-level direct | 3 |

Shared-expert metadata records two logical shared experts; the combined gate/up/down projections are mapped one-to-one. A separate shared routing/mixing gate is absent/not applicable. Shared partition/order is NOT_CHECKED.

## Type transitions and validation

| Source dtype | Physical records |
|---|---:|
| `BF16` | 2122 |
| `F32` | 506 |
| `U8` | 494592 |

| Target GGML type | Physical targets |
|---|---:|
| `F32` | 1181 |
| `IQ1_S` | 209 |
| `IQ2_XXS` | 56 |
| `IQ3_XXS` | 11 |
| `Q8_0` | 1116 |

Transition failures: 0; shape failures: 0; axis failures: 0.

| Duplicate or ambiguity class | Count |
|---|---:|
| Duplicate source physical assignments | 0 |
| Duplicate source logical assignments | 0 |
| Duplicate target physical assignments | 0 |
| Duplicate mapping-result identities | 0 |
| Duplicate source-group assignments | 0 |
| Ambiguous lookups | 0 |

## Unresolved families

- Source unresolved: 0 across 0 families.
- Target unresolved: 0 across 0 families.

## Findings
- **PASS** MAPGROUP-001: source accounting reconstructs 497220/497220
- **PASS** MAPGROUP-002: target accounting reconstructs 2573/2573
- **PASS** MAPGROUP-003: mapping policy digest 0201db3da3e2e6f47596b1cdb369d8004a34c7340a4ae5bca281004bb6e72f6c
- **PASS** MAPGROUP-006: duplicate assignments 0; ambiguous lookups 0
- **PASS** MAPGROUP-011: routed groups 276/276
- **PASS** MAPGROUP-012: packed targets 276/276
- **PASS** MAPGROUP-013: shared mappings 276/276
- **PASS** MAPGROUP-014: g_proj logical realizations 93/93
- **PASS** MAPGROUP-015: unresolved target descriptors 0
- **PASS** MAPGROUP-016: direct source mappings 1693/1693
- **PASS** MAPGROUP-017: historical source census reclassified 282 text and intentionally excluded 168
- **PASS** MAPGROUP-018: shape=0,axis=0,type=0,missing_source=0,missing_target=0
- **UNAVAILABLE** MAPGROUP-019: artifact-specific conversion provenance is unavailable
- **NOT_CHECKED** MAPGROUP-020: payload packing, transforms, values, and shared partition were not checked

Payload packing correctness: NOT_CHECKED.
Descriptor-level structural mapping does not prove payload order, quantization fidelity, or runtime parity.
