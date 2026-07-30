# Model Artifact Structural Comparison

## Executive Summary

**STRUCTURALLY\_EQUIVALENT\_WITH\_QUANTIZATION\_DIFFERENCES**

The verified artifact variants preserve the recorded target identities, normalized tensor structures, ontology, and semantic-mapping relations when all structural controls pass.

This comparison does not establish payload equality, numerical quantization fidelity, tokenizer equivalence, runtime equivalence, or comparative model quality.

## Baseline and Candidate

- Baseline: `unsloth/Kimi\-K3\-GGUF` / `UD\-IQ1\_M`
- Candidate: `unsloth/Kimi\-K3\-GGUF` / `UD\-Q4\_K\_XL`
- Baseline revision: `3d4b61ab4b6789d401191c476cbb4567246db8f5`
- Candidate revision: `3d4b61ab4b6789d401191c476cbb4567246db8f5`
- Comparison digest: `a2dc47c278642446813f6f1434cca0cebfe3639c7b89c4e6d22da8f25679e490`
- Comparison-policy digest: `ccd616c38828ac3397485195fbb17ae3edeeb3aca12affab188241e78154068e`
- Profile-policy digest: `a1eb5d64f3e6ef67c2870590a101b326d00e0c1e1ef40e9ddbf2ad39fe4cad69`

## Repository Layout

- Same immutable revision: True
- Shards: 15 / 32
- Repository bytes: 648872012448 / 1508668683104
- Repository file-byte ratio (candidate / baseline): 4285990577 / 1843386399 (2.325063578274)
- Header bytes accepted: 7098363 / 7100165
- Range requests: 219 / 381
- Tensor payload bytes accepted: 0 / 0

## Metadata

- Equal: 62
- Different and allowed: 2
- Different and unexpected: 0
- Missing baseline / candidate: 0 / 0

## Tensor Identity and Shapes

- Matched identities: 2573
- Baseline-only / candidate-only: 0 / 0
- Normalized shape matches: 2573
- Physical-only differences: 0
- Incompatible shapes: 0
- Encoded tensor bytes: 648864913792 / 1508661582208
- Encoded-span ratio (candidate / baseline): 11786418611 / 5069257139
- Bounded spans: 2573 / 2573
- Overlaps: 0 / 0

## GGML Type Transitions

| Family | Baseline type | Candidate type | State | Allowed | Count |
| --- | --- | --- | --- | --- | ---: |
| attention\.input\_norm | F32 | F32 | kept\_unquantized | True | 93 |
| attention\.output | Q8\_0 | Q8\_0 | unchanged | True | 93 |
| attn\_res\.attention\_score | F32 | F32 | kept\_unquantized | True | 93 |
| attn\_res\.ffn\_score | F32 | F32 | kept\_unquantized | True | 93 |
| attn\_res\.output\_score | F32 | F32 | kept\_unquantized | True | 1 |
| dense\.down | Q8\_0 | Q8\_0 | unchanged | True | 1 |
| dense\.gate | Q8\_0 | Q8\_0 | unchanged | True | 1 |
| dense\.up | Q8\_0 | Q8\_0 | unchanged | True | 1 |
| ffn\.input\_norm | F32 | F32 | kept\_unquantized | True | 93 |
| g\_proj\.kda | Q8\_0 | Q8\_0 | unchanged | True | 69 |
| g\_proj\.mla | Q8\_0 | Q8\_0 | unchanged | True | 24 |
| kda\.a | F32 | F32 | kept\_unquantized | True | 69 |
| kda\.beta | F32 | F32 | kept\_unquantized | True | 69 |
| kda\.dt\_bias | F32 | F32 | kept\_unquantized | True | 69 |
| kda\.forget\_a | Q8\_0 | Q8\_0 | unchanged | True | 69 |
| kda\.forget\_b | Q8\_0 | Q8\_0 | unchanged | True | 69 |
| kda\.key | Q8\_0 | Q8\_0 | unchanged | True | 69 |
| kda\.key\_conv | F32 | F32 | kept\_unquantized | True | 69 |
| kda\.output\_norm | F32 | F32 | kept\_unquantized | True | 69 |
| kda\.query | Q8\_0 | Q8\_0 | unchanged | True | 69 |
| kda\.query\_conv | F32 | F32 | kept\_unquantized | True | 69 |
| kda\.value | Q8\_0 | Q8\_0 | unchanged | True | 69 |
| kda\.value\_conv | F32 | F32 | kept\_unquantized | True | 69 |
| mla\.key\_b | Q8\_0 | Q8\_0 | unchanged | True | 24 |
| mla\.kv\_a\_mqa | Q8\_0 | Q8\_0 | unchanged | True | 24 |
| mla\.kv\_a\_norm | F32 | F32 | kept\_unquantized | True | 24 |
| mla\.query\_a | Q8\_0 | Q8\_0 | unchanged | True | 24 |
| mla\.query\_a\_norm | F32 | F32 | kept\_unquantized | True | 24 |
| mla\.query\_b | Q8\_0 | Q8\_0 | unchanged | True | 24 |
| mla\.value\_b | Q8\_0 | Q8\_0 | unchanged | True | 24 |
| model\.output\_norm | F32 | F32 | kept\_unquantized | True | 1 |
| model\.output\_projection | Q8\_0 | Q8\_0 | unchanged | True | 1 |
| model\.token\_embedding | Q8\_0 | Q8\_0 | unchanged | True | 1 |
| moe\.latent\_down | Q8\_0 | Q8\_0 | unchanged | True | 92 |
| moe\.latent\_norm | F32 | F32 | kept\_unquantized | True | 92 |
| moe\.latent\_up | Q8\_0 | Q8\_0 | unchanged | True | 92 |
| moe\.packed\_down | IQ1\_S | MXFP4 | quantization\_family\_changed | True | 81 |
| moe\.packed\_down | IQ3\_XXS | MXFP4 | quantization\_family\_changed | True | 11 |
| moe\.packed\_gate | IQ1\_S | MXFP4 | quantization\_family\_changed | True | 64 |
| moe\.packed\_gate | IQ2\_XXS | MXFP4 | quantization\_family\_changed | True | 28 |
| moe\.packed\_up | IQ1\_S | MXFP4 | quantization\_family\_changed | True | 64 |
| moe\.packed\_up | IQ2\_XXS | MXFP4 | quantization\_family\_changed | True | 28 |
| moe\.router | F32 | F32 | kept\_unquantized | True | 92 |
| moe\.router\_bias | F32 | F32 | kept\_unquantized | True | 92 |
| moe\.shared\_down | Q8\_0 | Q8\_0 | unchanged | True | 92 |
| moe\.shared\_gate | Q8\_0 | Q8\_0 | unchanged | True | 92 |
| moe\.shared\_up | Q8\_0 | Q8\_0 | unchanged | True | 92 |

## Acceptance Profiles

| Profile | Result | Warnings | Failed controls |
| --- | --- | --- | --- |
| structural\_equivalence | **SATISFIED\_WITH\_WARNINGS** | artifact\_specific\_provenance\_available | — |
| quantization\_layout\_comparison | **SATISFIED** | — | — |
| release\_variant\_consistency | **SATISFIED\_WITH\_WARNINGS** | artifact\_specific\_provenance\_available | — |
| full\_numerical\_equivalence | **NOT\_SATISFIED** | — | artifact\_specific\_provenance\_available, payload\_equality, payload\_equality\_checked, quantization\_fidelity\_checked, quantization\_numerical\_fidelity, runtime\_parity, runtime\_parity\_checked, tokenizer\_parity, tokenizer\_parity\_checked |

## Evidence Boundaries

- Cross-quantization structural comparison: checked
- Payload equality: not checked
- Quantization numerical fidelity: not checked
- Tokenizer parity: not checked
- Runtime parity: not checked

## Limitations

- The comparison is descriptor\-level and evidence\-level only\.
- Allowed GGML type transitions do not establish numerical quality\.
- Encoded size ratios describe physical storage, not compression quality\.
- Payload equality, tokenizer parity, and runtime parity were not checked\.
- Artifact\-specific conversion provenance remains unavailable unless independently supplied\.

## Artifact Index

- `inventories/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-IQ1\_M\.semantic\-mapping\.inventory\.json` — baseline\_mapping, `f380d9b9ee8060cf205eef4c69e58353608f148f2ea59ba680e7af522e034afb`, 3377729 bytes
- `inventories/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-IQ1\_M\.kimi\-k3\-ontology\.inventory\.json` — baseline\_ontology, `13a81e3f75b71266473bd1ab7588c6be3d47033245a2b96a80fb102d1ca1081f`, 323883 bytes
- `inventories/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-IQ1\_M\.split\.inventory\.json` — baseline\_split, `1aa8e70e92cda916aa552e468c49410389bc3cf71f1f56163716f68078bb04c7`, 1927690 bytes
- `validations/unsloth\_Kimi\-K3\-GGUF\_UD\-IQ1\_M\.validation\.inventory\.json` — baseline\_validation, `54b7f52695634878fcde5b9d4d9e89e4c8f6fd4b32060f2be81ebe7876e003c8`, 125305 bytes
- `inventories/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-Q4\_K\_XL\.semantic\-mapping\.inventory\.json` — candidate\_mapping, `6578d6a2d12a3f3950d6c937a1d17f240105e74e783b5e16dcdc13861ed51dda`, 3377549 bytes
- `inventories/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-Q4\_K\_XL\.kimi\-k3\-ontology\.inventory\.json` — candidate\_ontology, `a7dccbc370338778871bee07e2079b225e57e8fe0102f09587837b95e994ac6a`, 324844 bytes
- `inventories/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-Q4\_K\_XL\.split\.inventory\.json` — candidate\_split, `e30a2b8019258213d893d10caff79860bd07a3262ad6e5cc2352884b7cc4f51c`, 1956449 bytes
- `validations/unsloth\_Kimi\-K3\-GGUF\_UD\-Q4\_K\_XL\.validation\.inventory\.json` — candidate\_validation, `3b7bbfc865c235544574113dd93ab91d05d72aebafaf226f3b3c25a56fb02a34`, 175257 bytes

## Findings

- **PASS** COMPARE\-001: Baseline evidence verifies\.
- **PASS** COMPARE\-002: Candidate evidence verifies\.
- **PASS** COMPARE\-003: Repository identities are compatible\.
- **PASS** COMPARE\-004: Immutable revisions are compatible\.
- **PASS** COMPARE\-005: Architecture metadata is equivalent\.
- **PASS** COMPARE\-006: Tensor identity sets are equivalent\.
- **PASS** COMPARE\-007: Normalized shapes are equivalent\.
- **PASS** COMPARE\-008: Layer and family coverage is equivalent\.
- **PASS** COMPARE\-009: Both split layouts are structurally valid\.
- **PASS** COMPARE\-010: GGML transitions are classified\.
- **PASS** COMPARE\-011: Type transitions are allowed by structural policy\.
- **PASS** COMPARE\-012: Ontology structures are equivalent\.
- **PASS** COMPARE\-013: Semantic\-mapping structures are equivalent\.
- **PASS** COMPARE\-014: Source accounting is equivalent\.
- **PASS** COMPARE\-015: Target logical accounting is equivalent\.
- **PASS** COMPARE\-016: Encoded spans are structurally valid\.
- **PASS** COMPARE\-017: Acceptance profiles were reconstructed\.
- **NOT\_CHECKED** COMPARE\-018: Payload equality was not checked\.
- **NOT\_CHECKED** COMPARE\-019: Quantization numerical fidelity was not checked\.
- **NOT\_CHECKED** COMPARE\-020: Runtime parity was not checked\.
- **PASS** COMPARE\-021: Comparison uses deterministic canonical serialization\.
