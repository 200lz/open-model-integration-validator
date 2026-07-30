# Independent Model Validation — Kimi K3 UD\-IQ1\_M

## Executive Summary

**STRUCTURALLY\_VALIDATED\_WITH\_LIMITATIONS**

The pinned UD-IQ1_M split GGUF set is structurally validated under the recorded repository, HTTP Range, GGUF header, split-container, Kimi K3 ontology, and semantic-mapping policies.

This result is not evidence of tensor payload integrity, numerical quantization fidelity, tokenizer parity, runtime equivalence, or artifact-specific conversion provenance.

## Subject Identity

- Repository: `unsloth/Kimi\-K3\-GGUF`
- Requested revision: `main`
- Resolved revision: `3d4b61ab4b6789d401191c476cbb4567246db8f5`
- Selection: `UD\-IQ1\_M/\*\.gguf`
- Model pack: `kimi-k3` v3
- Model-pack digest: `6f151e70f2b28e367b84c59db6e7ad4184271b1cc7f518320043e3456c3ef288`
- Evidence-graph digest: `ea08a66295a72ebb1331196e9cd3c94845fc21208b08240447828ae77b7db2eb`
- Profile-policy digest: `ec745ebc9c7a7f1b51b115ab049a6507e76d5902aa98d8d7a27c70497886bdc7`
- Artifact-index digest: `6059d6a460f5d417173c4346f0c4e5d6c26a4887e488ea7c24d5e473ca6094a6`
- Validation inventory digest: `54b7f52695634878fcde5b9d4d9e89e4c8f6fd4b32060f2be81ebe7876e003c8`
- Validation report digest: `76dd9f56bf8e72504ac920d4a79bfb45b610a5520709346ad7c0c76ec63f3a4b`

## Validation Stages

| Stage | Status | Scope | Limitation / next evidence |
| --- | --- | --- | --- |
| artifact\_specific\_provenance | **UNAVAILABLE** | — | no artifact\-specific conversion\-run provenance exists; signed conversion\-run provenance |
| complete\_header | **PASS** | complete GGUF headers for all shards | does not establish tensor payload or numerical correctness |
| converter\_rule\_support | **AVAILABLE** | pinned converter code supports recorded relations | does not identify the converter run that produced this artifact; artifact\-specific conversion provenance |
| deterministic\_verification | **PASS** | canonical digests and dependency reconstruction | determinism applies to evidence artifacts, not model execution |
| file\_prefix | **PASS** | GGUF magic and version prefix | — |
| payload\_integrity | **NOT\_CHECKED** | — | no tensor payload bytes or hashes were accessed; payload digest evidence |
| payload\_span\_bounds | **PASS** | computed descriptor payload spans fit shard bounds | bounds do not prove payload bytes; payload integrity evidence |
| quantization\_fidelity | **NOT\_CHECKED** | — | allowed type transitions are not numerical fidelity; numerical quantization comparison |
| range\_semantics | **PASS** | bounded byte ranges | remote evidence was generated previously |
| repository\_identity | **PASS** | fixed repository and immutable revision | — |
| repository\_layout | **PASS** | 15\-file selected split layout | — |
| runtime\_parity | **NOT\_CHECKED** | — | no backend execution, logits, or runtime output; runtime parity evidence |
| split\_container | **PASS** | split identity and descriptor aggregation | does not establish tensor payload or numerical correctness |
| structural\_semantic\_mapping | **PASS** | descriptor\-level source\-to\-target assignments | does not establish tensor payload or numerical correctness; payload relation verification |
| target\_ontology | **PASS** | Kimi K3 target ontology | does not establish tensor payload or numerical correctness |
| tokenizer\_parity | **NOT\_CHECKED** | — | tokenizer arrays were not compared; tokenizer parity evidence |

## Acceptance Profiles

| Profile | Result | Warnings | Failed requirements |
| --- | --- | ---: | ---: |
| community\_structural | **SATISFIED** | 0 | 0 |
| vendor\_release\_structural | **SATISFIED\_WITH\_WARNINGS** | 2 | 0 |
| enterprise\_offline\_structural | **SATISFIED\_WITH\_WARNINGS** | 5 | 0 |
| regulated\_deployment\_full | **NOT\_SATISFIED** | 0 | 5 |

## Engineering Summary

- Selected shards: 15
- Repository bytes: 648872012448
- Accepted header bytes: 7098363
- Range requests: 219
- Tensor payload bytes accepted: 0
- Global/aggregated tensors: 2573/2573
- Duplicate/conflicting names: 0/0
- Computable/bounded spans: 2573/2573
- Span overlaps: 0

### Architecture

- Architecture: kimi\-k3
- Layers: 93
- KDA / MLA: 69 / 24
- Target tensors: 2573
- Routed experts: 896
- Experts used: 16
- Shared experts: 2
- Attention Residual block size: 12

### Source and Target Accounting

- Source records: 497220 (unresolved 0)
- Historical 450: 282 newly classified text + 168 source-only vision/mm-projector auxiliary
- Target descriptors: 2573 (unresolved 0)

| Accounting side | State | Count |
| --- | --- | ---: |
| source | directly\_mapped | 1693 |
| source | fused\_mapping\_member | 374 |
| source | intentionally\_excluded | 0 |
| source | invalid | 0 |
| source | logical\_realization\_source | 393 |
| source | packed\_group\_member | 494592 |
| source | source\_only\_auxiliary | 168 |
| source | unclassified | 0 |
| source | unsupported | 0 |
| target | directly\_realized | 1693 |
| target | fused\_target | 187 |
| target | invalid | 0 |
| target | logical\_realization\_target | 417 |
| target | packed\_group\_target | 276 |
| target | target\_only\_auxiliary | 0 |
| target | unclassified | 0 |
| target | unsupported | 0 |

### Semantic Mapping Domains

| Domain | Source | Target | Relation | Evidence | Payload |
| --- | ---: | ---: | --- | --- | --- |
| routed\_experts | 494592/494592 | 276/276 | many\_to\_one\_packed | converter\_rule\_support | **NOT\_CHECKED** |
| shared\_experts | 276/276 | 276/276 | one\_to\_one | converter\_rule\_support | **NOT\_CHECKED** |
| router\_and\_bias | 184/184 | 184/184 | one\_to\_one | converter\_rule\_support | **NOT\_CHECKED** |
| latent\_moe | 276/276 | 276/276 | one\_to\_one | converter\_rule\_support | **NOT\_CHECKED** |
| dense\_layer\_0 | 3/3 | 3/3 | one\_to\_one | converter\_rule\_support | **NOT\_CHECKED** |
| per\_layer\_norms | 186/186 | 186/186 | one\_to\_one | converter\_rule\_support | **NOT\_CHECKED** |
| attention\_output | 93/93 | 93/93 | one\_to\_one | converter\_rule\_support | **NOT\_CHECKED** |
| kda | 828/828 | 828/828 | one\_to\_one\_and\_logical\_realization | converter\_rule\_support | **NOT\_CHECKED** |
| mla | 144/144 | 168/168 | one\_to\_one\_and\_one\_to\_many\_split | converter\_rule\_support | **NOT\_CHECKED** |
| attention\_residual | 374/374 | 187/187 | fused\_target | converter\_rule\_support | **NOT\_CHECKED** |
| g\_proj | 93/93 | 93/93 | logical\_realization | converter\_rule\_support | **NOT\_CHECKED** |
| model\_level | 3/3 | 3/3 | one\_to\_one | converter\_rule\_support | **NOT\_CHECKED** |

## Commercial Acceptance Controls

| Control | Status | Commercial interpretation | Required next step |
| --- | --- | --- | --- |
| Artifact identity | **PASS** | Structural control accepted within its recorded scope\. | — |
| Immutable revision | **PASS** | Structural control accepted within its recorded scope\. | — |
| Repository completeness | **PASS** | Structural control accepted within its recorded scope\. | — |
| Remote byte\-range safety | **PASS** | Structural control accepted within its recorded scope\. | — |
| GGUF header completeness | **PASS** | Structural control accepted within its recorded scope\. | — |
| Split consistency | **PASS** | Structural control accepted within its recorded scope\. | — |
| Tensor descriptor completeness | **PASS** | Structural control accepted within its recorded scope\. | — |
| Payload\-span bounds | **PASS** | Structural control accepted within its recorded scope\. | payload integrity evidence |
| Target architecture ontology | **PASS** | Structural control accepted within its recorded scope\. | — |
| Structural semantic mapping | **PASS** | Structural control accepted within its recorded scope\. | payload relation verification |
| Converter rule evidence | **AVAILABLE** | Supporting converter rules are pinned; artifact production is not proven\. | artifact\-specific conversion provenance |
| Artifact\-specific provenance | **UNAVAILABLE** | This control cannot support an equivalence or deployment claim\. | signed conversion\-run provenance |
| Payload integrity | **NOT\_CHECKED** | This control cannot support an equivalence or deployment claim\. | payload digest evidence |
| Quantization fidelity | **NOT\_CHECKED** | This control cannot support an equivalence or deployment claim\. | numerical quantization comparison |
| Tokenizer parity | **NOT\_CHECKED** | This control cannot support an equivalence or deployment claim\. | tokenizer parity evidence |
| Runtime parity | **NOT\_CHECKED** | This control cannot support an equivalence or deployment claim\. | runtime parity evidence |

## Verified

- fixed repository identity and immutable revision
- selected remote file set, sizes, and stable identities where available
- filename split layout and bounded HTTP Range semantics
- GGUF version and complete headers
- split metadata, shard identity, and global descriptor aggregation
- payload\-span structural bounds without payload access
- Kimi K3 target ontology and architecture schedule
- source and target identity accounting
- descriptor\-level structural semantic mapping
- pinned converter\-code relation evidence
- deterministic artifact verification and regeneration

## Not Verified

- actual source\-to\-target payload equality
- routed expert numerical packing order and scale numerical association
- A\_log numerical transform result
- convolution reshape payload correctness
- MLA split and transpose payload correctness
- Attention Residual fusion payload correctness
- tensor payload integrity
- quantization error or quality
- tokenizer equivalence
- logits, backend execution, and runtime parity
- artifact\-specific conversion\-run provenance

## Limitations

- Structural descriptor validation does not establish tensor payload integrity\.
- Converter\-code support does not establish which converter produced the published artifact\.
- Allowed GGML type transitions do not establish numerical quantization fidelity\.
- Tokenizer arrays, logits, backend execution, and runtime behavior were not compared\.
- The result supports structural integration acceptance only under profiles that permit these limitations\.

## Unavailable Evidence

- artifact\_specific\_provenance: no artifact\-specific conversion\-run provenance exists

## Not-Checked Evidence

- payload\_integrity: no tensor payload bytes or hashes were accessed
- quantization\_fidelity: allowed type transitions are not numerical fidelity
- runtime\_parity: no backend execution, logits, or runtime output
- tokenizer\_parity: tokenizer arrays were not compared

## Reproducibility

Offline verification requires only the repository-relative artifacts in the embedded index.

- `omiv independent\-validation\-inventory\-verify \-\-input validations/unsloth\_Kimi\-K3\-GGUF\_UD\-IQ1\_M\.validation\.inventory\.json` — Verify the final inventory and every dependency\.
- `omiv report\-verify \-\-input reports/validation/unsloth\_Kimi\-K3\-GGUF\_UD\-IQ1\_M\.validation\.report\.json` — Verify the final report and reconstruct its results\.

## Artifact Index

- `reports/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-IQ1\_M\_shard1\.prefix\.report\.json` — prefix\_report, `c5ca33b43e208fc37c5ac2016f530aabc05642c24dcc915df61f96aff161a1b4`, 2721 bytes
- `snapshots/huggingface/unsloth\_Kimi\-K3\-GGUF\_UD\-IQ1\_M\.snapshot\.json` — repository\_snapshot, `a450f338b1582101b375e815682ee01215145bd5d6782014d954f130b4295520`, 7486 bytes
- `reports/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-IQ1\_M\.snapshot\.report\.json` — snapshot\_report, `ea7be6d02ddbf17ab0eb04ff9775bfcd6f21f0f9456947d158a973b8bb7f5cc4`, 4341 bytes
- `inventories/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-IQ1\_M/shards/Kimi\-K3\-UD\-IQ1\_M\-00001\-of\-00015\.header\.inventory\.json` — shard\_01\_header\_inventory, `ad657eab768dc46fb07054eb1fdfaa5e1fac48f389c78523b38bef63c2bd7a8d`, 46706 bytes
- `reports/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-IQ1\_M\_shard1\.header\.report\.json` — shard\_1\_header\_report, `5934de5d8ecb9ed921e7766651929eec1d7173912633bb9c8cfd442eb2b49e6c`, 53623 bytes
- `inventories/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-IQ1\_M/shards/Kimi\-K3\-UD\-IQ1\_M\-00002\-of\-00015\.header\.inventory\.json` — shard\_02\_header\_inventory, `573f7b53c497a91d030dc2e993f3e1c7348a4252a99a211a81d622363274e121`, 99370 bytes
- `inventories/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-IQ1\_M/shards/Kimi\-K3\-UD\-IQ1\_M\-00003\-of\-00015\.header\.inventory\.json` — shard\_03\_header\_inventory, `92ec5e106b1c6db7ce0645efc8fa3aefcabb7f1f132a34206150ee2784a1462c`, 90628 bytes
- `inventories/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-IQ1\_M/shards/Kimi\-K3\-UD\-IQ1\_M\-00004\-of\-00015\.header\.inventory\.json` — shard\_04\_header\_inventory, `00bb305d6673b26631fb3f7aaa388464f5ed3e6e83eeb19a46084daeffff990c`, 105098 bytes
- `inventories/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-IQ1\_M/shards/Kimi\-K3\-UD\-IQ1\_M\-00005\-of\-00015\.header\.inventory\.json` — shard\_05\_header\_inventory, `37f94765e7236b51d036699a1ced1d6f05ba1c17152126f30f2b64e3fdc7008c`, 80679 bytes
- `inventories/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-IQ1\_M/shards/Kimi\-K3\-UD\-IQ1\_M\-00006\-of\-00015\.header\.inventory\.json` — shard\_06\_header\_inventory, `f523a3a58cefed8872b988aa8c1429937a03a35d3abaad3578befa64250d86b9`, 105102 bytes
- `inventories/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-IQ1\_M/shards/Kimi\-K3\-UD\-IQ1\_M\-00007\-of\-00015\.header\.inventory\.json` — shard\_07\_header\_inventory, `903b73aa5bc85db3b48a5649fa49c7c777825ca72d0ac6419b3c4cc2930a5c2e`, 85195 bytes
- `inventories/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-IQ1\_M/shards/Kimi\-K3\-UD\-IQ1\_M\-00008\-of\-00015\.header\.inventory\.json` — shard\_08\_header\_inventory, `c327c2637cc8063ba8191c6ba87d1fb39d414518df4feec70d8a2499a71e501b`, 94338 bytes
- `inventories/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-IQ1\_M/shards/Kimi\-K3\-UD\-IQ1\_M\-00009\-of\-00015\.header\.inventory\.json` — shard\_09\_header\_inventory, `12e17207cc5600363b56edb6caeb15fb5fb9c2b3f1c736fa671a92c1f934fd0c`, 89299 bytes
- `inventories/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-IQ1\_M/shards/Kimi\-K3\-UD\-IQ1\_M\-00010\-of\-00015\.header\.inventory\.json` — shard\_10\_header\_inventory, `777c196329918092550868f4a22131536372b4370a31cc06734c5557572b1fd0`, 97509 bytes
- `inventories/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-IQ1\_M/shards/Kimi\-K3\-UD\-IQ1\_M\-00011\-of\-00015\.header\.inventory\.json` — shard\_11\_header\_inventory, `061a95b34670c69e4c223b81684de0dddc4cfab3b93c81b5b6c46adfb819def9`, 105112 bytes
- `inventories/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-IQ1\_M/shards/Kimi\-K3\-UD\-IQ1\_M\-00012\-of\-00015\.header\.inventory\.json` — shard\_12\_header\_inventory, `0dd5d96abf86e8a290e767cdada786716b4558623bcfcc353783725f5ab62b65`, 82154 bytes
- `inventories/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-IQ1\_M/shards/Kimi\-K3\-UD\-IQ1\_M\-00013\-of\-00015\.header\.inventory\.json` — shard\_13\_header\_inventory, `daf377ad7624e8c0a8a5bf8aa4fc7159e9a3e2089d7b2c988edbe51bd5801bdb`, 92935 bytes
- `inventories/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-IQ1\_M/shards/Kimi\-K3\-UD\-IQ1\_M\-00014\-of\-00015\.header\.inventory\.json` — shard\_14\_header\_inventory, `30b69a64b113f7f4d3f5a236e8b21ebb321c7d6f915478b2a663d61cb24ce771`, 93805 bytes
- `inventories/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-IQ1\_M/shards/Kimi\-K3\-UD\-IQ1\_M\-00015\-of\-00015\.header\.inventory\.json` — shard\_15\_header\_inventory, `cad7812fd44048000b91f36ae1cac417d697b8ef3ab6475760ebc6f769537e1b`, 20730 bytes
- `inventories/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-IQ1\_M\.split\.inventory\.json` — split\_inventory, `1aa8e70e92cda916aa552e468c49410389bc3cf71f1f56163716f68078bb04c7`, 1927690 bytes
- `reports/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-IQ1\_M\.split\.report\.json` — split\_report, `42d8d90ea9872527deceb1620fda8bdd73baf8fd4bfc5cde2d886cb78a771b29`, 2050414 bytes
- `inventories/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-IQ1\_M\.kimi\-k3\-ontology\.inventory\.json` — target\_ontology\_inventory, `13a81e3f75b71266473bd1ab7588c6be3d47033245a2b96a80fb102d1ca1081f`, 323883 bytes
- `reports/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-IQ1\_M\.kimi\-k3\-ontology\.report\.json` — target\_ontology\_report, `679ed30f030237868a832615252b03601c7f3deb09f025a2251d1ab73d9559a0`, 360918 bytes
- `inventories/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-IQ1\_M\.semantic\-mapping\.inventory\.json` — semantic\_mapping\_inventory, `f380d9b9ee8060cf205eef4c69e58353608f148f2ea59ba680e7af522e034afb`, 3377729 bytes
- `reports/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-IQ1\_M\.semantic\-mapping\.report\.json` — semantic\_mapping\_report, `a82b347f69fab5731a31e71a888e0b4acde4dfb4bb94ce34f0880f1cb292ded3`, 19510 bytes
- `reports/raw/kimi\_k3\_tensors\.json` — source\_checkpoint\_inventory, `15a6757becb69c56492fdb630d6853696082a9ec6109bcea05f387a5052ea469`, 115542096 bytes

## Findings

- **PASS** VALIDATE\-001: Subject identity is pinned\.
- **PASS** VALIDATE\-002: Evidence graph is complete and acyclic\.
- **PASS** VALIDATE\-003: All required artifact digests verify\.
- **PASS** VALIDATE\-004: Immutable repository evidence is valid\.
- **PASS** VALIDATE\-005: Bounded remote inspection evidence is valid\.
- **PASS** VALIDATE\-006: Complete GGUF header evidence is valid\.
- **PASS** VALIDATE\-007: Split\-container evidence is valid\.
- **PASS** VALIDATE\-008: Target ontology evidence is valid\.
- **PASS** VALIDATE\-009: Structural semantic\-mapping evidence is valid\.
- **PASS** VALIDATE\-010: Model\-pack and policy identities are valid\.
- **PASS** VALIDATE\-011: Source accounting is complete\.
- **PASS** VALIDATE\-012: Target accounting is complete\.
- **AVAILABLE** VALIDATE\-013: Pinned converter\-rule evidence is available\.
- **UNAVAILABLE** VALIDATE\-014: Artifact\-specific conversion provenance is unavailable\.
- **NOT\_CHECKED** VALIDATE\-015: Tensor payload integrity was not checked\.
- **NOT\_CHECKED** VALIDATE\-016: Numerical quantization fidelity was not checked\.
- **NOT\_CHECKED** VALIDATE\-017: Tokenizer parity was not checked\.
- **NOT\_CHECKED** VALIDATE\-018: Runtime parity was not checked\.
- **PASS** VALIDATE\-019: Evidence limitations are explicit and non\-empty\.
- **PASS** VALIDATE\-020: The final bundle uses deterministic canonical serialization\.
