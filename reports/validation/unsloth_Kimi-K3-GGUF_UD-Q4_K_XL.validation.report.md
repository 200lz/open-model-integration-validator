# Independent Model Validation — Kimi K3 UD\-Q4\_K\_XL

## Executive Summary

**STRUCTURALLY\_VALIDATED\_WITH\_LIMITATIONS**

The pinned UD-Q4_K_XL split GGUF set is structurally validated under the recorded repository, HTTP Range, GGUF header, split-container, Kimi K3 ontology, and semantic-mapping policies.

This result is not evidence of tensor payload integrity, numerical quantization fidelity, tokenizer parity, runtime equivalence, or artifact-specific conversion provenance.

## Subject Identity

- Repository: `unsloth/Kimi\-K3\-GGUF`
- Requested revision: `main`
- Resolved revision: `3d4b61ab4b6789d401191c476cbb4567246db8f5`
- Selection: `UD\-Q4\_K\_XL/\*\.gguf`
- Model pack: `kimi-k3` v3
- Model-pack digest: `6f151e70f2b28e367b84c59db6e7ad4184271b1cc7f518320043e3456c3ef288`
- Evidence-graph digest: `f4ebc3b3ec9de76fc26d1f23ea9c9755a88e9c53099c70f3d79a166af768109b`
- Profile-policy digest: `ec745ebc9c7a7f1b51b115ab049a6507e76d5902aa98d8d7a27c70497886bdc7`
- Artifact-index digest: `edf368d6550f38f47a918289212cf068e75dc81ca37a3f7f3e143865711486e0`
- Validation inventory digest: `3b7bbfc865c235544574113dd93ab91d05d72aebafaf226f3b3c25a56fb02a34`
- Validation report digest: `f4ed5f17b4b5195ebebd1f21f7899d042874c3006d46fd705ebfb7d6f70ee509`

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

- Selected shards: 32
- Repository bytes: 1508668683104
- Accepted header bytes: 7100165
- Range requests: 381
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

- `omiv independent\-validation\-inventory\-verify \-\-input validations/unsloth\_Kimi\-K3\-GGUF\_UD\-Q4\_K\_XL\.validation\.inventory\.json` — Verify the final inventory and every dependency\.
- `omiv report\-verify \-\-input reports/validation/unsloth\_Kimi\-K3\-GGUF\_UD\-Q4\_K\_XL\.validation\.report\.json` — Verify the final report and reconstruct its results\.

## Artifact Index

- `reports/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-Q4\_K\_XL\_shard1\.prefix\.report\.json` — prefix\_report, `8b1294201d1c24074778949e9a334b16df7d9f0a06ed2a797532b128cd9dbbe0`, 2729 bytes
- `snapshots/huggingface/unsloth\_Kimi\-K3\-GGUF\_UD\-Q4\_K\_XL\.snapshot\.json` — repository\_snapshot, `845df5f9ddfd88c6abe4778ac9924fb68bc0c247380dfa580a0683b07d9547c0`, 14804 bytes
- `reports/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-Q4\_K\_XL\.snapshot\.report\.json` — snapshot\_report, `165075db4049c0377e2acd5ae6ecf054fa9e65f354475d527cec226ecb24748b`, 5785 bytes
- `inventories/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-Q4\_K\_XL/shards/Kimi\-K3\-UD\-Q4\_K\_XL\-00001\-of\-00032\.header\.inventory\.json` — shard\_01\_header\_inventory, `17e7a23cc413b5983293ef45f85153ef5b0a69a0f1728f55468bbaf529440004`, 46710 bytes
- `reports/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-Q4\_K\_XL\_shard1\.header\.report\.json` — shard\_1\_header\_report, `5973e24f8ceae88c236749678497239f8354a8690209bd0151abfc4e5ca0b20b`, 53627 bytes
- `inventories/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-Q4\_K\_XL/shards/Kimi\-K3\-UD\-Q4\_K\_XL\-00002\-of\-00032\.header\.inventory\.json` — shard\_02\_header\_inventory, `469412c1c21169e05dbff14ff5e958b599f71d8244311e5384f1ea54389abe23`, 52586 bytes
- `inventories/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-Q4\_K\_XL/shards/Kimi\-K3\-UD\-Q4\_K\_XL\-00003\-of\-00032\.header\.inventory\.json` — shard\_03\_header\_inventory, `f7b5d7f14bcdc90a2baf1a72e82171ed87060c91dcad3c7e0282217475712d66`, 40112 bytes
- `inventories/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-Q4\_K\_XL/shards/Kimi\-K3\-UD\-Q4\_K\_XL\-00004\-of\-00032\.header\.inventory\.json` — shard\_04\_header\_inventory, `8503ac147f9284b3596c6f9edc5511309731650d627179179c805453c559d0ce`, 42351 bytes
- `inventories/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-Q4\_K\_XL/shards/Kimi\-K3\-UD\-Q4\_K\_XL\-00005\-of\-00032\.header\.inventory\.json` — shard\_05\_header\_inventory, `42175161af3c3dcce199fb54dea18a680d2c75e7da90c42030fed7db01e36c76`, 42454 bytes
- `inventories/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-Q4\_K\_XL/shards/Kimi\-K3\-UD\-Q4\_K\_XL\-00006\-of\-00032\.header\.inventory\.json` — shard\_06\_header\_inventory, `c850ac872822a8a0bc47e432dd13dea2303c6673ad07dd55397aef6f1ecc1ad6`, 46937 bytes
- `inventories/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-Q4\_K\_XL/shards/Kimi\-K3\-UD\-Q4\_K\_XL\-00007\-of\-00032\.header\.inventory\.json` — shard\_07\_header\_inventory, `bb27a08bc1412f51fc870165d99d15b889bff7ff1327b26042a7e259c2580e12`, 40201 bytes
- `inventories/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-Q4\_K\_XL/shards/Kimi\-K3\-UD\-Q4\_K\_XL\-00008\-of\-00032\.header\.inventory\.json` — shard\_08\_header\_inventory, `6afda615d9c4a53a9a730349855e3a38ad622221c8c081a21df8c7092c20ad30`, 42443 bytes
- `inventories/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-Q4\_K\_XL/shards/Kimi\-K3\-UD\-Q4\_K\_XL\-00009\-of\-00032\.header\.inventory\.json` — shard\_09\_header\_inventory, `b467b5bf284d4c8530085748dd6164e0c4a35d07b5f6501b00ef7f841b5370d9`, 42448 bytes
- `inventories/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-Q4\_K\_XL/shards/Kimi\-K3\-UD\-Q4\_K\_XL\-00010\-of\-00032\.header\.inventory\.json` — shard\_10\_header\_inventory, `2247539e69b56613519edddbfebe2506a0794d7957892aaeea7874815c160024`, 46937 bytes
- `inventories/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-Q4\_K\_XL/shards/Kimi\-K3\-UD\-Q4\_K\_XL\-00011\-of\-00032\.header\.inventory\.json` — shard\_11\_header\_inventory, `27dae9592a9e4cfff5573128800357ab197ec225572ccedb0256dcd6dc694934`, 40202 bytes
- `inventories/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-Q4\_K\_XL/shards/Kimi\-K3\-UD\-Q4\_K\_XL\-00012\-of\-00032\.header\.inventory\.json` — shard\_12\_header\_inventory, `5dedf7d108317bfeec00251e999246039100285af4be152daff45a467f371b8f`, 42444 bytes
- `inventories/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-Q4\_K\_XL/shards/Kimi\-K3\-UD\-Q4\_K\_XL\-00013\-of\-00032\.header\.inventory\.json` — shard\_13\_header\_inventory, `00c64dc68eca56db49bb4665b4098795dfe544f3b3436f8ad7ea5e50f8ad49ec`, 42449 bytes
- `inventories/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-Q4\_K\_XL/shards/Kimi\-K3\-UD\-Q4\_K\_XL\-00014\-of\-00032\.header\.inventory\.json` — shard\_14\_header\_inventory, `1e9535b6dd8eba2123256d3390138b7d68d438776f4ac97f75abb0a97bfb218a`, 46938 bytes
- `inventories/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-Q4\_K\_XL/shards/Kimi\-K3\-UD\-Q4\_K\_XL\-00015\-of\-00032\.header\.inventory\.json` — shard\_15\_header\_inventory, `e33e7747d3e72b920ffc6a71d95c653f9709254958dbc4ac8a51a585be844cb9`, 40202 bytes
- `inventories/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-Q4\_K\_XL/shards/Kimi\-K3\-UD\-Q4\_K\_XL\-00016\-of\-00032\.header\.inventory\.json` — shard\_16\_header\_inventory, `49cedf495c57791e28e7392b2fc0039b51085519d9ca3ae05dfcae2909594529`, 42444 bytes
- `inventories/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-Q4\_K\_XL/shards/Kimi\-K3\-UD\-Q4\_K\_XL\-00017\-of\-00032\.header\.inventory\.json` — shard\_17\_header\_inventory, `9d376ea2c23e9ea7d94bd3b633d8b6dfdc08e5c0c2334e2ae624e51f85985713`, 42449 bytes
- `inventories/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-Q4\_K\_XL/shards/Kimi\-K3\-UD\-Q4\_K\_XL\-00018\-of\-00032\.header\.inventory\.json` — shard\_18\_header\_inventory, `9c00ebe827879c870733e59670fdaa63d99ad7d2651e9f129bd0add12fc603ab`, 46938 bytes
- `inventories/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-Q4\_K\_XL/shards/Kimi\-K3\-UD\-Q4\_K\_XL\-00019\-of\-00032\.header\.inventory\.json` — shard\_19\_header\_inventory, `6aa697e51cbbb9d37709c8dd3ce401874d26adba275fd38b103368d4f29576e5`, 40202 bytes
- `inventories/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-Q4\_K\_XL/shards/Kimi\-K3\-UD\-Q4\_K\_XL\-00020\-of\-00032\.header\.inventory\.json` — shard\_20\_header\_inventory, `f6ca216881176b29923cecbd2741027b645ea5561590de097e735cb3258c2733`, 42444 bytes
- `inventories/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-Q4\_K\_XL/shards/Kimi\-K3\-UD\-Q4\_K\_XL\-00021\-of\-00032\.header\.inventory\.json` — shard\_21\_header\_inventory, `9be98b73c230bc4e5157b95118e1b892f1439c00015f4069feea30d4f092cfd8`, 42449 bytes
- `inventories/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-Q4\_K\_XL/shards/Kimi\-K3\-UD\-Q4\_K\_XL\-00022\-of\-00032\.header\.inventory\.json` — shard\_22\_header\_inventory, `b5f2a2fd1ff52ee8d37e3f64648f1c614ed23ef7e1be8f1545a93324684f54c6`, 46938 bytes
- `inventories/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-Q4\_K\_XL/shards/Kimi\-K3\-UD\-Q4\_K\_XL\-00023\-of\-00032\.header\.inventory\.json` — shard\_23\_header\_inventory, `b214e9bc702446ed075c9f5287a700ccd487e6f87ae45baa9681610f6b46210b`, 40202 bytes
- `inventories/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-Q4\_K\_XL/shards/Kimi\-K3\-UD\-Q4\_K\_XL\-00024\-of\-00032\.header\.inventory\.json` — shard\_24\_header\_inventory, `731d205ba00ac0318b6726fd45c344549dec7e9cfde53cd42728f7efdbacca01`, 42444 bytes
- `inventories/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-Q4\_K\_XL/shards/Kimi\-K3\-UD\-Q4\_K\_XL\-00025\-of\-00032\.header\.inventory\.json` — shard\_25\_header\_inventory, `ba94e765519f2b2d9c676a42af1eaf3ca4b774a2f68be0690e7279aaf9b608f9`, 42449 bytes
- `inventories/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-Q4\_K\_XL/shards/Kimi\-K3\-UD\-Q4\_K\_XL\-00026\-of\-00032\.header\.inventory\.json` — shard\_26\_header\_inventory, `6441cbf4b5ee2b0f37731b090f728392dac2b625c62ac631cbc4d6c3105bc7fc`, 46938 bytes
- `inventories/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-Q4\_K\_XL/shards/Kimi\-K3\-UD\-Q4\_K\_XL\-00027\-of\-00032\.header\.inventory\.json` — shard\_27\_header\_inventory, `ca32fd2da73d0269c67d2a1d76296a51825e411df62d8de4db1ec227ed61cdd9`, 40202 bytes
- `inventories/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-Q4\_K\_XL/shards/Kimi\-K3\-UD\-Q4\_K\_XL\-00028\-of\-00032\.header\.inventory\.json` — shard\_28\_header\_inventory, `79583c5657ed081919c121e7c6b3b645c0252e1315dde47acd074def8fd06918`, 42444 bytes
- `inventories/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-Q4\_K\_XL/shards/Kimi\-K3\-UD\-Q4\_K\_XL\-00029\-of\-00032\.header\.inventory\.json` — shard\_29\_header\_inventory, `c7895c4005403f80153cb2d9580a76a32a0d3caf1bbfa37aef024c391eb620b9`, 42449 bytes
- `inventories/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-Q4\_K\_XL/shards/Kimi\-K3\-UD\-Q4\_K\_XL\-00030\-of\-00032\.header\.inventory\.json` — shard\_30\_header\_inventory, `56fb495e8764de555471a0d9fb7e6475e5488066c16778f0c831091d5bd2156b`, 46938 bytes
- `inventories/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-Q4\_K\_XL/shards/Kimi\-K3\-UD\-Q4\_K\_XL\-00031\-of\-00032\.header\.inventory\.json` — shard\_31\_header\_inventory, `236ef34901e06cb1b4d85bc351bd4c26d7f70899eac1bdd18f27ba9b74737f4f`, 40202 bytes
- `inventories/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-Q4\_K\_XL/shards/Kimi\-K3\-UD\-Q4\_K\_XL\-00032\-of\-00032\.header\.inventory\.json` — shard\_32\_header\_inventory, `e37f7d383147a54f1898a4a99589651f167e28d25e468138fc28ce64f7254622`, 32439 bytes
- `inventories/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-Q4\_K\_XL\.split\.inventory\.json` — split\_inventory, `e30a2b8019258213d893d10caff79860bd07a3262ad6e5cc2352884b7cc4f51c`, 1956449 bytes
- `reports/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-Q4\_K\_XL\.split\.report\.json` — split\_report, `d1ff8dc455fb3111458f9fa485358fcebf44f7aa21de6d6cc34f09b04beb6fae`, 2080227 bytes
- `inventories/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-Q4\_K\_XL\.kimi\-k3\-ontology\.inventory\.json` — target\_ontology\_inventory, `a7dccbc370338778871bee07e2079b225e57e8fe0102f09587837b95e994ac6a`, 324844 bytes
- `reports/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-Q4\_K\_XL\.kimi\-k3\-ontology\.report\.json` — target\_ontology\_report, `d57cf6d6b29cdabf2c2c7537ae15e05b51420d0721de12c07fbee7ec67c8f775`, 361897 bytes
- `inventories/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-Q4\_K\_XL\.semantic\-mapping\.inventory\.json` — semantic\_mapping\_inventory, `6578d6a2d12a3f3950d6c937a1d17f240105e74e783b5e16dcdc13861ed51dda`, 3377549 bytes
- `reports/remote/unsloth\_Kimi\-K3\-GGUF\_UD\-Q4\_K\_XL\.semantic\-mapping\.report\.json` — semantic\_mapping\_report, `0a8c39846e5681147aa1c034a1797c148f080e479c18d5d9135e08b274421755`, 19456 bytes
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
