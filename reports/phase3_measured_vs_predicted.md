# Phase 3 — released Kimi K3 tensor schema and measured-vs-predicted analysis

Date: 2026-07-28 (Asia/Tokyo)  
Repository: `Hudabey/theseus`  
Theseus commit: `f4e7b24883a8f2d62de418965915ee5fe722cbf1`  
Model repository: `moonshotai/Kimi-K3`  
llama.cpp comparison commit: `1a064ab0921238c1daa397d6f4a900ef33884de2` (the commit pinned by the recon documents; `recon/02-mxfp4-preservation.md:9-11`)

## 1. Executive summary

The inventory fetch **PASSed**. Explicit HTTP Range requests read the safetensors
framing headers of all 96 released shards and produced a parseable 115,542,096-byte
JSON inventory containing 497,220 tensor records: 2,122 BF16, 506 F32, and 494,592
U8. No tensor-data payload range and no model shard was downloaded. The fetcher's
scope is visible in `tools/drop_day/fetch_headers.py:1-6,29-40,57-75`; the released
run summary is `raw/kimi_k3_fetch_headers.txt:96-98`.

The released 93-layer text stack is an exact partition:

- KDA, zero-based: **`{0,1,2,4,5,6,8,9,10,12,13,14,16,17,18,20,21,22,24,25,26,28,29,30,32,33,34,36,37,38,40,41,42,44,45,46,48,49,50,52,53,54,56,57,58,60,61,62,64,65,66,68,69,70,72,73,74,76,77,78,80,81,82,84,85,86,88,89,90}`** (69 layers).
- MLA, zero-based: **`{3,7,11,15,19,23,27,31,35,39,43,47,51,55,59,63,67,71,75,79,83,87,91,92}`** (24 layers).
- Neither: **none**; overlap: **none**.

The config contains the corresponding one-based lists, and the configuration class
subtracts one by testing `layer_idx + 1`
(`raw/kimi_k3_source/config.json:66-169`;
`raw/kimi_k3_source/configuration_kimi_k3.py:152-156`). Header detection independently
reproduces the partition (`raw/kimi_k3_schema_analysis.json:111-210`).

“MLA every fourth layer” is exact for one-based layers 4 through 92. It is not a
uniform rule through the end: one-based layer 93 is also MLA, making zero-based
layers 91 and 92 consecutive MLA layers. The first 92 layers have an exact 69:23
(3:1) KDA:MLA ratio; the full model has 69:24, not 3:1. Layer 0 is also structurally
exceptional because it is the only dense-MLP layer; layers 1–92 are MoE
(`raw/kimi_k3_source/config.json:46,176-191`;
`raw/kimi_k3_source/modeling_kimi_linear.py:883-900`).

The strongest released findings are:

1. All 92 MoE layers contain exactly the expert-ID set `0..895`; the sets are
   identical. Layer 0 alone lacks routed experts
   (`raw/kimi_k3_schema_analysis.json:5178-5294`).
2. Exactly 247,296 packed/scale pairs exist:
   `92 layers × 896 experts × 3 projections`. There are no packed-only, scale-only,
   malformed-shape, or non-routed-expert pairs
   (`raw/kimi_k3_schema_analysis.json:5297-5412`).
3. Released SiTU is config-scalar math, not an additional learned tensor family:
   `4*tanh(gate/4)*sigmoid(gate) * (25*tanh(up/25))`
   (`raw/kimi_k3_source/config.json:20-21,49`;
   `raw/kimi_k3_source/modeling_kimi_linear.py:64-91,242-270`).
4. Stable LatentMoE is structurally real: routing is performed in 7,168 dimensions,
   routed inputs are projected to 3,584, expert `w1/w2/w3` operate there, the routed
   result is RMS-normalized, then projected back to 7,168; a separate two-shared-expert
   MLP is added. This is not merely a name for an otherwise standard full-width MoE
   (`raw/kimi_k3_source/config.json:64,176,185-191,246`;
   `raw/kimi_k3_source/modeling_kimi_linear.py:762-838`).
5. MLA output-gate wiring is direct: `sigmoid(g_proj(hidden_states))` multiplies the
   attention output before `o_proj`
   (`raw/kimi_k3_source/modeling_kimi_linear.py:398-402,468-474`).
6. AttnRes uses the same depth-softmax-over-RMS-normalized-sources formula as the
   pinned FLA reference, with ordinary prenorm applied immediately afterward, but its
   block-size arithmetic differs: released K3 snapshots at
   `layer_idx % attn_res_block_size == 0`, so config value 12 means twelve transformer
   layers per block, not FLA's six-layer interpretation for an even sublayer block size
   12 (`raw/kimi_k3_source/config.json:26`;
   `raw/kimi_k3_source/modeling_kimi_linear.py:973-1046,1075-1088`;
   `recon/04-attnres-analysis.md:169-190`).

Header/config/source evidence does **not** prove numerical equivalence to llama.cpp,
payload-byte correctness, MXFP4 nibble order, trained AttnRes query values, tokenizer
semantics, or successful K3 execution.

## 2. Evidence and exact commands

Evidence classes used below:

- **Config fact** — read from released `config.json`.
- **Header fact** — name, dtype, shape, shard, or offset from safetensors headers.
- **Name/shape observation** — grouping based on exact names/shapes, without a semantic
  claim by itself.
- **Source-code fact** — behavior directly implemented by the released small Python
  source files.
- **Calculation** — arithmetic over the preceding evidence.
- **Unresolved semantic** — requires payload inspection, execution, tokenizer work, or
  a llama.cpp implementation.

Commands:

```bash
set -o pipefail
.venv/bin/python tools/drop_day/fetch_headers.py \
  moonshotai/Kimi-K3 \
  -o <PROJECT_ROOT>/reports/raw/kimi_k3_tensors.json \
  2>&1 | tee <PROJECT_ROOT>/reports/raw/kimi_k3_fetch_headers.txt
# PIPESTATUS[0] = 0

.venv/bin/python /tmp/analyze_k3_inventory.py
# exit 0; offline; output copied to raw/kimi_k3_schema_analysis.json

.venv/bin/python tools/drop_day/classify_tensors.py \
  /tmp/kimi_k3_tensors.json --show 200
# exit 0; /tmp/kimi_k3_tensors.json was a symlink to the released inventory

git status --short
# no output
```

The small released configuration/modeling files were fetched separately by metadata
API, with an explicit per-file 1 MiB cap, into `raw/kimi_k3_source/`. The exact file
sizes and SHA-256 hashes are preserved in
`raw/kimi_k3_source/manifest.json:1-52`. These are source/config evidence, not model
payload. The manifest does not record a Hugging Face revision SHA, so this report does
not pretend the source snapshot has a commit identity.

## 3. Inventory result

| Fact | Result | Evidence class |
|---|---:|---|
| Fetch exit | 0 | command result |
| Inventory parse | valid JSON array | offline validation |
| File size | 115,542,096 bytes | filesystem |
| Tensor records | 497,220 | header fact |
| Shards | 96 | header/index fact |
| BF16 | 2,122 | header fact |
| F32 | 506 | header fact |
| U8 | 494,592 | header fact |
| Worktree | clean | `git status --short` |

The final fetch totals are `raw/kimi_k3_fetch_headers.txt:96-98`; the machine-readable
summary is `raw/kimi_k3_schema_analysis.json:2-9`. Phase 2's independent Theseus run
reported the same tensor/dtype counts (`raw/kimi_k3_inspect.txt:8-14`).

## 4. Exact layer placement

The exact zero-based KDA and MLA sets are printed in full in §1 and serialized at
`raw/kimi_k3_schema_analysis.json:111-210`. The released config is one-based
(`raw/kimi_k3_source/config.json:67-169`), while the model's selection function is
explicitly `(layer_idx + 1) in kda_layers`
(`raw/kimi_k3_source/configuration_kimi_k3.py:152-156`).

Placement conclusions:

| Conclusion | Classification |
|---|---|
| All layers 0..92 are exactly one of KDA or MLA | CONFIRMED by config and headers |
| One-based layers 4,8,…,92 are MLA | CONFIRMED |
| One-based layer 93 is additionally MLA | CONFIRMED |
| “Every fourth layer” describes the entire model without exception | CONTRADICTED by final layer 93 |
| Global KDA:MLA ratio is exactly 3:1 | CONTRADICTED: 69:24 |
| Ratio across layers 0..91 is exactly 3:1 | CONFIRMED: 69:23 |
| First layer is exceptional | CONFIRMED: KDA plus the sole ordinary dense MLP |
| Final layer is exceptional | CONFIRMED in placement: MLA immediately after another MLA; no unique tensor suffix or shape was found |

The source instantiates KDA only when the explicit list says so and otherwise MLA
(`raw/kimi_k3_source/modeling_kimi_linear.py:880-892`). Thus “architecturally
exceptional” for the final layer is limited here to placement; no unsupported special
semantics are inferred.

## 5. Exact major tensor families

Counts in this section are semantic groups constructed from exact prefixes/suffixes and
may overlap normalization subfamilies. They must not be confused with Theseus's
first-match regex buckets.

### 5.1 Text-stack overview

| Family | Exact pattern | Count | dtype / representative shapes | Layer coverage | Packed + scale? |
|---|---|---:|---|---|---|
| KDA attention | `language_model.model.layers.{L}.self_attn.{suffix}`, for KDA L | 966 (14 × 69) | BF16/F32; see §8 | KDA set | no |
| MLA attention | same prefix, MLA-specific eight suffixes | 192 (8 × 24) | BF16; see §9 | MLA set | no |
| AttnRes | per-layer `self_attention_res_{norm,proj}` and `mlp_res_{norm,proj}`; model `output_attn_res_{norm,proj}` | 374 | BF16 `[7168]` or `[1,7168]` | all 93 + two model-level | no |
| Routed expert weights | `...block_sparse_moe.experts.{E}.w{1,2,3}.weight_{packed,scale}` | 494,592 records / 247,296 pairs | U8; see §7 | 1..92 | yes |
| Shared experts | `...block_sparse_moe.shared_experts.{gate,up,down}_proj.weight` | 276 | BF16 `[6144,7168]` ×2 and `[7168,6144]` | 1..92 | no |
| Latent-MoE bridge | `...routed_expert_{down_proj,norm,up_proj}.weight` | 276 | BF16 `[3584,7168]`, `[3584]`, `[7168,3584]` | 1..92 | no |
| Router | `...gate.weight`, `...gate.e_score_correction_bias` | 184 | BF16 `[896,7168]`; F32 `[896]` | 1..92 | no |
| Ordinary dense MLP | `layers.0.mlp.{gate,up,down}_proj.weight` | 3 | BF16 `[33792,7168]` ×2, `[7168,33792]` | 0 only | no |

Header-derived family totals and shapes are preserved at
`raw/kimi_k3_schema_analysis.json:212-653,827-3329`. Source construction explains the
dense-to-MoE boundary (`raw/kimi_k3_source/modeling_kimi_linear.py:893-900`) and the
latent/shared structures (`raw/kimi_k3_source/modeling_kimi_linear.py:762-838`).

### 5.2 Attention Residual, embedding, output, and norm inventory

- Per decoder layer: exactly four AttnRes tensors—two query projections
  `[1,7168]` and two key RMSNorm weights `[7168]`, all BF16. The two model-level output
  tensors have the same shapes. Exact suffixes/counts:
  `raw/kimi_k3_schema_analysis.json:2230-2667`.
- Language embedding:
  `language_model.model.embed_tokens.weight`, BF16 `[163840,7168]`.
- Output head:
  `language_model.lm_head.weight`, BF16 `[163840,7168]`.
- Exact names/shapes are at `raw/kimi_k3_schema_analysis.json:698-725`.
- There are 639 tensors whose exact path contains `norm`: 570 BF16 and 69 F32.
  This inclusive count comprises standard text prenorms/final norm, AttnRes key norms,
  KDA `o_norm`, MLA LoRA norms, latent-MoE norms, vision norms, and projector post-norm
  (`raw/kimi_k3_schema_analysis.json:726-824`). It is an inventory count, not a claim
  that all norms have identical semantics.

### 5.3 Vision and multimodal projector

The vision tower contains **165 BF16 tensors**:

- 27 encoder blocks, each with:
  `mlp.fc0.weight [4096,1024]`,
  `mlp.fc1.weight [1024,4096]`,
  `norm0.weight [1024]`,
  `norm1.weight [1024]`,
  `wo.weight [1024,1536]`,
  `wqkv.weight [4608,1024]` (162 tensors);
- `vision_tower.encoder.final_layernorm.weight [1024]`;
- `vision_tower.patch_embed.pos_emb.weight [64,64,1024]`;
- `vision_tower.patch_embed.proj.weight [1024,3,14,14]`.

The 27-layer/1,024-wide config is direct evidence
(`raw/kimi_k3_source/config.json:270-298`); the header family total and shape
distribution are `raw/kimi_k3_schema_analysis.json:654-670`.

The projector is a distinct three-tensor multimodal bridge:

- `mm_projector.proj.0.weight`, BF16 `[4096,4096]`;
- `mm_projector.proj.2.weight`, BF16 `[7168,4096]`;
- `mm_projector.post_norm.weight`, BF16 `[7168]`.

These are exact header facts (`raw/kimi_k3_schema_analysis.json:5146-5176`). The
released `patchmergerv2` class computes a 4 × 1,024 = 4,096 input width, applies those
two bias-free linears, then RMSNorm at text width 7,168
(`raw/kimi_k3_source/modeling_kimi_k3.py:783-815`);
`KimiK3ForConditionalGeneration` selects this class from config
(`raw/kimi_k3_source/modeling_kimi_k3.py:899-919`;
`raw/kimi_k3_source/config.json:278-295`).

Therefore the two tensors Theseus leaves unclassified are explained and should be
classified under a new **multimodal projector** family, not absorbed into the vision
tower. The projector consumes vision features and emits language-width features; that
bridge role is directly supported by code and shapes.

## 6. Exact MoE structure

### 6.1 Expert IDs and layer coverage

For every layer 1 through 92:

- detected expert-ID set = exactly `{0,1,…,895}`;
- set size = 896;
- all layer sets are identical;
- missing IDs = none;
- extra IDs = none.

Layer 0 is the only layer without routed experts. The exhaustive result is
`raw/kimi_k3_schema_analysis.json:5178-5294`. This improves on `theseus verify`,
which only checks expert counts; verify's reported result is
`raw/kimi_k3_verify.txt:8-9`, while the count-only implementation limitation was
documented in Phase 2B.

Each expert has exactly:

```text
...experts.{E}.w1.weight_packed
...experts.{E}.w1.weight_scale
...experts.{E}.w2.weight_packed
...experts.{E}.w2.weight_scale
...experts.{E}.w3.weight_packed
...experts.{E}.w3.weight_scale
```

The released model defines `w1` as gate, `w2` as down, and `w3` as up
(`raw/kimi_k3_source/modeling_kimi_linear.py:242-270`).

### 6.2 Router, shared experts, and Stable LatentMoE

Each MoE layer has:

- router `gate.weight` BF16 `[896,7168]`;
- router `gate.e_score_correction_bias` F32 `[896]`;
- shared expert gate/up BF16 `[6144,7168]` and down BF16 `[7168,6144]`;
- `routed_expert_down_proj.weight` BF16 `[3584,7168]`;
- `routed_expert_norm.weight` BF16 `[3584]`;
- `routed_expert_up_proj.weight` BF16 `[7168,3584]`.

The header suffix table is `raw/kimi_k3_schema_analysis.json:2668-3329`. Config fixes
896 experts, top-16, two shared experts, expert intermediate 3,072, latent width 3,584,
and latent norm enabled (`raw/kimi_k3_source/config.json:64,176-191,246`).

Released source establishes the formula/order:

1. router scores are sigmoid of a float32 linear, corrected for selection, top-k 16,
   then selected uncorrected scores are renormalized
   (`raw/kimi_k3_source/modeling_kimi_linear.py:666-759`);
2. routed input `x` is projected `7168 → 3584`;
3. selected `w1/w2/w3` experts run at latent width;
4. routed result is RMS-normalized and projected `3584 → 7168`;
5. a full-width shared-expert MLP with intermediate width `2 × 3072 = 6144` is added
   (`raw/kimi_k3_source/modeling_kimi_linear.py:762-838`).

This directly resolves “Stable LatentMoE”: it is a factored latent routed path plus a
separate shared path, not merely branding. Numerical stability/performance claims
beyond this code are unresolved.

## 7. MXFP4 packed/scale analysis

Exact arithmetic:

```text
92 MoE layers × 896 experts × 3 projections = 247,296 pairs
247,296 pairs × 2 tensors = 494,592 U8 tensor records
per layer: 896 × 3 = 2,688 pairs
per projection: 92 × 896 = 82,432 pairs
per expert across all layers: 92 × 3 = 276 pairs
```

All arithmetic matches the released header inventory
(`raw/kimi_k3_schema_analysis.json:5297-5412`).

| Projection | packed shape | scale shape | pairs | Exact dimensional relation |
|---|---|---|---:|---|
| `w1` | `[3072,1792]` | `[3072,112]` | 82,432 | 1792 = 112 × 16 |
| `w2` | `[3584,1536]` | `[3584,96]` | 82,432 | 1536 = 96 × 16 |
| `w3` | `[3072,1792]` | `[3072,112]` | 82,432 | 1792 = 112 × 16 |

Both members are U8 in every pair. Exact orphan scan in both directions found:

- packed-only: 0;
- scale-only: 0;
- pairs outside routed experts: 0;
- dtype mismatches: 0;
- leading-dimension or 16:1 last-dimension failures: 0.

The config directly says group size 32, four bits, U8 scales, compressed-tensors
`mxfp4-pack-quantized`, and excludes attention, shared experts, dense MLP, head, vision,
and projector (`raw/kimi_k3_source/config.json:202-239`). Header dimensions agree with
two packed nibbles per byte and one scale per 32 logical values.

However, because payload bytes were deliberately not fetched, Phase 3 does **not**
validate adjacent-pair nibble order, E8M0 scale interpretation, scale byte identity,
or byte-exact compatibility with ggml `block_mxfp4`. Therefore recon 02's proposed
repacker remains structurally supported but still needs the separately scoped
small-payload oracle before “lossless passthrough” can be claimed
(`recon/02-mxfp4-preservation.md:21-40,221-230`).

## 8. KDA

Every KDA layer has the following 14 tensors:

| Suffix | dtype | shape | Direct source role |
|---|---|---|---|
| `A_log` | F32 | `[128]` | per-head decay parameter |
| `dt_bias` | F32 | `[12288]` | per-channel gate bias |
| `f_a_proj.weight` | BF16 | `[128,7168]` | low-rank gate first projection |
| `f_b_proj.weight` | BF16 | `[12288,128]` | low-rank gate second projection |
| `b_proj.weight` | BF16 | `[96,7168]` | beta projection |
| `q_proj.weight` | BF16 | `[12288,7168]` | q projection |
| `k_proj.weight` | BF16 | `[12288,7168]` | k projection |
| `v_proj.weight` | BF16 | `[12288,7168]` | v projection |
| `q_conv1d.weight` | F32 | `[12288,1,4]` | q short convolution |
| `k_conv1d.weight` | F32 | `[12288,1,4]` | k short convolution |
| `v_conv1d.weight` | F32 | `[12288,1,4]` | v short convolution |
| `g_proj.weight` | BF16 | `[12288,7168]` | full-rank output gate |
| `o_norm.weight` | F32 | `[128]` | gated output RMSNorm |
| `o_proj.weight` | BF16 | `[7168,12288]` | output projection |

Header suffix/count evidence begins at
`raw/kimi_k3_schema_analysis.json:827-1947`; all occur exactly 69 times on the KDA
set. Config confirms 96 heads, head dimension 128, short-convolution kernel 4,
full-rank output gate, and gate lower bound -5
(`raw/kimi_k3_source/config.json:93-94,166-168`).

Released source confirms q/k/v short convolutions and recurrent cache state
(`raw/kimi_k3_source/modeling_kimi_linear.py:477-518,572-600`), calls FLA KDA with
q/k L2 normalization, gate handling, sigmoid beta, and safe lower bound
(`raw/kimi_k3_source/modeling_kimi_linear.py:609-645`), then applies the full-rank
gate through sigmoid-gated RMSNorm and `o_proj`
(`raw/kimi_k3_source/modeling_kimi_linear.py:651-659`).

This is strong structural and source-level alignment with recon 01's existing
KIMI_LINEAR reuse target (`recon/01-kda-gap-analysis.md:171-181`). It is not a
numerical equivalence result: no released tensor values or reference outputs were read,
and llama.cpp's pinned implementation has not executed K3.

One concrete converter/classifier difference from the older assumptions is the
released **full-rank** `g_proj`, rather than low-rank `g_a_proj/g_b_proj`; code selects
that path explicitly (`raw/kimi_k3_source/modeling_kimi_linear.py:531-537`).

## 9. MLA

Every MLA layer has exactly:

| Suffix | dtype | shape |
|---|---|---|
| `q_a_proj.weight` | BF16 | `[1536,7168]` |
| `q_a_layernorm.weight` | BF16 | `[1536]` |
| `q_b_proj.weight` | BF16 | `[18432,1536]` |
| `kv_a_proj_with_mqa.weight` | BF16 | `[576,7168]` |
| `kv_a_layernorm.weight` | BF16 | `[512]` |
| `kv_b_proj.weight` | BF16 | `[24576,512]` |
| `g_proj.weight` | BF16 | `[12288,7168]` |
| `o_proj.weight` | BF16 | `[7168,12288]` |

Each occurs on exactly the 24-layer MLA set
(`raw/kimi_k3_schema_analysis.json:1948-2229`). Config gives q rank 1,536, kv rank
512, NoPE dimension 128, nominal rope component 64, value dimension 128, and enables
NoPE plus output gating (`raw/kimi_k3_source/config.json:59,173-174,199-201,266`).

The source projects q through q-a/norm/q-b and kv through the 576-wide
`512 + 64` projection (`raw/kimi_k3_source/modeling_kimi_linear.py:364-389`).
Although local variables are named `q_rot`/`k_rot`, no rotary transform is applied:
the source splits and directly concatenates them, and initializes `rotary_emb = None`
(`raw/kimi_k3_source/modeling_kimi_linear.py:396-403,418-440`). No rope parameter
tensor exists in headers. This supports the released NoPE execution path, not an
unsupported claim about all possible MLA implementations.

The predicted gate wiring is **CONFIRMED**: `g_proj` maps `7168 → 96×128=12288`;
`sigmoid(g_proj(hidden_states))` multiplies flattened attention output, followed by
`o_proj` (`raw/kimi_k3_source/modeling_kimi_linear.py:398-402,468-474`).

## 10. Attention Residuals

### 10.1 Exact released inventory

Every decoder layer, KDA and MLA alike, has exactly:

```text
self_attention_res_proj.weight  BF16 [1,7168]
self_attention_res_norm.weight  BF16 [7168]
mlp_res_proj.weight             BF16 [1,7168]
mlp_res_norm.weight             BF16 [7168]
```

The model also has:

```text
language_model.model.output_attn_res_proj.weight  BF16 [1,7168]
language_model.model.output_attn_res_norm.weight  BF16 [7168]
```

Total: 374 tensors. Header evidence is
`raw/kimi_k3_schema_analysis.json:2230-2667`; source declarations are
`raw/kimi_k3_source/modeling_kimi_linear.py:906-917,1103-1108`.

### 10.2 Formula and block placement

Released `_apply_attn_res` concatenates completed block sources plus the current
prefix, computes sourcewise RMS normalization, scores each source with the elementwise
product of norm weight and learned `[1,D]` projection, applies softmax over sources,
and mixes raw source values (`raw/kimi_k3_source/modeling_kimi_linear.py:1075-1088`).
There is no explicit logit scale, hence scale 1.

The resulting mixture is then passed through the ordinary `input_layernorm` or
`post_attention_layernorm`; this is operationally the same location as FLA's folded
output prenorm, but implemented as a separate call
(`raw/kimi_k3_source/modeling_kimi_linear.py:987-1001,1028-1039`). A final model-level
mixture is followed by the normal final RMSNorm
(`raw/kimi_k3_source/modeling_kimi_linear.py:1215-1233`).

Released block boundaries occur before attention when
`layer_idx % attn_res_block_size == 0`; the config value is 12
(`raw/kimi_k3_source/modeling_kimi_linear.py:995-998`;
`raw/kimi_k3_source/config.json:26`). Thus boundaries are zero-based layers
`{0,12,24,36,48,60,72,84}`, yielding eight stored layer-block sources plus the
current prefix at the output.

### 10.3 Comparison to pinned FLA analysis

**PARTIALLY_CONFIRMED, with a material contradiction in config semantics.**

Confirmed:

- depth-axis softmax of query against RMS-normalized sources;
- raw-value convex mixture;
- per-attention and per-MLP query/norm tensors;
- embedding/partial-sum source discipline;
- plain-add write path;
- final top-level aggregation;
- all attention types participate;
- common config epsilon (`1e-5`) and scale 1.

Contradicted:

- recon 04's pinned FLA configuration defines even `N` as N sublayers = N/2
  transformer layers per block (`recon/04-attnres-analysis.md:169-190`). Released K3
  directly uses N transformer layers. For N=12, that is 12 layers rather than six.
- checkpoint names are close but not identical:
  `self_attention_res_*` and `output_attn_res_*`, not FLA's `attn_res_*` and
  `res_*` (`recon/04-attnres-analysis.md:195-220`).

Still unresolved because payload reads are prohibited:

- whether trained pseudo-query tensors are non-zero;
- numerical equality of the standalone-norm and folded-norm implementations under
  actual dtype/backend execution;
- reference-output parity.

It would therefore be incorrect to claim mathematical/e2e equivalence merely from
headers. The source formulas support a close graph-level port, with K3's own boundary
arithmetic treated as authoritative.

## 11. SiTU

Direct config evidence:

```text
hidden_act = "situ"
activation_situ_beta = 4.0
activation_situ_linear_beta = 25.0
```

(`raw/kimi_k3_source/config.json:20-21,49`).

Direct released source formula:

```text
gate' = 4 * tanh(gate / 4) * sigmoid(gate)
up'   = 25 * tanh(up / 25)
output = gate' * up'
```

(`raw/kimi_k3_source/modeling_kimi_linear.py:64-91`). Both routed experts and dense
MLPs concatenate the gate/up projections before applying the same function
(`raw/kimi_k3_source/modeling_kimi_linear.py:242-301`).

The betas are config scalars. There are no additional SiTU-named learned tensors in the
inventory. This resolves recon 05's formula/granularity unknown; it does not establish
performance or backend fusion behavior.

## 12. Classifier comparison

Actual `tools/drop_day/classify_tensors.py` output:

```text
attnres 374; kda 552; mla 444; moe 495052; mlp 187;
norms 404; embed 4; vision 108; UNMATCH 95
```

(`raw/kimi_k3_drop_day_classify.txt:1-9`).

Package classifier output:

```text
attnres 374; kda 552; mla 537; moe 495052; mlp 187;
norms 404; embed 4; vision 108; unmatched 2
```

(`raw/kimi_k3_inspect.txt:9-14`;
`raw/kimi_k3_schema_analysis.json:5414-5437`).

There are exactly 93 disagreements, all
`language_model.model.layers.{0..92}.self_attn.g_proj.weight`: the drop-day script
leaves every one unmatched, while the package assigns all to MLA. The pattern
difference is explicit:

- package adds `self_attn\.g_proj` to MLA
  (`theseus/census.py:10-18`);
- drop-day does not
  (`tools/drop_day/classify_tensors.py:15-23`).

Released layer selection and source code prove that 69 are KDA full-rank output gates
and 24 are MLA output gates
(`raw/kimi_k3_source/modeling_kimi_linear.py:398-402,531-537`;
`raw/kimi_k3_schema_analysis.json:1227-1306,1949-2018`). Therefore:

- the drop-day output is incomplete but semantically cautious;
- the package removes the warning but semantically overcounts MLA by 69;
- a correct classifier must use layer context or distinguishing companion tensors,
  not the shared suffix alone.

The two package-unmatched tensors are the projector linears. The package also reports
only 108 “vision” tensors because first-match ordering diverts 55 vision norms to
`norms` and two patch-embedding tensors to `embed`; exact prefix-based vision count is
165. These are classification disagreements in meaning, not missing header records.

## 13. Measured versus predicted

Status applies to K3-dependent claims; static source facts about the pinned llama.cpp
commit remain source-code facts rather than checkpoint measurements.

| Recon claim | Status | Released evidence |
|---|---|---|
| 01: mainline KIMI_LINEAR KDA is the reuse target | **PARTIALLY_CONFIRMED** | K3 source uses the same named recurrence pieces and FLA KDA call; config/head/conv/gate shapes match the predicted family (`modeling_kimi_linear.py:477-659`). Numerical parity remains unrun. |
| 01-OQ1: K3 uses head dim 128, sigmoid beta/output gate, per-channel decay, short conv | **CONFIRMED at config/source level** | `config.json:93-94,166-168`; released call flags at `modeling_kimi_linear.py:609-659`. Chunk size is internal to FLA and not exposed here. |
| 01: full-attention layers are MLA every four layers | **PARTIALLY_CONFIRMED** | Exact through one-based layer 92; extra MLA at 93. Exact zero-based set in §1. |
| 01: new K3 MLA gate needs wiring | **CONFIRMED** | `[12288,7168]` gate and `sigmoid × attention output` before `o_proj` (`modeling_kimi_linear.py:398-402,468-474`). |
| 01: AttnRes is net-new and FLA is closest reference | **PARTIALLY_CONFIRMED** | Formula/source discipline close; names and block-size semantics differ (§10). |
| 01/02: routed expert MXFP4 only | **CONFIRMED structurally** | All 247,296 pairs are routed-expert-only; config ignores other families (§7). |
| 01/02: HF bytes can be losslessly repacked to ggml without requantization | **STILL_UNRESOLVED** | Header shapes/group size are compatible, but nibble/scale payload bytes were not read. |
| 02: pair by expert/layer/projection rather than input order | **CONFIRMED as applicable design** | Exact one-to-one names and no orphans; 247,296 pairs (§7). |
| 04: per-sublayer query/norm layout plus top-level aggregation | **CONFIRMED** | Four tensors per transformer layer plus two output tensors (§10). |
| 04: FLA AttnRes formula transfers | **PARTIALLY_CONFIRMED** | Same mix formula/source discipline; output norm is separate and boundary arithmetic differs. |
| 04: even block size 12 means six transformer layers | **CONTRADICTED** | Released code uses `layer_idx % 12`, i.e. 12 transformer layers. |
| 04: all MLA layers carry AttnRes | **CONFIRMED** | all four AttnRes tensors cover layers 0..92. |
| 04: trained pseudo-queries are nonzero/live | **STILL_UNRESOLVED** | requires prohibited payload values. |
| 05 A1: about 2.8T logical parameters | **CONFIRMED as a calculation** | Theseus calculates 2,779,931,837,184 (`raw/kimi_k3_inspect.txt:9-11`). |
| 05 A2: 1M context | **CONFIRMED in config** | 1,048,576 (`config.json:171`). |
| 05 A3: native vision tower | **CONFIRMED structurally** | 27-layer tower + projector (§5.3). “Image-only” preprocessing semantics were not investigated here. |
| 05 A7: 93 decoder layers | **CONFIRMED** | config 93 plus header indices 0..92 (`config.json:187`). |
| 05 A9: 896 routed, 16 active, shared experts | **CONFIRMED** | config plus exact ID sets; shared count is two (§6). |
| 05 A10: Stable LatentMoE exists, semantics unknown | **CONFIRMED and resolved structurally** | 7168→3584→experts→norm→7168 path plus shared add (§6.2). |
| 05 A11: MXFP4 release format | **CONFIRMED in config/header structure** | compressed MXFP4 config and paired U8 inventory (§7). |
| 05 A12/A13: approximately 23/70 and 3:1 globally | **CONTRADICTED in exact released placement** | exact 24 MLA / 69 KDA; 3:1 only across first 92 layers. |
| 05 SiTU formula/parameters unknown | **CONFIRMED term, now resolved by release** | formula and scalar betas in §11. |
| 06: completeness/header/classification workflow | **CONFIRMED operationally** | 96 headers, valid inventory; classifier discovery worked but exposed g_proj ambiguity (`raw/kimi_k3_fetch_headers.txt:96-98`; §12). |
| 06: expect two AttnRes projections per layer and top aggregation | **CONFIRMED** | exact inventory §10. |
| 06: packed bytes/scales appear GPT-OSS-compatible | **PARTIALLY_CONFIRMED** | shape/group/dtype compatible; byte convention untested. |

This table deliberately leaves runtime semantics unresolved where only regex, config,
or header evidence exists.

## 14. llama.cpp gap-oriented assessment

### Likely reusable from existing KIMI_LINEAR support

- KDA recurrence primitive and graph concepts: q/k L2 normalization, per-channel decay,
  sigmoid beta, recurrent state, q/k/v short convolution, and output gating. This is
  a **reuse candidate**, conditional on reference-output parity; recon's pinned
  llama.cpp evidence is `recon/01-kda-gap-analysis.md:171-181`.
- MLA q/kv low-rank projection and NoPE attention structure, but not the new output
  gate or K3's explicit layout.
- Existing `GGML_TYPE_MXFP4` representation and the recon's repacking oracle, once a
  small-payload layout test is separately authorized.

### Clearly new architecture wiring

- `LLM_ARCH_KIMI_K3`, config metadata, explicit 69/24 hybrid layer list, and the final
  consecutive MLA layer.
- K3 AttnRes graph with **12-transformer-layer** block boundaries, per-attn/per-MLP
  mixtures, and final aggregation.
- Stable LatentMoE's 7,168→3,584 bridge, latent RMSNorm, 3,584→7,168 bridge, and shared
  expert addition.
- SiTU composition with config scalars beta=4 and linear-beta=25.
- MLA `sigmoid(g_proj(x))` output gate.
- Vision tower plus a separately named PatchMergerMLPV2 projector if multimodal K3 is
  in the initial scope.

### Converter/tensor-mapping changes

- Register exact K3 tensor mappings, including the shared `self_attn.g_proj` name whose
  semantic family depends on layer type.
- Map all six AttnRes suffix families and K3's block-size metadata.
- Pair and stack 247,296 per-expert `weight_packed`/`weight_scale` tensors without
  depending on iteration order; retain all non-routed families at source precision.
- Emit Stable LatentMoE bridge/norm tensors and projector tensors.
- Preserve the final MLA exception via explicit layer metadata rather than only an
  interval.

### GGML graph changes

- AttnRes depth mixture and prefix/block-source lifetime.
- Latent-MoE pre/post projections and normalization.
- SiTU activation composition.
- MLA output gate.
- Architecture-specific hybrid attention dispatch.

The released evidence supports a correctness-first AttnRes composition from existing
RMSNorm, matmul, softmax, multiply, and add primitives. It does not yet establish
whether performance requires a fused op.

### Still blocked on semantics/reference execution

- K3-vs-llama.cpp numerical parity for KDA, MLA, AttnRes, SiTU, and LatentMoE.
- MXFP4 nibble order/scale-byte equivalence and byte-exact repack.
- trained AttnRes pseudo-query values.
- tokenizer/chat/tool/reasoning semantics.
- any claim that K3 currently converts, loads, or runs in llama.cpp.

## 15. Recommended first contribution

The recommended first scoped llama.cpp contribution is **architecture metadata and
tensor mapping for the released K3 schema, with no execution claim**:

1. register `LLM_ARCH_KIMI_K3` and exact config keys/layer list;
2. add tensor mappings for KDA/MLA, AttnRes, latent-MoE, and projector names;
3. add converter-side schema validation tests using synthetic header/name fixtures.

This is reviewable independently, makes the ambiguous `g_proj` handling explicit, and
unblocks later graph work without prematurely claiming numerical support. The next
independent candidates are (a) AttnRes graph composition using K3's 12-layer boundary
semantics and (b) MXFP4 pair/repack support gated by a small-payload oracle.

## 16. Safety and final state

- Full shards downloaded: **none**.
- Tensor payload ranges fetched: **none**.
- `hf download`: **not run**.
- git-lfs: **not run**.
- Theseus production/source/test files modified: **none**.
- Final `git status --short`: **empty**.

Artifacts:

- `raw/kimi_k3_tensors.json`
- `raw/kimi_k3_fetch_headers.txt`
- `raw/kimi_k3_schema_analysis.json`
- `raw/kimi_k3_drop_day_classify.txt`
- `raw/kimi_k3_drop_day_unmatched.json`
- `raw/kimi_k3_source/manifest.json` and its listed small config/source files

## 17. Final result

- **Inventory fetch:** PASS (exit 0)
- **Exact KDA layer set:** `{0,1,2,4,5,6,8,9,10,12,13,14,16,17,18,20,21,22,24,25,26,28,29,30,32,33,34,36,37,38,40,41,42,44,45,46,48,49,50,52,53,54,56,57,58,60,61,62,64,65,66,68,69,70,72,73,74,76,77,78,80,81,82,84,85,86,88,89,90}`
- **Exact MLA layer set:** `{3,7,11,15,19,23,27,31,35,39,43,47,51,55,59,63,67,71,75,79,83,87,91,92}`
- **MoE layers:** 1..92; layer 0 is dense
- **Expert-ID validation:** every MoE layer exactly equals `0..895`; all sets identical
- **AttnRes:** four BF16 tensors on every decoder layer plus two output tensors; depth-softmax formula confirmed; block boundary every 12 transformer layers; payload liveness unresolved
- **Quantized pairs:** 247,296 = 92×896×3; all U8 packed/U8 scale; zero orphans, zero outside routed experts, zero shape failures
- **Unresolved:** runtime numerical parity, MXFP4 payload layout/byte-exact repack, trained AttnRes query values, tokenizer/serving semantics, and end-to-end llama.cpp execution
- **Recommended first llama.cpp contribution:** K3 architecture metadata plus exact tensor mappings and synthetic schema validation
