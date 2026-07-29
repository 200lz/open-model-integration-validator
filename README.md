# Open Model Integration Validator

Open Model Integration Validator (OMIV) turns local checkpoint-header evidence into
a compact, deterministic inventory and checks evidence-backed structural assumptions.
Phase 2 remains intentionally narrow: it supports only the released Kimi K3 JSON
header inventory and static checkpoint structure. In addition to layer layout,
attention signatures, and routed experts, it validates shared projections, contextual
attention gates, Attention Residual coverage, and semantic dtype/shape consistency.

## Install

Python 3.11 or newer is required.

```bash
python -m pip install -e '.[dev]'
```

The runtime has no Hugging Face client and performs no network access.

## Normalize

The raw input must be a top-level JSON array of tensor header records. Normalization
validates every record but retains only counts, classifications, component coverage,
expert-ID sets, grouped descriptors, bounded examples, and diagnostics—not a second
copy of all tensor descriptors. Duplicate exact tensor names are rejected as malformed
input with exit code 2.

```bash
omiv normalize \
  --input reports/raw/kimi_k3_tensors.json \
  --output fixtures/kimi_k3_inventory.json
```

The canonical JSON is sorted and stable. It contains no timestamp, absolute path, or
machine-specific metadata. Its SHA-256 identifies the exact local source inventory.

## Validate

```bash
omiv validate \
  --inventory fixtures/kimi_k3_inventory.json \
  --schema schemas/kimi_k3.yaml
```

A valid measured inventory produces:

```text
PASS K3-LAYER-001 Layer 0 is dense
PASS K3-LAYER-002 Layers 1-92 are MoE
PASS K3-ATTN-001 MLA tail contains consecutive layers 91 and 92
PASS K3-MOE-001 Routed expert sets and components are complete
PASS K3-MOE-002 Shared expert projection coverage is complete
PASS K3-ATTN-002 Contextual g_proj coverage and descriptors are complete
PASS K3-ATTNRES-001 Per-layer Attention Residual coverage and descriptors are complete
PASS K3-ATTNRES-002 Model-level Attention Residual coverage is complete
PASS K3-TENSOR-001 Supported semantic descriptor groups are unanimous
WARN K3-TENSOR-002 Unclassified tensors are present; review the compact summary
```

Exit code 0 means all required rules passed, 1 means at least one rule failed, and 2
means the input inventory or schema was invalid. Failed rules include structured,
concise evidence. WARN means the checkpoint contains names outside Phase 2's supported
semantic groups; it is visible for review but does not by itself invalidate the
checkpoint or change exit code 0.

## Evidence provenance

The implementation is bounded by the observed local evidence in
`reports/raw/kimi_k3_tensors.json` and
`reports/phase3_measured_vs_predicted.md`. The 111 MB raw inventory is intentionally
gitignored. Unit tests use small synthetic records; the marked integration test skips
cleanly when the local evidence file is unavailable.

KDA and MLA are derived from their complete observed companion-marker families.
`g_proj.weight` is recorded but never used alone to distinguish attention type. The
routed expert set is derived from unanimous per-layer evidence and checked for
contiguity; 896 is not treated as a universal architecture constant. Because the
compact inventory stores missing-component coverage rather than every observed
per-expert component list, Phase 1 schemas must require exactly the supported six
packed/scale components. Misspelled, duplicate, added, or omitted component names are
configuration errors.

Phase 2 compares descriptors only within supported semantic groups. It records every
observed `(dtype, shape)` group rather than choosing the first or a majority. Layer
coverage is retained directly. Routed expert descriptors use observation counts,
affected layers, and at most 12 deterministic layer/expert examples per descriptor
group. Unclassified summaries emit at most 100 groups and three deterministic examples
per group.

`self_attn.g_proj.weight` is contextual evidence checked on both KDA and MLA layers.
It cannot classify either attention kind, and its presence does not establish a gate
formula. Likewise, the three shared-expert projection names establish tensor coverage
but do not reveal the logical number of shared experts. Attention Residual tensor
presence and descriptor consistency do not validate its formula, execution order, or
runtime use.

## Limitations

This tool validates checkpoint schema and structural assumptions.
It does not prove numerical inference correctness.

Tensor presence does not prove runtime use. Header evidence does not prove formulas or
execution order. The logical shared expert count is not derived from the three
projection names.

Presence validation asks whether required names exist. Structural consistency asks
whether their layer coverage and descriptors agree. Neither establishes framework
mapping correctness, and mapping correctness would still not establish numerical
correctness.

Phase 2 does not access Hugging Face, load safetensors payloads, parse GGUF or
llama.cpp sources, validate framework mappings, make numerical-inference claims, or
assert routing behavior, quantization nibble semantics, Attention Residual formulas,
Attention Residual boundary behavior, KDA recurrence semantics, MLA gate formulas, or
runtime execution order. It does not validate tokenizers, payload values, runtime
execution, or numerical parity.

## Optional GGUF structural inventories

Phase 3A adds generic, local GGUF descriptor reading and policy-driven structural
comparison. Install the pinned optional dependency separately:

```bash
python -m pip install -e '.[gguf]'
```

Create a canonical inventory:

```bash
omiv gguf-normalize \
  --input model.gguf \
  --output fixtures/gguf/model.inventory.json
```

Compare a source inventory with a converted inventory:

```bash
omiv gguf-diff \
  --source fixtures/gguf/source.inventory.json \
  --target fixtures/gguf/target.inventory.json \
  --policy policies/qwen2_5_0_5b_fp16_to_q8_0.yaml
```

GGUF support is isolated behind an adapter and uses `GGUFReader(path, mode="r")`.
`GGUFReader` uses `numpy.memmap`; metadata and tensor descriptors are parsed eagerly.
OMIV never accesses or materializes `ReaderTensor.data`, although payload address
ranges may remain mmap-backed by the reader.

The artifact SHA-256 reads every file byte, including payload bytes, but does not
interpret tensor values. Canonical tensor shapes are the GGUF on-disk dimension order
reported by `ReaderTensor.shape`, never `tensor.data.shape`.

Metadata scalars retain their explicit GGUF type and value. Arrays of at most 16
elements are stored inline. Larger arrays retain element type, length, and a
deterministic SHA-256 produced from typed binary serialization; `repr()` is not used.
The serialization preserves each declared GGUF scalar width. Inventory digests may
therefore change from pre-release Phase 3A output because this canonical scalar
encoding was corrected before the first Phase 3A release. This keeps tokenizer arrays
from expanding canonical inventories.

The included Qwen policies validate exact architecture identity, tensor names, shape
mappings, selected metadata behavior, and name-sensitive GGML type transitions.
`general.file_type` is allowed to differ, while `qwen2.context_length` drift is
reported as WARN rather than assumed to be caused by quantization.

Matching names, shapes, and allowed GGML-type transitions proves structural conversion
fidelity only. It does not prove tensor payload correctness, dequantization
correctness, runtime use, or numerical parity.

The synthetic `kimi-linear-moe.gguf` fixture is only a regression case for reading a
complex GGUF inventory. It is not official Kimi K3 evidence and supports no Kimi K3
production claim. Phase 3A does not perform HF-to-GGUF semantic mapping, split-GGUF
aggregation, llama.cpp source parsing, payload decoding, inference, tokenizer parity,
or numerical comparison.
