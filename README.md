# Open Model Integration Validator

Open Model Integration Validator (OMIV) turns local checkpoint-header evidence into
a compact, deterministic inventory and checks evidence-backed structural assumptions.
Phase 1 is intentionally narrow: it supports only the released Kimi K3 JSON header
inventory and four checkpoint-schema rules for layer layout, attention signatures,
and routed experts.

## Install

Python 3.11 or newer is required.

```bash
python -m pip install -e '.[dev]'
```

The runtime has no Hugging Face client and performs no network access.

## Normalize

The raw input must be a top-level JSON array of tensor header records. Normalization
validates every record but retains only counts, classifications, component coverage,
expert-ID sets, and diagnostics—not a second copy of all tensor descriptors.

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
```

Exit code 0 means all required rules passed, 1 means at least one rule failed, and 2
means the input inventory or schema was invalid. Failed rules include structured,
concise evidence.

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

## Limitations

This tool validates checkpoint schema and structural assumptions.
It does not prove numerical inference correctness.

Tensor presence does not prove runtime use. Header evidence does not prove formulas or
execution order. The logical shared expert count is not derived from the three
projection names.

Phase 1 does not access Hugging Face, load safetensors payloads, parse GGUF or
llama.cpp sources, validate framework mappings, make numerical-inference claims, or
assert routing behavior, quantization nibble semantics, Attention Residual formulas,
or Attention Residual boundary behavior.
