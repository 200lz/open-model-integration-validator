# Case Study 01 — Validating an Unsloth Q8_0 GGUF Export with OMIV

This case study records an independent structural validation and
provenance-observability analysis of an Unsloth export. It separates the
successful export result from the evidence gaps observed around the exported
artifacts.

## Why this case

This is OMIV's first public ecosystem case study. This case began with a [public
technical exchange](https://x.com/chen_linzh96875/status/2087210507782807856)
with Daniel Han. We are grateful to Daniel for suggesting Gemma 4 E2B IT as the
first reproducible case and for giving OMIV the opportunity to test a real Unsloth
export path. OMIV then independently executed and analyzed the export. The
relationship described here is limited to that public technical exchange.
(P1-C001; P1-AUTHORIZED-CONTEXT)

The fixed source was `google/gemma-4-E2B-it` at revision
`3e22461f65e89153144f8adb70e3b8c2cc9845a7`: 9 files, 10,278,849,571 bytes,
with source-manifest SHA-256
`b73a8a4dd3aa11c51f5dcc06e13dbdecbbcd1f7eaa55518febe8ffeaf10d8a75`.
The canonical source manifest remained unchanged during export. (P1-C002;
A1-LINEAGE)

## Result in brief

The export itself succeeded. Retained execution evidence records one successful
Q8_0 export and verified artifact custody. (P1-C003; A1-EXPORT-HISTORY)

The positive reproducibility result is deliberately narrower: the current Q8_0 and
mmproj file sizes and SHA-256 values match retained historical C1 observations. The
historical C1 bytes are unavailable, so this is `HISTORICAL_C1_MATCH`, not a new
direct C1/C2 file comparison. (P1-C009; A1-REPRODUCIBILITY)

| Artifact | Format | Bytes | SHA-256 | Metadata | Tensors | Type distribution | Evidence |
|---|---:|---:|---|---:|---:|---|---|
| Main Q8_0 | GGUF v3 | 4,954,594,880 | `fbf3f93d603e92dbcf00742163cc3018b9bf8fbfbcf87158cc836e5ed0bc9455` | 51 | 601 | 318 Q8_0; 283 F32 | P1-C004, P1-C005; A1-INPUT-CUSTODY, A1-MAIN-GGUF |
| BF16 mmproj | GGUF v3 | 986,833,792 | `e00089a95d2dc85c71f249bd83760e348f721757318802ddb889c65ec64eae3c` | 39 | 1,411 | 247 BF16; 1,164 F32 | P1-C006, P1-C007; A1-INPUT-CUSTODY, A1-MMPROJ-GGUF |

All parsed tensor byte ranges were inside their files and non-overlapping. No tensor
payload values were interpreted for semantic or numerical evaluation. (P1-C008,
P1-C015; A1-MAIN-GGUF, A1-MMPROJ-GGUF, A1-LIMITATIONS)

## Methodology

The analysis was completely offline. It verified custody hashes and retained
evidence seals, parsed GGUF headers, metadata, and tensor descriptors, validated
descriptor ranges, compared deterministic OMIV-native reports, assembled
source/work-copy/target lineage, and evaluated the contextual association between
the main GGUF and mmproj. It did not load a model, run inference, invoke an
exporter, use a GPU, or access tensor payload values for fidelity testing. (P1-C014,
P1-C020; A1-NATIVE-REPEATABILITY, A1-CAPABILITY-COVERAGE, A1-LIMITATIONS)

See [methodology.md](methodology.md) for the concise procedure,
[results.json](results.json) for the machine-readable result, and
[evidence-index.json](evidence-index.json) for the public evidence definitions and
commitments.

## Source → work copy → GGUF lineage

The retained lineage identifies the fixed source repository, revision, size, file
count, and manifest. During export, only `tokenizer_config.json` changed in the
tracked work-copy configuration set; `chat_template.jinja`, `config.json`,
`generation_config.json`, and `processor_config.json` remained unchanged.
(P1-C002, P1-C013; A1-LINEAGE)

The semantic JSON-pointer comparison of `tokenizer_config.json` contains 195
changes: 181 additions and 14 removals. This is a verified lineage event. It is not,
by itself, evidence of a bug. (P1-C013; A1-LINEAGE)

Neither target GGUF metadata inventory contained the exact source revision. That is
a provenance-observability gap: it makes the exported files harder to tie back to
the fixed source without sidecar evidence, but it is not proof that the model
weights are incorrect. (P1-C010, P1-C017; A1-LINEAGE)

## Main/mmproj association

The main GGUF and mmproj have a moderate contextual association: retained execution
evidence places them in the same export, and their exporter and
model-family/projector-role metadata are compatible by inference. (P1-C011;
A1-ASSOCIATION)

No cryptographic or format-native cross-reference binds the files. Their shared
name, `Work Copy`, has low identifying power. This is an artifact-association gap,
not proof that the pair is incompatible. (P1-C012, P1-C018; A1-ASSOCIATION)

## What OMIV made visible

- Neither target GGUF metadata inventory contained the exact source revision,
  exposing a provenance-observability gap. (P1-C010, P1-C017; A1-LINEAGE)
- The main/mmproj relationship was contextual rather than cryptographically or
  format-natively bound. (P1-C011, P1-C012; A1-ASSOCIATION)
- A specific work-copy mutation was measured: 195 JSON-pointer changes in
  `tokenizer_config.json`, without labeling that mutation a bug. (P1-C013;
  A1-LINEAGE)
- Current OMIV coverage is strong for custody, GGUF structure, scalar metadata,
  tensor inventories, structural comparisons, and deterministic reporting, while
  lineage assembly, large-array disclosure, companion binding, and fidelity
  evaluation need additional product support. (P1-C019; A1-CAPABILITY-COVERAGE)

These observations do not identify which component originated the behavior. In
particular, missing revision metadata and absent main/mmproj binding must not be
attributed solely to Unsloth, and the tokenizer configuration mutation must not be
attributed to a specific component without root-cause evidence. This study did not
determine whether those observations originated in Unsloth, llama.cpp tooling,
GGUF conventions, llm-compressor, or the surrounding export workflow. (P1-C021;
A1-LINEAGE, A1-ASSOCIATION, A1-LIMITATIONS)

## What this does not prove

- Semantic fidelity and numerical quantization fidelity were not evaluated.
  (P1-C015; A1-LIMITATIONS)
- Q8_0 tensor-type classification is not a quality result. (P1-C015;
  A1-MAIN-GGUF, A1-LIMITATIONS)
- Structural validation does not establish runtime compatibility. (P1-C016;
  A1-LIMITATIONS)
- A successful export does not by itself establish that every runtime will load or
  correctly execute the artifacts. (P1-C016; A1-EXPORT-HISTORY, A1-LIMITATIONS)
- `HISTORICAL_C1_MATCH` relies on retained C1 size/SHA-256 observations; historical
  C1 bytes were unavailable and no new direct C1/C2 file comparison occurred.
  (P1-C009; A1-REPRODUCIBILITY)

Additional boundaries are in [limitations.md](limitations.md). The complete claim
registry is [claims.json](claims.json), and every evidence ID it uses is defined in
[evidence-index.json](evidence-index.json).
