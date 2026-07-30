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

Local inventory, validation, mapping, reporting, and conversion commands remain
offline. Phase 4F-1 adds explicitly invoked remote commands for public Hugging Face
repository metadata and bounded byte-range inspection. The production adapter uses
the documented Hub API directly; `huggingface_hub` remains an optional, lazily
imported integration rather than a runtime requirement.

## Core, format adapters, and model packs

Phase 4C separates OMIV into three layers:

- **Core** owns canonical hashing, safe writes, report schemas and verification,
  inventory base types, manifest parsing, mapping resolution and validation,
  coverage/uniqueness rules, provenance-availability semantics, and CLI
  orchestration.
- **Format adapters** parse Safetensors or GGUF structure, metadata, dtype, shape,
  and physical tensor descriptors. They do not interpret model-family tensor names.
- **Model packs** contain model-family identity, format ontologies, config
  interpretation, structural expectations, logical ties, mapping manifests, and
  versioned capability metadata.

A model pack contains model-family-specific interpretation rules. Format readers
parse artifacts, while the core validation engine operates on canonical semantic
entities. Adding a model family should not require changing the core resolver or
validator.

The built-in production packs are:

| Pack | Capabilities | Formats |
| --- | --- | --- |
| `qwen2` | `hf_ontology`, `gguf_ontology`, `semantic_mapping` | HF Safetensors → GGUF |
| `kimi-k3` | `checkpoint_ontology`, `checkpoint_schema` | Safetensors header inventory |

`synthetic-dense` is a tiny two-layer, test-only pack used to prove that the same
core classifier, resolver, coverage checks, shape checks, and report generator work
for a second ontology. It is not production-supported and is hidden from normal
listings.

```bash
omiv model-packs list
omiv model-packs list --include-test-packs
omiv model-packs show --pack qwen2
```

The registry is deliberately static: only packs explicitly imported by OMIV are
available. Phase 4C performs no arbitrary runtime imports, user-supplied path loading,
entry-point discovery, `eval`, or `exec`. This keeps untrusted CLI input from becoming
Python code execution. A future built-in pack is added by implementing the typed
capability-gated interface, registering its trusted import, and adding its ontology,
constraints, manifests, and tests; the format readers and core resolver/validator do
not change.

Each pack has canonical `omiv.model-pack.v1` metadata containing its ID, schema
version, pack version, family, capabilities, supported formats, and support status.
Its deterministic SHA-256 covers only this declarative metadata. It does **not** prove
that Python implementation source, bytecode, dependencies, or behavior are unchanged.

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

Run the optional GGUF integration tests by enabling them and configuring the local
model paths:

```bash
OMIV_RUN_GGUF_INTEGRATION=1 \
OMIV_QWEN_GGUF_DIR=/path/to/qwen-gguf-files \
OMIV_KIMI_LINEAR_GGUF=/path/to/kimi-linear-moe.gguf \
python -m pytest tests/test_gguf_integration.py -q
```

`OMIV_QWEN_GGUF_DIR` must contain the FP16, Q8_0, and Q4_K_M Qwen files named in
`tests/test_gguf_integration.py`. `OMIV_KIMI_LINEAR_GGUF` is the full path to the
Kimi Linear GGUF file. Tests whose configured files are absent skip cleanly.

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

Phase 3B can persist the same comparison as deterministic JSON and Markdown:

```bash
omiv gguf-diff \
  --source fixtures/gguf/qwen2_5_0_5b_fp16.inventory.json \
  --target fixtures/gguf/qwen2_5_0_5b_q8_0.inventory.json \
  --policy policies/qwen2_5_0_5b_fp16_to_q8_0.yaml \
  --json-output reports/gguf/qwen2_5_0_5b_fp16_to_q8_0.report.json \
  --markdown-output reports/gguf/qwen2_5_0_5b_fp16_to_q8_0.report.md
```

Markdown can also be rendered later from a valid JSON report:

```bash
omiv report \
  --input reports/gguf/qwen2_5_0_5b_fp16_to_q8_0.report.json \
  --format markdown \
  --output reports/gguf/qwen2_5_0_5b_fp16_to_q8_0.report.md
```

Verify the JSON report without the original inventory or artifact:

```bash
omiv report-verify \
  --input reports/gguf/qwen2_5_0_5b_fp16_to_q8_0.report.json
```

`report-verify` exits 0 for a valid report, 1 when a structurally valid report's
integrity digest does not match, and 2 for malformed input or an unsupported report
schema. This verifies the report payload's integrity only; it does not revalidate
the artifact or establish authenticity.

### Deterministic reports and hashes

The versioned `omiv.gguf-comparison-report.v1` JSON envelope contains no timestamp,
absolute path, host name, user name, environment dump, or other machine identity.
Objects use sorted keys, compact UTF-8 JSON is used for hashing, list order remains
significant, and NaN and Infinity are rejected. The persisted JSON is pretty-printed
for inspection, but its integrity digest covers only the canonical compact value of
the envelope's `report` member. It never covers or refers to the `integrity` member
itself. Re-running the same tool version with semantically identical validated inputs
and policy produces identical report content.

Four SHA-256 values have deliberately different meanings:

- The **artifact hash** covers the underlying GGUF file bytes, including payload
  bytes, without interpreting tensor values.
- The **inventory hash** covers the canonical JSON value of the complete validated
  GGUF inventory. Reformatting that inventory file does not change this hash.
- The **policy hash** covers the complete validated semantic policy, including its
  explicit ID, schema version, selectors, metadata rules, and defaults.
- The **report hash** covers the canonical report payload, excluding the integrity
  envelope to avoid self-reference.

A valid report SHA-256 proves that the report payload has not changed since the digest
was computed. It does not prove who generated the report, that the source artifacts
were trustworthy, or that the underlying model is numerically correct.

### Output safety

JSON and Markdown output parent directories are created when needed. An absent output
or an existing regular output file is replaced only after the entire report has been
validated and serialized. OMIV creates a restrictive-permission temporary file in the
destination directory, writes and flushes it, calls `fsync` where the platform
supports it, and then uses `os.replace` for same-directory atomic replacement.
Temporary files are removed after success and handled write failures. Existing output
symlinks and non-regular destinations are rejected, as are output paths resolving to
the source inventory, target inventory, or policy. Ordinary existing report files are
overwritten by design.

These checks reduce accidental partial writes and straightforward symlink misuse; they
do not claim to eliminate every time-of-check/time-of-use race available to a hostile
process with concurrent access to the destination directory. Directory durability
after a power loss is platform- and filesystem-dependent because the directory itself
is not fsynced. File permissions and replacement semantics also remain subject to the
operating system, filesystem, parent-directory permissions, and process umask.
SHA-256 integrity is not a signature and provides no authorship, non-repudiation, or
trust in the original artifact.

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

## Local Hugging Face Safetensors inventories

Phase 4A securely inventories a local Qwen2 Safetensors checkpoint and assigns its
measured physical tensors stable Qwen2 canonical identities:

```bash
omiv hf-normalize \
  --model-pack qwen2 \
  --model-dir /path/to/local/Qwen2.5-0.5B-Instruct \
  --provenance /path/to/local/Qwen2.5-0.5B-Instruct/omiv-source.json \
  --output fixtures/hf/qwen2_5_0_5b_instruct.inventory.json
```

Provenance is optional. When absent, the inventory records that it is unavailable
rather than guessing a repository or revision. Supported provenance fields are
`repository`, `revision`, `source`, and `purpose`; absolute paths and unknown keys are
rejected.

Exactly two checkpoint layouts are supported:

- a monolithic `model.safetensors` with no index;
- an indexed sharded checkpoint whose `model.safetensors.index.json` declares every
  safe shard basename and tensor assignment.

The reader rejects ambiguous layouts, missing or undeclared shards, traversal and
absolute shard names, shard symlink escapes, non-regular shards, duplicate tensor
names, index/header disagreements, and `total_size` contradictions. It never treats a
recursive search for arbitrary Safetensors files as checkpoint truth.

OMIV reads only the 8-byte Safetensors prefix and the declared JSON header. It never
reads, decodes, maps, hashes, or materializes tensor payload bytes. Config and index
digests use the shared canonical JSON encoding, so inconsequential JSON key order does
not change the inventory. Full shard SHA-256 is deliberately omitted.

Defensive limits are centralized in `omiv.hf.limits`: config 1 MiB, index 16 MiB,
provenance 64 KiB, Safetensors header 64 MiB, one million tensors, 10,000 shards,
4,096-byte tensor names, rank 16, dimensions at most 2^40, and element counts below
2^63. JSON must be UTF-8, object-key duplicates are rejected, and nesting is capped at
128.

The Qwen2 ontology covers embeddings, output norm, Q/K/V/O projections and biases,
per-layer norms, and gate/up/down FFN projections. Static checks compare config layer
coverage, attention-derived K/V width, embedding/normalization dimensions, FFN shapes,
and safely mapped declared dtype. Unknown names remain visible as unclassified
physical tensors.

A logical tied tensor is not an additional physical tensor. OMIV records the declared
relationship without inventing payload data or claiming that two materialized tensors
contain identical values.

For tied Qwen2 embeddings with no physical `lm_head.weight`, the logical output
projection points to the token embedding and is marked `materialized: false`. If both
physical tensors exist, both remain in the inventory and payload equality is explicitly
unverified.

Phase 4A does not validate HF-to-GGUF mappings, execute converters, inspect tensor
values, compare tokenizers, run inference, or make numerical-fidelity claims.

## Semantic mapping manifests

Phase 4B adds versioned, declarative mapping validation between a canonical Hugging
Face Safetensors inventory and a canonical GGUF inventory. A mapping manifest names
the model family, model-pack ID/schema/minimum version, and formats explicitly; its ID
is part of the manifest and is never derived from a file name. Compact `{layer}`
bindings connect every decoder layer without relying on inventory or tensor-file
order.

The first manifest is
`mappings/qwen2_5_0_5b_hf_to_gguf.yaml`. It covers Qwen2 embeddings, output norm,
Q/K/V/O projections and biases, layer norms, FFN gate/up/down projections, and the
logical tied output projection. The derived Qwen2 GGUF ontology preserves each exact
GGUF tensor name, GGML type, and GGUF descriptor shape while assigning the same stable
canonical identities used by the HF inventory. Unknown GGUF names remain
unclassified and cause complete target coverage to fail.

Physical and logical source tensors are intentionally distinct. A physical source is
present in the Safetensors header. A logical source records a semantic relationship,
such as the tied `qwen2.output_projection.weight`, without synthesizing a physical
`lm_head.weight`. The output mapping requires the physical GGUF `output.weight` and
records `qwen2.token_embedding.weight` as the logical tie's physical source, while
leaving payload origin and equality unverified.

Run mapping validation and optionally persist both report formats:

```bash
omiv mapping-validate \
  --model-pack qwen2 \
  --source fixtures/hf/qwen2_5_0_5b_instruct.inventory.json \
  --target fixtures/gguf/qwen2_5_0_5b_fp16.inventory.json \
  --mapping mappings/qwen2_5_0_5b_hf_to_gguf.yaml \
  --json-output reports/mapping/qwen2_5_0_5b_hf_to_gguf_fp16.report.json \
  --markdown-output reports/mapping/qwen2_5_0_5b_hf_to_gguf_fp16.report.md
```

The command exits 0 for `pass` or `pass_with_warnings`, 1 for a structural mapping
failure, and 2 for a malformed inventory or manifest. The current Qwen case passes
MAP-001 through MAP-008 and warns at MAP-009 because the committed GGUF inventories
do not record the source artifact hash, source repository/revision, converter commit,
or conversion command.

`--model-pack` is the explicit selection mechanism. For backward compatibility it
may be omitted when trusted inventory/config metadata or the manifest identifies
exactly one registered production pack. Detection is bounded to registered packs and
model-family metadata; checkpoint or manifest filenames are never used. Missing,
unsupported, or ambiguous identification exits 2, and ambiguity never selects a pack
silently. The selected pack family, manifest family, supported formats, pack schema
version, and minimum pack version must agree.

`shape_relation` concerns descriptor conventions only. Qwen matrices declare
`reverse_dimensions`, including square matrices, because GGUF descriptor dimensions
are reversed relative to the HF/PyTorch shape display. `payload_transform: identity`
separately records the declared converter behavior; it is not a transpose claim and
does not prove anything about tensor values. Vectors use `shape_relation: identical`.

Mapping reports use the separate `omiv.semantic-mapping-report.v1` envelope and include
source inventory, target inventory, target artifact, manifest, model-pack ID/version,
model-pack metadata, and report digests. The pack digest has the declarative limitation
described above. Reports contain no timestamp or absolute path. Existing report tooling
recognizes both GGUF comparison and semantic mapping report schemas:

```bash
omiv report-verify \
  --input reports/mapping/qwen2_5_0_5b_hf_to_gguf_fp16.report.json

omiv report \
  --input reports/mapping/qwen2_5_0_5b_hf_to_gguf_fp16.report.json \
  --format markdown \
  --output reports/mapping/qwen2_5_0_5b_hf_to_gguf_fp16.report.md
```

Report integrity detects changes to the persisted report payload; it is not a
signature and does not revalidate the original inventories. Matching names, canonical
identities, layers, parameters, and shapes cannot establish conversion lineage.
Exact provenance must be recorded by the target artifact rather than inferred from
structural similarity.

A successful semantic mapping report proves that the declared source and target
tensor semantics are completely and uniquely connected under the mapping manifest.
It does not prove that target tensor payload values were copied, transformed,
quantized, or generated correctly.

Phase 4C performs no payload access, value hashing or sampling, dequantization,
converter execution, tokenizer validation, inference, numerical parity, packed MoE
expert mapping, split/concatenate/reshape/fusion transform, or Kimi K3 production
mapping.

## Conversion provenance and lineage

Phase 4D adds the model- and format-independent
`omiv.conversion-provenance.v1` schema. It cryptographically links the complete
declared chain:

```text
source artifacts → source inventory → model pack → mapping manifest
→ process/tool/invocation → target artifacts → target inventory
```

The provenance ID is explicit and is never derived from a filename. The canonical
payload records an operation (`convert`, `quantize`, `export`, `compile`, `pack`,
`merge`, `shard`), one or more source and target artifacts, exact inventory
identities, model-pack and mapping identities, an immutable tool identity, an ordered
argument-array invocation, and process completion state. Qwen2.5 HF-to-GGUF is the
first reference workflow, but the core PROV rules contain no Qwen, Kimi, llama.cpp,
or GGUF-specific tensor logic.

Canonical provenance never contains timestamps, durations, absolute paths, hostnames,
usernames, process IDs, temporary names, environment dumps, stdout, or stderr.
Sensitive arguments such as `--token`, `--password`, `--api-key`, `--secret`,
`--credential`, and `--auth` retain their argument name but replace the value with
the canonical `[REDACTED]` marker. Invocation is always an argument array; OMIV never
uses `shell=True`, command interpolation, `eval`, or `exec`.

Validate an existing envelope using inventory-level evidence alone:

```bash
omiv provenance-validate \
  --provenance conversion.provenance.json \
  --source-inventory source.inventory.json \
  --target-inventory target.inventory.json \
  --mapping mappings/qwen2_5_0_5b_hf_to_gguf.yaml \
  --model-pack qwen2 \
  --json-output conversion.provenance.report.json \
  --markdown-output conversion.provenance.report.md
```

Optional `--source-artifact ROLE=PATH` and `--target-artifact ROLE=PATH` arguments
request current full-file SHA-256 verification. Without them, OMIV uses only
full-artifact digests explicitly available in trusted inventories and emits WARN for
anything not checked. Descriptor inventory hashes are never mislabeled as complete
artifact hashes.

The hash meanings are distinct:

- Source and target inventory SHA-256 values identify canonical descriptor inventory
  payloads.
- Artifact SHA-256 values cover every byte of a physical artifact.
- Model-pack metadata SHA-256 covers declarative `omiv.model-pack.v1` metadata.
- Mapping SHA-256 covers the canonical validated manifest.
- Provenance SHA-256 covers only the canonical `provenance` value.
- Report SHA-256 covers only the canonical report payload.

All use the shared `omiv-json-v1` canonicalization where the hashed value is JSON.
These integrity digests are deterministic tamper detection, not signatures or PKI.
`report-verify` and `report --format markdown` support
`omiv.conversion-provenance-report.v1` alongside all earlier report schemas.

### Conservative conversion capture

`conversion-run` accepts only a strict `omiv.conversion-run.v1` YAML or JSON spec:

```yaml
conversion_schema: omiv.conversion-run.v1
conversion_id: qwen2.5-0.5b-instruct-f16
offline: true
source:
  model_dir: /runtime/source
  inventory: /runtime/source.inventory.json
  artifact_roles:
    - role: config
      path: /runtime/source/config.json
      required: true
interpretation:
  model_pack: qwen2
  mapping: mappings/qwen2_5_0_5b_hf_to_gguf.yaml
tool:
  name: llama.cpp
  repository: ggml-org/llama.cpp
  repository_dir: /runtime/clean-llama-cpp
  expected_revision: 0123456789012345678901234567890123456789
  require_clean_worktree: true
  executable: python
  entrypoint: convert_hf_to_gguf.py
runtime:
  python: true
  packages:
    - gguf
    - safetensors
    - torch
    - transformers
invocation:
  arguments:
    - "{source_model_dir}"
    - --outfile
    - "{target_output}"
    - --outtype
    - f16
target:
  output: /runtime/output.gguf
  format: gguf
  inventory_output: /runtime/output.inventory.json
  role: model
outputs:
  provenance: /runtime/output.provenance.json
  report_json: /runtime/output.provenance.report.json
  report_markdown: /runtime/output.provenance.report.md
```

Runtime paths exist only in the spec and process argument list used at execution;
they are replaced by explicit placeholders in canonical provenance. The entrypoint
must resolve inside the configured repository, repository HEAD must equal the full
expected commit, and a required-clean checkout must be clean. Inputs and outputs
cannot collide, outputs must be distinct and absent, and output symlinks are rejected.
An optional runtime probe invokes the same resolved Python executable with an argument
array and records only its version plus the explicitly allowlisted package versions.
The process uses `subprocess` with an argument list and `shell=False`. A failed process
does not emit successful provenance or reports and partial targets are not
automatically deleted. These checks are conservative best-effort protections and do
not claim perfect protection against concurrent filesystem changes or TOCTOU races.

Use a clean detached converter worktree pinned to a reviewed full commit. Do not use a
development checkout containing unrelated model-support changes. Capture is offline:
there are no cloud APIs, telemetry, network fetches, arbitrary plugins, or GitHub API
calls.

When a validated provenance report is supplied to `mapping-validate` through
`--provenance-report`, MAP-009 consumes its exact-lineage summary instead of
reimplementing PROV validation. Exact lineage PASS makes MAP-009 PASS, incomplete
lineage remains WARN, and contradictory lineage makes MAP-009 FAIL. Without
provenance, MAP-009 remains WARN. Earlier persisted mapping reports remain readable
and verifiable.

A complete conversion provenance chain establishes which source artifacts, semantic
interpretation, tool revision, invocation, and target artifacts were declared and
cryptographically linked. It does not prove that the converter was bug-free, that
target payload values are numerically correct, or that inference outputs match the
reference implementation.

## Logical target realizations

Phase 4E separates a logical tensor identity from the physical representation used
by a target. A mapping may declare a strict
`omiv.target-realization.v1` `one_of` contract. Exactly one alternative must be
satisfied; zero or multiple matches fail, and alternatives have no implicit
precedence.

The supported realization kinds are:

- `materialized`: the target tensor exists exactly once under its declared physical
  name and canonical identity.
- `format_alias`: both the alias and its backing tensor exist, and explicit target
  metadata establishes a named format contract. Tensor absence never establishes an
  alias.
- `backend_fallback`: the logical tensor is absent, the fallback tensor exists, and
  trusted model-pack evidence plus validated conversion provenance establishes a
  pinned, architecture-scoped backend policy.
- `synthesized`: the target tensor exists and its converter, immutable revision,
  stable synthesis rule, and operation (`copy`, `initialization`, `derivation`, or
  `transform`) are declared and provenance-checked.

Qwen2 tied output projection is the first production case. The realization-aware
manifest at
`mappings/qwen2_5_0_5b_hf_to_gguf_realizations.yaml` accepts either a separately
materialized `output.weight` (the 291-tensor GGUF) or the reviewed llama.cpp Qwen2
runtime fallback to `token_embd.weight` (the locally generated 290-tensor GGUF).
The fallback evidence is static data owned by the Qwen2 model pack. It pins the
backend repository, immutable revision, architecture, policy symbol, logical and
fallback identities, and runtime consumer. User manifests can reference trusted
evidence IDs but cannot create trusted evidence, load it from the filesystem, or
supply executable policy code.

The 290-tensor fallback requires conversion provenance tied to the
realization-aware manifest and pinned converter revision. Absence of
`output.weight` alone is insufficient: it could equally indicate an incomplete or
incorrect target. The 291-tensor materialized alternative needs no backend fallback
claim, so structural validation may pass while MAP-009 remains WARN when exact
lineage is unavailable.

Payload relation is independent and explicit. Phase 4E accepts only
`status: not_checked`; structural validation never upgrades it to `declared`,
`digest_verified`, or `numerically_verified`, and never implies aliasing or payload
identity.

> A structural realization PASS proves that one declared and evidence-supported
> target representation satisfies the logical mapping contract. It does not prove
> payload equality, numerical correctness, or runtime output parity.

The original Qwen2 manifest retains its Phase 4C
`target_materialization: required` behavior and is not reinterpreted as `one_of`;
therefore the legacy 290-tensor report remains a deliberate failure. Kimi K3 exposes
no realization evidence. Future Kimi K3 mappings, MoE expert packing, fused tensors,
and accelerator-specific backends require their own explicit schemas and trusted,
architecture-scoped evidence rather than extrapolation from the Qwen2 policy.

## Pinned remote repository snapshots and bounded Range probes

Phase 4F-1 introduces a provider-neutral remote-artifact boundary with a Hugging
Face model-repository adapter. The primary identity is always the provider,
repository ID, repository type, requested revision, and resolved immutable commit;
an arbitrary URL is never accepted by the CLI as repository identity. A mutable
reference such as `main` is resolved once through the Hub API, both revisions are
recorded, and all later file requests use the full resolved commit. OMIV never
silently returns to `main`.

Create a metadata-only snapshot and its reports with:

```bash
omiv remote-snapshot \
  --provider huggingface \
  --repo unsloth/Kimi-K3-GGUF \
  --revision main \
  --path-prefix UD-IQ1_M \
  --pattern "*.gguf" \
  --output snapshots/huggingface/unsloth_Kimi-K3-GGUF_UD-IQ1_M.snapshot.json \
  --report-output reports/remote/unsloth_Kimi-K3-GGUF_UD-IQ1_M.snapshot.report.json \
  --markdown-output reports/remote/unsloth_Kimi-K3-GGUF_UD-IQ1_M.snapshot.report.md
```

Enumeration requests repository metadata only. Every returned path is treated as
untrusted and must be a bounded-length canonical POSIX relative path with no
absolute, empty, dot, traversal, backslash, control, NUL, or percent-decoded
traversal component. Selection is restricted to the requested subtree and patterns,
sorted deterministically, and records declared sizes plus stable Git, LFS, or Xet
identifiers where the provider supplies them. It stores no timestamps, machine
paths, token, cache location, temporary URL, or signed query parameter.

Names of the form `<stem>-00001-of-00015.gguf` are grouped generically. The
snapshot reports observed and declared ordinals, duplicates, gaps, inconsistent
counts, non-contiguity, independent sets, and unrelated GGUF files. The shard count
is always derived from pinned API evidence; it is not specific to 15. Filename
completeness is repository-layout evidence only and is not complete GGUF-header or
split-metadata validation.

Probe one explicit interval, or the safe eight-byte GGUF prefix, with:

```bash
omiv remote-range-probe \
  --snapshot snapshots/huggingface/unsloth_Kimi-K3-GGUF_UD-IQ1_M.snapshot.json \
  --file UD-IQ1_M/Kimi-K3-UD-IQ1_M-00001-of-00015.gguf \
  --offset 0 \
  --length 8 \
  --output reports/remote/range-probe.json

omiv remote-gguf-prefix \
  --snapshot snapshots/huggingface/unsloth_Kimi-K3-GGUF_UD-IQ1_M.snapshot.json \
  --file UD-IQ1_M/Kimi-K3-UD-IQ1_M-00001-of-00015.gguf \
  --output reports/remote/unsloth_Kimi-K3-GGUF_UD-IQ1_M_shard1.prefix.report.json \
  --markdown-output reports/remote/unsloth_Kimi-K3-GGUF_UD-IQ1_M_shard1.prefix.report.md
```

The example filename illustrates the currently observed repository layout; the
integration test and generic implementation derive the first shard and count from
the immutable snapshot rather than relying on it.

The Range client guarantees HTTPS, an explicit Hugging Face, `.huggingface.co`,
`.cdn.hf.co`, and Xet bridge host policy, an explicit
start and positive length, configured response/header/error-body caps, bounded
redirects with destination revalidation, cross-host Authorization removal,
`Accept-Encoding: identity`, and incremental reads of at most the permitted bytes
plus one overflow-detection byte. Success requires HTTP 206, a single matching
`Content-Range`, the exact body length, and agreement between the range total and
snapshot size. HTTP 200 is never a successful fallback, multipart and compressed
ranges are rejected, cookies are not persisted, and raw response bytes are omitted
unless an explicit preview of at most 16 bytes is requested.

Hugging Face may redirect resolved files to LFS or Xet storage using expiring signed
URLs. OMIV validates each redirect host and retains repository identity separately;
it neither persists nor logs those URLs or reconstructs Xet chunks. A provider path
that cannot return a standards-compliant eight-byte 206 response fails honestly.
The host policy is not relaxed and the file is not downloaded as a fallback.

The snapshot SHA-256 covers the canonical `snapshot` payload and excludes its
`integrity` member. A remote report SHA-256 similarly covers only the canonical
`report` payload. These deterministic hashes detect changes but are not signatures,
authorship claims, or independent attestations. Remote reports work with
`report-verify` and `report --format markdown`.

Remote commands are explicitly online and reject `--offline`. All pre-4F commands
remain offline and make no background request. Public repositories need no token;
Phase 4F-1 has no token-persistence feature, telemetry, upload, arbitrary crawling,
generic URL CLI, local-model discovery, or tensor payload access. The normal test
suite mocks metadata and transport. The opt-in live test is enabled only with
`OMIV_RUN_REMOTE_INTEGRATION=1`, with optional `OMIV_HF_REPO`,
`OMIV_HF_REVISION`, and `OMIV_HF_PATH_PREFIX` overrides.

> A successful repository snapshot and Range probe prove that a pinned remote
> artifact set was enumerated and that selected byte ranges were retrieved with
> validated HTTP semantics. They do not prove complete GGUF headers, tensor payload
> integrity, semantic mapping correctness, quantization fidelity, or runtime parity.

Phase 4F-2 will review GGUF prefix endianness and aggregate complete split-header
metadata. Phase 4F-1 deliberately does not parse header length, tensor counts,
metadata counts, complete headers, or payloads.
