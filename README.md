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

Phase 5D uses the maintained `cryptography` library as its single cryptographic
backend, with Ed25519 as the initial signature algorithm. OMIV does not implement
cryptographic primitives itself, and private keys must never be committed. This
dependency baseline does not yet implement Phase 5D signing or trust evaluation.

Local inventory, validation, mapping, reporting, and conversion commands remain
offline. Phase 4F-1 adds explicitly invoked remote commands for public Hugging Face
repository metadata and bounded byte-range inspection. The production adapter uses
the documented Hub API directly; `huggingface_hub` remains an optional, lazily
imported integration rather than a runtime requirement.

## Model Passports

A Model Passport is a portable, integrity-linked summary of an AI artifact’s
identity, evidence, trust status, and known limitations.

A Model Chain of Custody is the integrity-linked history of how that artifact was
acquired, transformed, approved, deployed, and observed at runtime.

Phase 5A implements the first concept, not the second. A passport answers what an
artifact is, which immutable identity and validation evidence are known, which
checks remain unavailable, and what the recorded policies permit. It does not
invent lifecycle events. The custody section therefore reports `NOT_AVAILABLE`
and zero events until a future Phase 5B custody ledger supplies real evidence.

The same strict `omiv.model-passport.v1` document supports several audiences:

- A personal user gets a compact summary with prominent payload, security, and
  runtime limitations.
- A team can share a deterministic identity and structural-intake record without
  copying full tensor or header inventories.
- An enterprise system can consume typed trust dimensions, evidence references,
  policy digests, and usage-profile decisions.

Create and verify a passport entirely offline:

```bash
omiv passport create \
  --validation validations/unsloth_Kimi-K3-GGUF_UD-IQ1_M.validation.inventory.json \
  --output passports/unsloth_Kimi-K3-GGUF_UD-IQ1_M.passport.json \
  --markdown-output passports/unsloth_Kimi-K3-GGUF_UD-IQ1_M.passport.md

omiv passport verify \
  --input passports/unsloth_Kimi-K3-GGUF_UD-IQ1_M.passport.json

omiv passport show \
  --input passports/unsloth_Kimi-K3-GGUF_UD-IQ1_M.passport.json
```

Full verification reconstructs the referenced independent-validation inventory,
evidence graph, artifact index, model-pack identity, policy identities, passport
stages, multidimensional trust summary, and usage profiles. `--digest-only`
performs portable schema, digest, and internal policy reconstruction when private
dependencies are not present; it is explicitly reported as
`digest_only_verification`, never as full verification.

Trust is intentionally not a single score. The passport records separate identity,
structural, provenance, payload, security, custody, and runtime outcomes. Typical
structural evidence can yield `STRUCTURALLY_VALIDATED_WITH_LIMITATIONS` while
artifact-specific provenance remains `UNAVAILABLE` and payload, security, and
runtime checks remain `NOT_CHECKED`. An unavailable or unchecked stage is never
converted into `PASS`.

Four static usage profiles provide policy-scoped guidance:

- `local_experimentation` requires identity and format structure and can be
  `SUITABLE_WITH_LIMITATIONS`; this is not a safety claim.
- `team_structural_intake` additionally requires ontology and semantic mapping;
  unavailable provenance remains a visible review warning.
- `enterprise_structural_review` requires integrity-linked structural evidence and
  policies; missing provenance, payload, security, custody, and runtime evidence
  produces `REVIEW_REQUIRED`.
- `regulated_production` requires provenance, payload, tokenizer, security, custody,
  approval, deployment, and runtime evidence. Current structural-only passports are
  `NOT_SUITABLE`.

Phase 5A performs no security scanning, payload hashing or sampling, signing,
approval, deployment admission, backend execution, or runtime observation. A GGUF
parse does not establish safe execution, numerical conversion fidelity, backend
compatibility, or production approval. Phase 5B is reserved for a real,
integrity-linked custody-event ledger; the current validation evidence graph proves
evidence dependencies and is not treated as a custody history.

## Model Chain of Custody ledgers

Phase 5B adds the deterministic `omiv.custody-ledger.v1` lifecycle record. A Model
Passport summarizes an artifact's current identity and trust evidence; a Model Chain
of Custody records ordered lifecycle claims about that artifact. The Phase 4F evidence
graph remains a dependency graph and is never substituted for a custody ledger.

A hash-linked custody ledger proves that recorded events have not been modified,
removed, reordered, or relinked without detection.

It does not, by itself, prove that a real-world action occurred or that the actor was
authentic.

A complete enterprise custody chain additionally requires acquisition,
transformation, security, approval, deployment, runtime, and attestation evidence
according to policy.

Custody events use a deterministic sequence number, the previous event digest, and
their own canonical digest. They do not use wall-clock timestamps, UUIDs, hostnames,
usernames, or local paths for identity or ordering. The `event_id` changes when its
subject, claim, evidence, policy, or parent changes; each downstream digest then
changes because the previous digest is covered by the next event.

The v1 taxonomy reserves lifecycle events for source location, immutable identity,
acquisition, remote and format inspection, structural validation, transformation,
quantization, passport issuance, security inspection, approval, registry promotion,
deployment, runtime observation, revocation, and expiration. Reserved support does
not mean those actions occurred. OMIV emits only event types backed by supplied
evidence.

Create, verify, and inspect a custody evidence segment entirely offline:

```bash
omiv custody create \
  --passport passports/unsloth_Kimi-K3-GGUF_UD-IQ1_M.passport.json \
  --validation validations/unsloth_Kimi-K3-GGUF_UD-IQ1_M.validation.inventory.json \
  --profile evidence_segment \
  --output custody/unsloth_Kimi-K3-GGUF_UD-IQ1_M.custody-ledger.json \
  --report-output reports/custody/unsloth_Kimi-K3-GGUF_UD-IQ1_M.custody.report.json \
  --markdown-output reports/custody/unsloth_Kimi-K3-GGUF_UD-IQ1_M.custody.report.md

omiv custody verify \
  --input custody/unsloth_Kimi-K3-GGUF_UD-IQ1_M.custody-ledger.json

omiv custody show \
  --input custody/unsloth_Kimi-K3-GGUF_UD-IQ1_M.custody-ledger.json
```

`custody append` accepts a strict event-input document, verifies the source ledger,
derives the next sequence and parent digest, and writes a distinct output atomically.
Appended declarations remain `USER_DECLARED` and `UNATTESTED`; hash integrity never
upgrades their authenticity.

The static custody profiles are `evidence_segment`, `local_model_intake`,
`team_release`, `enterprise_deployment`, and `regulated_runtime`. An intact ledger can
be lifecycle-incomplete. Current Kimi evidence satisfies `evidence_segment`, but it
lacks acquisition, transformation, quantization, security, approval, registry,
deployment, and runtime events. Its correct overall custody result is therefore
`INCOMPLETE`, not `BROKEN` and not fully trusted.

Custody-linked passports use `omiv.model-passport.v2`; existing v1 passports remain
byte-identical and fully supported. The linked passport reports ledger availability
and integrity separately from incomplete lifecycle coverage and unattested event
authenticity.

Phase 5B does not implement signatures, signer or actor proof, revocation services,
approval workflows, deployment admission, runtime agents, security scanning, or
payload validation. Phase 5C may consume custody evidence in additional policy
decisions without changing these facts. Phase 5D is reserved for cryptographic
attestations and trust-root verification. Phase 5B is not legal chain-of-custody
certification.

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
| `kimi-k3` | `checkpoint_ontology`, `checkpoint_schema`, `gguf_ontology` | Safetensors header inventory → GGUF |

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

Phase 4F-1 deliberately does not parse header length, tensor counts, metadata
counts, complete headers, or payloads. Complete per-file headers begin in Phase
4F-2 below; cross-shard aggregation remains later work.

## Incremental remote GGUF v3 headers

Phase 4F-2 parses one pinned GGUF file at a time. Unlike Safetensors, GGUF has no
single field containing the complete header length. OMIV must decode the fixed
prefix, every metadata key/value encoding, and every tensor descriptor before it
can align the exclusive descriptor end and derive the tensor payload start.

```bash
omiv remote-gguf-header \
  --snapshot snapshots/huggingface/unsloth_Kimi-K3-GGUF_UD-IQ1_M.snapshot.json \
  --file UD-IQ1_M/Kimi-K3-UD-IQ1_M-00001-of-00015.gguf \
  --output inventories/remote/unsloth_Kimi-K3-GGUF_UD-IQ1_M_shard1.header.inventory.json \
  --report-output reports/remote/unsloth_Kimi-K3-GGUF_UD-IQ1_M_shard1.header.report.json \
  --markdown-output reports/remote/unsloth_Kimi-K3-GGUF_UD-IQ1_M_shard1.header.report.md
```

The filename above is an example from the immutable Phase 4F-1 snapshot. The
integration test derives the first ordinal and path from a complete filename
candidate rather than hard-coding the shard count or name.

The range-backed source uses half-open intervals `[start, end)`. Each HTTP request
has an explicit offset and length and is validated by the Phase 4F-1 206 and
`Content-Range` checks. A last-window cache avoids duplicate reads. Read-ahead is
never speculative: the parser supplies a conservative lower bound for bytes known
to remain in later metadata values or tensor descriptors. Early reads can therefore
fill a bounded window, while reads near the final descriptor shrink to the exact
remaining encoding. Alignment padding is not fetched, and after the payload start
is derived the source permanently rejects any interval whose exclusive end exceeds
that boundary.

The effective `omiv.remote-gguf-header-policy.v1` is embedded in every inventory and
hashed canonically. Defaults are:

| Limit | Default |
| --- | ---: |
| Total accepted header bytes | 64 MiB |
| Bytes per Range request | 256 KiB |
| Safe read-ahead | 256 KiB |
| Metadata entries | 1,000,000 |
| Tensor descriptors | 1,000,000 |
| Individual string bytes | 16 MiB |
| Metadata key bytes | 1,024 |
| Array elements | 10,000,000 |
| Tensor name bytes | 4,096 |
| Tensor dimensions | 4 |
| Alignment | 4,096 |
| Range requests | 4,096 |
| Preview bytes | 256 |

All limits have CLI overrides. Offset addition, alignment, array byte counts,
dimension products, and relative tensor offsets use checked unsigned 64-bit
arithmetic. GGUF v3 is supported explicitly; another version is rejected rather
than interpreted using a guessed layout.

All GGUF v3 scalar metadata types, UTF-8 strings, and non-nested arrays of those
scalar/string types are parsed. Metadata entry SHA-256 values cover the exact
encoded key, type, and value bytes in the file. Large numeric arrays are hashed and
validated in request-sized chunks. String arrays are decoded incrementally for
UTF-8 validity. Inventories retain only scalar summaries and deterministic bounded
previews, never complete tokenizer vocabularies, merges, scores, or token-type
arrays.

Every per-file tensor descriptor records its name, dimensions in GGUF on-disk
order, GGML type code and name, relative data offset, logical element count,
exclusive encoded span, and encoded SHA-256. This is syntax and boundary evidence
only. Phase 4F-2 does not interpret Kimi K3 tensor semantics or read the data at
those offsets.

`general.alignment` is accepted only as a bounded non-zero power-of-two `UINT32`;
otherwise the GGUF default of 32 is used. The descriptor end is aligned with checked
arithmetic to obtain both the exclusive header end and payload start. The inventory
records whether this boundary is before or exactly at repository EOF. A boundary
past EOF fails. Successful evidence requires both the highest requested and highest
accepted inclusive offsets to be strictly less than the payload start.

The inventory and report have strict
`omiv.remote-gguf-header-inventory.v1` and
`omiv.remote-gguf-header-report.v1` schemas. Report verification reconstructs all
ten HEADER findings from the embedded typed inventory, validates the inventory and
policy linkage, and recomputes report integrity. Digests are deterministic tamper
detection, not signatures.

> A successful Phase 4F-2 result proves that one pinned GGUF file’s complete
> metadata and tensor descriptor region was parsed using bounded remote byte
> ranges without accepting tensor payload bytes. It does not prove cross-shard
> consistency, model architecture correctness, semantic mapping correctness,
> payload integrity, quantization fidelity, or runtime parity.

Phase 4F-3 may aggregate independent shard inventories and define explicit
cross-shard consistency rules. Phase 4F-2 does not aggregate the 15 files, validate
split metadata across files, or describe them as a semantically valid model.

## Deterministic split GGUF aggregation

Phase 4F-3 consumes the immutable snapshot and one integrity-verified Phase 4F-2
header inventory per selected file. It requires exactly one complete filename
candidate, processes its files in filename ordinal order, and rejects inventories
whose snapshot digest, repository, resolved revision, path, size, or parser-policy
identity does not match. Missing inventories may be generated with the same bounded
Range parser; `--regenerate` explicitly replaces reuse with parsing.

```bash
omiv remote-split-gguf \
  --snapshot snapshots/huggingface/unsloth_Kimi-K3-GGUF_UD-IQ1_M.snapshot.json \
  --inventory-dir inventories/remote/unsloth_Kimi-K3-GGUF_UD-IQ1_M/shards \
  --output inventories/remote/unsloth_Kimi-K3-GGUF_UD-IQ1_M.split.inventory.json \
  --report-output reports/remote/unsloth_Kimi-K3-GGUF_UD-IQ1_M.split.report.json \
  --markdown-output reports/remote/unsloth_Kimi-K3-GGUF_UD-IQ1_M.split.report.md
```

The split keys are the llama.cpp GGUF keys `split.no`, `split.count`, and
`split.tensors.count`. `split.no` is zero-based; the human-facing five-digit filename
ordinal is one-based. OMIV records both and compares `split.no + 1` to the filename
ordinal instead of conflating the conventions.

The recorded metadata policy treats split keys as derived identity and permits the
broad metadata set—including tokenizer arrays, chat templates, general identity,
quantization/imatrix fields, and URL-shaped repository fields—to occur only in the
structurally broadest shard. Replicated values are compared by their encoded-byte
digests; complete tokenizer arrays are never restored into aggregate reports.
Effective alignment is compared across every shard. These conservative structural
classes are policy evidence, not an assertion that metadata values are semantically
correct.

Tensor descriptors are globally ordered by name, filename shard ordinal, and
descriptor index. Exact duplicate names and conflicting shapes, types, offsets, or
descriptor identities are retained as separate bounded evidence and are never
silently deduplicated. The type-size policy is pinned to llama.cpp GGML type traits
and uses block element counts and encoded block sizes—not nominal bits per
element—to calculate row-major tensor spans. Unsupported layouts remain WARN
evidence. Computable spans are checked against repository file size and against
other spans in the same shard without requesting a payload byte.

Aggregate defaults bound the run to 256 shards, 1 GiB of accepted remote header
bytes, 65,536 Range requests, 2,000,000 metadata records, 5,000,000 tensor
descriptors, and a 1 GiB serialized inventory. Duplicate details, metadata summaries,
and representative tensors are independently capped. The effective aggregation,
metadata, GGML type-size, and per-shard parser policies are embedded and hashed.

> A successful Phase 4F-3 result proves that a pinned collection of GGUF files
> forms a structurally consistent split container under the recorded filename,
> header metadata, inventory, tensor identity, and payload-span policies. It does
> not prove that the tensors implement Kimi K3 correctly, that HF-to-GGUF mapping
> is correct, that tensor payload bytes are intact, that quantization is faithful,
> or that runtime outputs are equivalent.

## Kimi K3 target-side GGUF ontology

Phase 4F-4 adds a versioned `gguf_ontology` capability to the static trusted
`kimi-k3` model pack. It consumes the verified Phase 4F-3 split inventory without
network access, classifies physical target descriptors, and validates them against a
policy grounded in the pinned target census, the existing Kimi K3 checkpoint
ontology, and the Kimi K3 loader and tensor-name tables from pinned llama.cpp commit
`cf67f0d24511864d2d3da0769108fd6fc16d00d1`.

```bash
omiv kimi-k3-gguf-ontology \
  --input inventories/remote/unsloth_Kimi-K3-GGUF_UD-IQ1_M.split.inventory.json \
  --model-pack kimi-k3 \
  --output inventories/remote/unsloth_Kimi-K3-GGUF_UD-IQ1_M.kimi-k3-ontology.inventory.json \
  --report-output reports/remote/unsloth_Kimi-K3-GGUF_UD-IQ1_M.kimi-k3-ontology.report.json \
  --markdown-output reports/remote/unsloth_Kimi-K3-GGUF_UD-IQ1_M.kimi-k3-ontology.report.md
```

The command verifies the split inventory first. Phase 4F-3 intentionally retained
metadata consistency summaries rather than model-specific scalar values, so the
ontology command also verifies the integrity-linked broadest-metadata header
inventory. Its default location is derived from the canonical split artifact name;
`--metadata-inventory` provides an explicit equivalent. Repository, snapshot, shard
path, declared file size, header parser policy, and inventory digest must all agree
before those bounded metadata summaries are trusted.

The mandatory census uses the exact `blk.<layer>.<component>[.<parameter>]` grammar,
not a first-number search. It records top-level and suffix vocabularies, layer and
shard counts, shape signatures, GGML type distributions, packed/shared/residual and
gate names, and descriptor-order versus payload-offset observations. Every descriptor
then has exactly one accounting outcome: classified, intentionally unclassified, or
invalid. Duplicate classification is separately prohibited. Unknown auxiliary names
remain visible rather than being forced into a nearby family.

The target policy validates all 93 layers and the exact observed KDA/MLA schedule:
69 KDA layers and the 24 MLA layers `3, 7, …, 91, 92`. Layer 0 has the three dense
MLP tensors; layers 1 through 92 have router, latent-MoE, three packed routed-expert,
and three shared-expert families. Packed expert dimensions structurally encode 896
experts. This proves only the physical packed shape and coverage—it neither expands
896 synthetic records per layer nor asserts source expert order.

GGUF names differ from checkpoint names in several important ways. KDA uses the
`ssm_*` vocabulary while MLA uses `attn_q_a`, `attn_kv_a_mqa`, and decomposed
`attn_k_b`/`attn_v_b` tensors. Logical `g_proj` coverage is the union of `ssm_g` on
KDA layers and `attn_gate` on MLA layers. Attention Residual is the target's fused
`attn_res_score`, `ffn_res_score`, and `output_res_score` representation; the
recorded block-size metadata is checked separately. These are target-side structural
relations, not source-to-target transform claims.

Shape rules are family-specific. Inventories retain physical GGUF loader-order
dimensions and a documented normalized logical order; vectors remain unchanged,
while explicitly declared matrix, convolution, and MLA families use the recorded
reversal relation; packed-expert families retain their target semantic axis order.
Family-level GGML type policy permits F32 controls
and norms, Q8_0 projections, and the observed IQ1_S/IQ2_XXS/IQ3_XXS placements for
packed expert matrices. Type placement says nothing about numerical quantization
quality.

The strict schemas are
`omiv.kimi-k3-gguf-ontology-inventory.v1` and
`omiv.kimi-k3-gguf-ontology-report.v1`. They embed the model-pack and ontology
policies and their deterministic digests, reconstruct all `KIMIGGUF-001` through
`KIMIGGUF-015` findings, and retain split, snapshot, repository, and metadata-header
linkages without local paths or raw metadata. Standalone verification and full source
linkage are available with:

```bash
omiv kimi-k3-gguf-ontology-inventory-verify \
  --input inventories/remote/unsloth_Kimi-K3-GGUF_UD-IQ1_M.kimi-k3-ontology.inventory.json \
  --source inventories/remote/unsloth_Kimi-K3-GGUF_UD-IQ1_M.split.inventory.json

omiv report-verify \
  --input reports/remote/unsloth_Kimi-K3-GGUF_UD-IQ1_M.kimi-k3-ontology.report.json
```

> A successful Phase 4F-4 result proves that the verified target GGUF tensor
> descriptors satisfy the recorded Kimi K3 target-side architecture ontology,
> including layer schedules, required tensor families, packed expert structure,
> shape relations, and GGML type placement. It does not prove that source
> checkpoint tensors were mapped into those target tensors correctly, that packed
> expert ordering is correct, that tensor payload values are intact, that
> quantization is numerically faithful, or that runtime outputs are equivalent.

Phase 4F-5 defines the source-to-target mapping; Phase 4F-4 remains target-only.
Phase 4F-4 does not reconstruct the 497,220 source identities, inspect payloads, or
make conversion, quantization-fidelity, tokenizer, logit, or runtime-parity claims.

### Phase 4F-5 grouped semantic mapping

Phase 4F-5 adds a generic, deterministic grouped mapping engine for one-to-one,
many-to-one packed, one-to-many split, fused-target, logical-realization, and
source-only auxiliary relations. The Kimi K3 adapter groups the verified
checkpoint's routed-expert `w1/w2/w3` identities by `(layer, component)` and checks
the converter-supported 896-member descriptor relation against one target
`ffn_*_exps` descriptor. Explicit non-overlapping rules also cover shared experts,
routers, latent MoE projections, dense layer 0, per-layer norms, attention output,
model-level tensors, KDA, MLA, Attention Residual fusion, and g_proj logical
realizations.

The inventory reconstructs every source and target claim. The 450 historical
source records are reclassified as 282 mapped text tensors and 168 intentionally
excluded vision/mm-projector auxiliary tensors. It records exact physical-member,
group, fused-member, logical-source, direct-target, packed-target, fused-target,
and logical-target denominators, with duplicate and ambiguity detection. Shape,
axis, and machine-readable dtype-to-GGML-type policies are descriptor checks only.

Mapping is descriptor-level only: payload packing correctness, quantization
fidelity, artifact-specific conversion provenance, and runtime parity are not
checked. The pinned llama.cpp revision `cf67f0d24511864d2d3da0769108fd6fc16d00d1`
is retained as converter-rule evidence and is not evidence that the Unsloth
artifact was produced by that converter. Artifact-specific provenance therefore
remains `unavailable`, and payload verification remains `not_checked`.

```bash
omiv kimi-k3-semantic-mapping \
  --source-inventory reports/raw/kimi_k3_tensors.json \
  --target-split-inventory inventories/remote/unsloth_Kimi-K3-GGUF_UD-IQ1_M.split.inventory.json \
  --target-ontology-inventory inventories/remote/unsloth_Kimi-K3-GGUF_UD-IQ1_M.kimi-k3-ontology.inventory.json \
  --output inventories/remote/unsloth_Kimi-K3-GGUF_UD-IQ1_M.semantic-mapping.inventory.json \
  --report-output reports/remote/unsloth_Kimi-K3-GGUF_UD-IQ1_M.semantic-mapping.report.json \
  --markdown-output reports/remote/unsloth_Kimi-K3-GGUF_UD-IQ1_M.semantic-mapping.report.md
```

> A successful Phase 4F-5 result proves that verified source checkpoint tensor
> identities can be deterministically grouped and associated with verified target
> GGUF descriptors under the recorded mapping, packing, shape, axis, type-transition,
> and realization policies. It does not prove that source payloads were packed in
> the correct numerical order, that target payload bytes match source values, that
> quantization is numerically faithful, or that runtime outputs are equivalent.

### Phase 4F-6 independent validation bundles

Phase 4F-6 composes the canonical Phase 4F-1 through 4F-5 artifacts into an
independent, offline-verifiable validation bundle. It does not rerun remote
inspection or reimplement the underlying validators. Instead, a typed dependency
graph records each artifact schema and digest, every parent linkage, the applicable
model-pack and policy identities, its evidence scope, and its limitations. The graph
and its repository-relative artifact index have separate deterministic digests.

Evidence is reported as stages rather than a misleading global correctness Boolean.
Repository identity and layout, bounded Range behavior, GGUF prefix and complete
headers, split consistency, payload-span bounds, target ontology, and structural
semantic mapping can pass while converter-rule support is merely available,
artifact-specific provenance is unavailable, and payload integrity, numerical
quantization fidelity, tokenizer parity, and runtime parity remain not checked.

Static trusted acceptance profiles translate those stages into product decisions:
`community_structural`, `vendor_release_structural`,
`enterprise_offline_structural`, and `regulated_deployment_full`. A structural
profile can be satisfied with explicit limitations; the regulated full profile
cannot pass when provenance, payload, quantization, tokenizer, or runtime evidence
is absent. The JSON report carries both a neutral executive summary and detailed
engineering evidence, while its Markdown rendering includes a commercial
control-by-control acceptance table.

```bash
omiv independent-validation \
  --subject kimi-k3 \
  --variant UD-IQ1_M \
  --snapshot snapshots/huggingface/unsloth_Kimi-K3-GGUF_UD-IQ1_M.snapshot.json \
  --split-inventory inventories/remote/unsloth_Kimi-K3-GGUF_UD-IQ1_M.split.inventory.json \
  --ontology-inventory inventories/remote/unsloth_Kimi-K3-GGUF_UD-IQ1_M.kimi-k3-ontology.inventory.json \
  --mapping-inventory inventories/remote/unsloth_Kimi-K3-GGUF_UD-IQ1_M.semantic-mapping.inventory.json \
  --profile community_structural \
  --output validations/unsloth_Kimi-K3-GGUF_UD-IQ1_M.validation.inventory.json \
  --report-output reports/validation/unsloth_Kimi-K3-GGUF_UD-IQ1_M.validation.report.json \
  --markdown-output reports/validation/unsloth_Kimi-K3-GGUF_UD-IQ1_M.validation.report.md

omiv independent-validation-inventory-verify \
  --input validations/unsloth_Kimi-K3-GGUF_UD-IQ1_M.validation.inventory.json

omiv report-verify \
  --input reports/validation/unsloth_Kimi-K3-GGUF_UD-IQ1_M.validation.report.json
```

The inventory schema is `omiv.independent-model-validation.v1`; the report schema
is `omiv.independent-model-validation-report.v1`; and the static profile-policy
schema is `omiv.validation-acceptance-profile-policy.v1`. Verification reconstructs
the evidence graph, stages, profile decisions, findings, summaries, artifact index,
and all canonical digests from the checked-in dependencies. No network or model
payload is required.

> A successful Phase 4F-6 structural validation bundle proves that all required
> repository, bounded remote-inspection, GGUF header, split-container, target
> ontology, and descriptor-level semantic-mapping evidence is present,
> integrity-linked, and valid under the selected structural acceptance profile.
>
> It does not prove tensor payload integrity, numerical quantization fidelity,
> tokenizer parity, runtime equivalence, or artifact-specific conversion provenance
> when those stages are unavailable or not checked.

### Phase 4F-7 cross-quantization structural comparison

Phase 4F-7 adds a generic directional comparison engine for two independently
verified artifact variants. Baseline and candidate are neutral roles: neither is
treated as numerically superior. The strict schemas
`omiv.model-artifact-structural-comparison.v1`,
`omiv.model-artifact-structural-comparison-report.v1`,
`omiv.structural-comparison-policy.v1`, and
`omiv.structural-comparison-profile-policy.v1` cover repository/revision identity,
metadata categories, normalized target identities and shapes, family-aware GGML
type transitions, exact encoded-size ratios, ontology structure, semantic-mapping
structure, validation evidence, findings, and deterministic verification.

The static profiles are `structural_equivalence`,
`quantization_layout_comparison`, `release_variant_consistency`, and
`full_numerical_equivalence`. The full profile cannot pass without payload,
quantization, tokenizer, runtime, and provenance evidence. Allowed GGML type or
shard-layout differences describe structural policy only; they are not quality
rankings.

```bash
omiv structural-compare \
  --baseline-validation validations/unsloth_Kimi-K3-GGUF_UD-IQ1_M.validation.inventory.json \
  --candidate-validation validations/unsloth_Kimi-K3-GGUF_UD-Q4_K_XL.validation.inventory.json \
  --baseline-split inventories/remote/unsloth_Kimi-K3-GGUF_UD-IQ1_M.split.inventory.json \
  --candidate-split inventories/remote/unsloth_Kimi-K3-GGUF_UD-Q4_K_XL.split.inventory.json \
  --baseline-ontology inventories/remote/unsloth_Kimi-K3-GGUF_UD-IQ1_M.kimi-k3-ontology.inventory.json \
  --candidate-ontology inventories/remote/unsloth_Kimi-K3-GGUF_UD-Q4_K_XL.kimi-k3-ontology.inventory.json \
  --baseline-mapping inventories/remote/unsloth_Kimi-K3-GGUF_UD-IQ1_M.semantic-mapping.inventory.json \
  --candidate-mapping inventories/remote/unsloth_Kimi-K3-GGUF_UD-Q4_K_XL.semantic-mapping.inventory.json \
  --profile structural_equivalence \
  --output comparisons/unsloth_Kimi-K3-GGUF_UD-IQ1_M_vs_UD-Q4_K_XL.comparison.inventory.json \
  --report-output reports/comparison/unsloth_Kimi-K3-GGUF_UD-IQ1_M_vs_UD-Q4_K_XL.comparison.report.json \
  --markdown-output reports/comparison/unsloth_Kimi-K3-GGUF_UD-IQ1_M_vs_UD-Q4_K_XL.comparison.report.md
```

The command verifies and reconstructs every supplied validation, split, ontology,
and mapping dependency before comparing it. Invalid or incomplete upstream
evidence fails closed with exit 2; an unsatisfied comparison profile returns exit
1; satisfied structural profiles (including their explicitly permitted warnings)
return exit 0. `structural-comparison-inventory-verify` and `report-verify`
reconstruct the canonical results offline.

The pinned real UD-Q4_K_XL inspection at revision
`3d4b61ab4b6789d401191c476cbb4567246db8f5` contains 32 shards and 2,573
descriptors. Its 276 packed expert targets use `MXFP4`. Narrow structural support
is based on the pinned llama.cpp revision
`cf67f0d24511864d2d3da0769108fd6fc16d00d1`: GGML type code 39 uses
`QK_MXFP4=32` elements and a 17-byte block consisting of one E8M0 scale byte and
16 packed-data bytes. The checked row-size rule requires the first logical
dimension to be divisible by 32. This evidence permits deterministic encoded-span
calculation without reading payload bytes.

MXFP4 remains restricted to the Kimi packed routed-expert gate, up, and down
families in the ontology, mapping, and comparison policies. The completed Q4
chain verifies 2,573 bounded non-overlapping spans, classifies all 2,573 target
descriptors, accounts for all source and target mapping identities, and produces
an independent validation bundle before comparison. These checks establish only
descriptor layout and policy-supported structural transitions; MXFP4 payload
integrity, expert/scale ordering, numerical quantization fidelity, and runtime
behavior remain not checked.

> A successful Phase 4F-7 structural comparison proves that the two verified
> artifact variants preserve the same model-level target identities, normalized
> tensor structures, architecture ontology, and semantic-mapping relationships
> under the recorded comparison policies, while explicitly reporting physical
> layout and GGML type differences.
>
> It does not prove tensor payload equality, numerical quantization fidelity,
> tokenizer equivalence, runtime equivalence, or comparative model quality.

External publication, release tagging, and website generation remain out of scope.

### Phase 4F evidence-linked publication case study

The Kimi K3 case study packages the verified Phase 4F-1 through 4F-7 evidence
without adding new validation conclusions. It covers UD-IQ1_M and UD-Q4_K_XL at
immutable revision `3d4b61ab4b6789d401191c476cbb4567246db8f5`: bounded
header inspection with zero accepted tensor payload bytes, split aggregation,
complete Kimi target ontology and semantic-mapping accounting, independent
validation, and cross-quantization structural comparison.

- [Technical article](articles/validating-kimi-k3-gguf-with-omiv.md)
- [Evidence manifest](articles/evidence/kimi-k3-gguf-validation.evidence-manifest.json)
- [Public claim registry](articles/evidence/kimi-k3-gguf-validation.claim-registry.json)
- [Reproducibility manifest](articles/evidence/kimi-k3-gguf-validation.reproducibility.json)

```bash
omiv article-evidence-verify --root .
omiv article-claims-verify --root .
omiv article-preflight --root . \
  --article articles/validating-kimi-k3-gguf-with-omiv.md
```

The case study establishes descriptor-level structural evidence under recorded
policies. It does not establish payload equality or integrity, numerical
quantization fidelity, tokenizer parity, runtime equivalence, model quality, or
artifact-specific conversion provenance.

## Artifact acquisition and transformation attestations

An artifact attestation is a structured claim about an acquisition, transfer,
transformation, or quantization action. Phase 5C provides generic strict schemas,
deterministic identities, evidence-link reconstruction, execution-record linkage,
provenance-strength reconstruction, reports, and a custody-event adapter. The core
attestation, custody, and Passport packages do not depend on Kimi or GGUF logic;
local files, Safetensors-like artifacts, registries, OCI objects, S3 identities,
and air-gapped packages use the same artifact-reference model.

A valid attestation proves that the canonical record has not been altered and
that its internal references satisfy the selected policy. It does not, by itself,
prove the issuer's identity or provide cryptographic non-repudiation. A verified
execution record can establish artifact-specific input, tool, configuration, and
output linkage without proving numerical correctness, security, or runtime
behavior.

Acquisition and inspection are different. Remote inspection is not acquisition:
a source locator, immutable revision, or bounded header read does not establish
that an artifact was downloaded or transferred. A transfer preserves artifact
identity between custody contexts, while a transformation explicitly relates
different input and output identities. Quantization is a specialized
transformation with an explicit target-type policy; its execution record does not
establish numerical fidelity.

A generic transfer does not automatically become an acquisition custody event.
Transfer materialization is fail-closed unless policy-reconstructable evidence
establishes entry into a new custody boundary, verifies the destination artifact
identity and source/destination continuity, and satisfies every acquisition-event
requirement. Same-boundary replication, cache relocation, registry mirroring,
storage-tier migration, backup, and packaging remain valid transfer descriptions
but are not acquisition-materializable.

Attestation integrity, authenticity, and provenance are reported separately:

- `USER_DECLARED` records a declaration and remains `DECLARED` and unsigned.
- `SYSTEM_OBSERVED` requires explicit observation evidence but does not identify
  an actor.
- `DERIVED_FROM_VERIFIED_EVIDENCE` may be `EVIDENCE_LINKED` when all relevant
  evidence reconstructs.
- `VERIFIED_EXECUTION_RECORD` may be `EXECUTION_VERIFIED` when exact tool,
  configuration, environment-status, input, output, and execution evidence
  reconstruct.
- Signed authenticity and signed provenance are reserved for Phase 5D.

`EXECUTION_VERIFIED` always remains visibly unsigned: execution-record integrity
is verified, while cryptographic signature is not available, issuer and actor
authenticity are unverified, and payload correctness, numerical fidelity,
security, runtime compatibility, and approval remain not checked.

Structural equivalence is not artifact-specific transformation provenance.
Converter source availability, a pinned revision, or compatible output structure
cannot replace an execution record linking a specific input to a specific output.

```bash
omiv attestation create \
  --input attestations/examples/synthetic_transformation.attestation-input.json \
  --output attestations/examples/synthetic_transformation.attestation.json \
  --report-output reports/attestations/synthetic_transformation.attestation.report.json \
  --markdown-output reports/attestations/synthetic_transformation.attestation.report.md

omiv attestation verify \
  --input attestations/examples/synthetic_transformation.attestation.json

omiv attestation show \
  --input attestations/examples/synthetic_transformation.attestation.json

omiv attestation report-verify \
  --input reports/attestations/synthetic_transformation.attestation.report.json \
  --attestation attestations/examples/synthetic_transformation.attestation.json

omiv attestation append-custody \
  --attestation attestations/examples/example.attestation.json \
  --ledger custody/example.custody-ledger.json \
  --output custody/example.with-attestation.custody-ledger.json
```

The custody adapter verifies both inputs, maps acquisition, transformation, and
quantization claims to the existing typed custody taxonomy, derives the next
sequence and parent digest, and writes a new ledger atomically. It never mutates
the source ledger. Declared attestations remain unattested custody events;
execution-verified events remain unsigned.

A portable custody segment is a self-contained attestation-backed ledger
fragment. Its genesis is the beginning of the portable segment, not necessarily
the beginning of the artifact's real-world lifecycle. Segment envelopes are not
concatenated: an attestation is re-materialized as a newly sequenced event under
the verified destination ledger and its exact parent digest. A one-event intact
segment remains lifecycle-incomplete.

The Kimi K3 gap report deliberately records absence rather than creating a
lifecycle claim. Its source locator, immutable revision, remote inspection, and
structural evidence are available, while acquisition, transformation,
quantization, execution, issuer, signature, and artifact-specific provenance
attestations remain unavailable. Existing Kimi Passport v1/v2 and custody-ledger
artifacts remain unchanged.

Phase 5C is not signed supply-chain attestation. Phase 5D may add cryptographic
signatures and trust roots; approval workflows, deployment admission, runtime
agents, security scanning, payload fidelity, revocation services, and hosted
registries remain outside Phase 5C.

## Phase 5D: signed attestations and trust roots

Phase 5D signs canonical OMIV source objects through separate
`omiv.signed-object-envelope.v1` wrappers. It supports artifact attestations,
tool-execution records, custody events, portable custody-ledger v2 segments, and
Model Passport v1/v2 objects. The source object's ID, digest, and bytes are not
changed.

Only Ed25519 is active. OMIV uses `cryptography`'s Ed25519 implementation with
32-byte raw public keys and 64-byte detached signatures encoded as lowercase
hex. ECDSA, RSA-PSS, and Sigstore identifiers are reserved and fail closed.
OMIV never implements or selects a fallback cryptographic primitive.

The exact signed bytes are:

```text
ASCII("OMIV-SIGNED-OBJECT-V1")
+ 0x00
+ canonical_json(omiv.signature-payload.v1)
```

The payload descriptor binds the canonicalization version, source schema,
typed object kind, object ID, SHA-256 digest of the complete canonical object,
signature purpose, optional policy identity, namespace, provider/artifact scope,
and key usage. Consequently a signature cannot be reused across an attestation
and Passport, an execution record and custody event, a custody event and custody
segment, or a different purpose, namespace, schema, ID, or canonicalization
version. Pretty-printed source bytes and local line endings are never signed.

The dependency order avoids digest cycles:

```text
canonical source object
→ signature payload descriptor
→ domain-separated canonical bytes
→ detached Ed25519 signature
→ signature record
→ signed-object envelope
→ reconstructed trust report
```

Key identity and signer identity are separate. `omiv.key-identity.v1` derives a
`key_<32 hex>` ID from the schema, algorithm, encoding, and raw public-key bytes;
it never contains a private key. `omiv.signer-identity.v1` contains an explicit
declared or evidence-linked identity, while `omiv.signer-key-binding.v1` records
the policy-visible relationship between that identity and key. A signature may
be cryptographically valid while signer identity remains unavailable or
unverified. OMIV never infers identity from a username, Git author, email,
hostname, repository owner, or filesystem metadata.

`omiv.trust-bundle.v1` is a deterministic static offline collection of public
keys, signer identities, bindings, roots, bounded signed delegations, and static
revocations. A trusted key is trusted only for the object types, purposes,
namespaces, provider/artifact scopes, usages, delegation depth, validity window,
and other constraints accepted by the selected `omiv.trust-policy.v1` policy.
There is no universal built-in root. The available policy model supports the
profiles `personal_local_trust`, `project_maintainer_release`, `team_release`,
`enterprise_offline_release`, and `regulated_multi_party_release`; a profile has
no approval semantics.

Revocation is static and offline. Local declarative revocation is authoritative
only when the selected policy explicitly accepts it. Expiration is evaluated
only against an explicit `omiv.evaluation-context.v1`; verification never calls
the system clock. Historical evaluation therefore means validity under the
caller-supplied historical context, not a trusted signing time or timestamp
authority.

Root-signed revocation is reserved and rejected in Phase 5D because no signed
revocation issuer format is implemented. Record integrity alone is never
revocation authority. Reports identify each applicable record, its local-policy
authority, scope, effective status, reason, and replacement relation. Validity
windows use strict fixed-width UTC values; `not_before` and `not_after` are
inclusive, and offsets or ambiguous local times are rejected rather than
normalized.

Signed-object envelopes can carry deterministically ordered signatures from
distinct key/purpose pairs. Verification evaluates every signature independently
and policies can require up to eight accepted signatures. Duplicate signatures
and duplicate key/purpose pairs fail schema validation; one invalid signature
makes the overall envelope invalid. This N-of-M signature threshold is trust
evaluation only and has no approval semantics. The `trust sign` command creates
one signature per new envelope; multi-signature envelope assembly is available
through the typed builder API rather than an append-signature CLI workflow.

A valid signature proves that the holder of the corresponding private key
signed a specific canonical OMIV object. It does not by itself prove the
underlying real-world claim is true. Signature validity is not key trust; a known
key is not necessarily trusted; a valid signer/key binding does not prove claim
content; a signed execution record does not establish a trusted environment; a
trusted Passport signature does not mean a model is safe or approved.

Signing an attestation does not upgrade its evidence, authenticity, provenance,
payload, numerical fidelity, tokenizer parity, security, runtime, approval,
deployment, or lifecycle-completeness state. A signed declared acquisition
remains `DECLARED` with `DECLARED_PROVENANCE`. An execution-verified
transformation retains its reconstructed Phase 5C authenticity and provenance,
while payload, fidelity, security, and runtime remain `NOT_CHECKED`. A signed
custody event remains one event, and `PORTABLE_SEGMENT_BEGINNING` does not become
real-world lifecycle genesis.

Trust reports render approval as `NOT_AVAILABLE`: Phase 5D contains no approval
decision mechanism. A policy-accepted signature is always shown next to its
signature integrity, key, signer identity and binding, underlying claim state,
unchecked payload/fidelity/security/runtime dimensions, and lifecycle status.

All commands operate offline:

```bash
omiv trust key-inspect --public-key maintainer-public.pem

omiv trust sign \
  --input attestations/examples/synthetic_transformation.attestation.json \
  --object-type ARTIFACT_ATTESTATION \
  --purpose ATTESTATION_ISSUANCE \
  --private-key runtime-only-private-key.pem \
  --public-key maintainer-public.pem \
  --output signed-envelope.json

omiv trust verify \
  --input signed-envelope.json \
  --trust-bundle trust/examples/project-trust-bundle.json \
  --policy trust/examples/project-trust-policy.json \
  --evaluation-context trust/examples/evaluation-context.json

omiv trust show --input signed-envelope.json
omiv trust bundle-verify --input trust/examples/project-trust-bundle.json
omiv trust delegation-verify \
  --input trust/examples/delegation-record.json \
  --trust-bundle trust/examples/delegated-trust-bundle.json
omiv trust revocation-verify --input trust/examples/project-key.revocation-record.json
```

`trust verify` exits 0 when the selected policy is satisfied, 1 for a valid
object and signature with incomplete or unsatisfied trust, and 2 for malformed
input, invalid signatures, authoritative revocation, required-current-validity
failure, invalid delegation, unsupported algorithms or purposes, and operational
errors. Signing accepts only a bounded unencrypted PKCS8 PEM private key at
runtime. Private material is never placed in keys, envelopes, bundles, reports,
or console output.

The synthetic examples under `trust/examples/` and `reports/trust/` use public
cryptographic test-vector material and fictional identities. They include
trusted, declared, unknown-key, delegated, revoked, expired, execution-record,
custody-event, and custody-segment cases. They make no publisher claim about
Kimi K3; the existing Kimi gap remains signature unavailable and lifecycle
incomplete.

Phase 5D uses static offline trust bundles. KMS, HSM, TPM, smart cards, X.509,
OIDC, Sigstore, Fulcio, Rekor, transparency logs, timestamp authorities, online
key discovery, online revocation, approval, promotion, deployment admission,
runtime agents, security scanning, payload verification, and fidelity/parity are
not implemented. A future policy-decision, approval, and promotion-gate phase
can consume these layered reports without changing Phase 5D signature meaning.

## Phase 5E: policy decisions, approval, and promotion gates

Phase 5E adds a generic deterministic governance layer under `omiv governance`.
It links artifact identity, Passport and custody references, attestations, and
Phase 5D trust reports to explicit evidence requirements, reconstructed policy
decisions, scoped approval records, separation-of-duties checks, approval quorum,
release candidates, and logical promotion gates. It remains offline and does not
contact a registry, notification service, identity provider, or deployment system.

The dependency order is acyclic:

```text
canonical evidence references
→ policy evaluation input
→ requirement results
→ policy decision record
→ approval request
→ approval or rejection records
→ quorum and separation-of-duties results
→ release candidate and logical promotion target
→ promotion decision
→ governance report and separate Passport/custody adapters
```

Phase 5D signed-object envelopes remain external wrappers around canonical Phase
5E objects. A signature report or governance report is never part of the bytes it
describes.

### Governance semantics

A policy decision proves that the supplied evidence was evaluated against a
specific policy. It does not independently prove the underlying claims.

An approval record is an explicit governance action under a defined scope. A
generic trusted signature is not automatically an approval. A signed approval
counts only when its object type and purpose are approval-specific and its request,
subject, scope, role, binding, trust, revocation, and expiration state satisfy the
selected policy.

Promotion allowed means that policy permits movement into a logical target. It
does not prove that the artifact was uploaded, deployed, or observed at runtime.
Phase 5E never performs registry upload or deployment.

Separation of duties is evaluated only from available identity, key, role, trust
root, and policy evidence. It does not prove organizational independence beyond
that evidence. Multiple signatures on one envelope are not multiple business
approvals; each `ApprovalRecord` is evaluated independently.
An approver role label counts toward quorum only when a supplied role assignment
matches the actor, policy, requested action, and subject scope.

Missing mandatory security evidence remains blocking until Phase 5F produces
verifiable security evidence. Phase 5E models security, payload, fidelity,
deployment, and runtime requirements so policies can fail closed, but it does not
produce or verify those forms of evidence. A caller-declared future schema,
generic signature, approval, or text such as “security passed” cannot satisfy a
mandatory security requirement in Phase 5E.

### Governance schemas

- `omiv.governance-policy.v1`
- `omiv.evidence-requirement.v1`
- `omiv.evidence-requirement-set.v1`
- `omiv.policy-evaluation-input.v1`
- `omiv.policy-evaluation.v1`
- `omiv.policy-decision-record.v1`
- `omiv.approval-request-input.v1`
- `omiv.approval-request.v1`
- `omiv.approval-input.v1`
- `omiv.approval-record.v1`
- `omiv.rejection-record.v1`
- `omiv.approval-policy.v1`
- `omiv.separation-of-duties-policy.v1`
- `omiv.release-candidate.v1`
- `omiv.promotion-target.v1`
- `omiv.promotion-gate-policy.v1`
- `omiv.promotion-decision-record.v1`
- `omiv.governance-report.v1`
- `omiv.passport-governance-summary.v1`
- `omiv.custody-governance-linkage.v1`
- `omiv.governance-artifact-index.v1`

Records reject unknown fields. Portable governance values reject local absolute
paths, credentials, signed URLs, UUID identities, and implicit timestamps. IDs and
digests derive from OMIV canonical JSON; freshness uses only a caller-supplied
fixed-width UTC evaluation context.

### Policy profiles and precedence

- `personal_local_use`: identity and structural evidence with security explicitly
  not checked; expected `ALLOW_WITH_LIMITATIONS`.
- `team_artifact_intake`: immutable identity, acquisition, structure, custody, and
  trusted signed evidence plus scoped approval; expected
  `ALLOW_WITH_LIMITATIONS` for the synthetic example.
- `team_release_candidate`: signed provenance, quorum, duties, and mandatory
  security evidence; missing Phase 5F evidence yields `DENY`.
- `enterprise_registry_promotion`: strict evidence, approval, duties, revocation,
  expiration, and security requirements; missing security evidence yields `DENY`.
- `regulated_production_release`: payload, security, runtime, and multi-party
  requirements remain deliberately unsatisfied in Phase 5E.

Decision precedence is:

```text
POLICY_INVALID
→ EVIDENCE_BROKEN
→ DENY
→ NOT_EVALUATED
→ REVIEW_REQUIRED
→ ALLOW_WITH_LIMITATIONS
→ ALLOW
```

`NOT_APPLICABLE` requires an explicit fully verified policy-evidence reference.
Absence is `MISSING`, `UNAVAILABLE`, `NOT_CHECKED`, or `NOT_EVALUATED`; it is never
silently converted to not applicable.

### Offline governance CLI

```bash
omiv governance evaluate \
  --input governance/examples/personal.policy-evaluation-input.json \
  --policy governance/examples/personal.governance-policy.json \
  --output /tmp/decision.json \
  --report-output /tmp/governance-report.json \
  --markdown-output /tmp/governance-report.md

omiv governance decision-verify \
  --decision /tmp/decision.json \
  --input governance/examples/personal.policy-evaluation-input.json \
  --policy governance/examples/personal.governance-policy.json

omiv governance approval-request-create \
  --input governance/examples/team-intake.approval-request-input.json \
  --decision governance/examples/intake.policy-decision.json \
  --policy governance/examples/intake.governance-policy.json \
  --output /tmp/approval-request.json

omiv governance approval-create \
  --request /tmp/approval-request.json \
  --input governance/examples/team-intake.approval-input.json \
  --output /tmp/approval-record.json

omiv governance promotion-evaluate \
  --candidate governance/examples/enterprise.release-candidate.json \
  --target governance/examples/enterprise.promotion-target.json \
  --policy governance/examples/enterprise.promotion-gate-policy.json \
  --decision governance/examples/enterprise.policy-decision.json \
  --output /tmp/promotion-decision.json
```

Additional commands are `decision-show`, `approval-verify`, `approval-show`,
`promotion-verify`, and `report-verify`. Use `omiv trust sign` with the additive
Phase 5E object types and issuance purposes when a decision or approval needs a
detached Ed25519 wrapper.

Exit codes are:

- `0`: `ALLOW`, unconditional `PROMOTION_ALLOWED`, or successful structural
  verification;
- `1`: `ALLOW_WITH_LIMITATIONS`, `REVIEW_REQUIRED`, conditional promotion,
  partial/incomplete non-blocking results, or a valid approval whose required
  signature trust was not evaluated;
- `2`: denial, malformed or broken evidence, invalid/revoked/expired required
  signatures, failed duty separation, insufficient mandatory quorum, prohibited
  escalation, or operational failure.

Generated examples live in `governance/examples/`, reports in
`reports/governance/`, and their public deterministic inventory in
`governance/artifact-index.json`. They use synthetic identities only. No Kimi
approval, Kimi promotion, security pass, deployment authorization, or runtime
authorization is generated.

## Phase 5F: artifact security evidence

Phase 5F adds the generic, deterministic, offline-first `omiv security` evidence
layer. It binds an exact artifact identity to a bounded inspection plan, explicit
scanner capabilities, an execution record, normalized findings, exact coverage,
a policy evaluation, and a scope-limited verdict. It is an evidence and policy
foundation, not an antivirus product or security certification.

The dependency order is:

```text
artifact reference
→ security inspection plan
→ scanner identity and bounded execution
→ normalized findings and coverage
→ security evidence bundle
→ security policy evaluation
→ deterministic report
→ separate governance, Passport, custody, and signed-envelope linkages
```

The core package is `src/omiv/security/` and imports no model pack. Generic local
files and artifact sets use the existing custody `ArtifactReference`, whose
origins include local, S3, OCI, internal registry, and air-gapped references.
Safetensors-like, GGUF-like, ONNX-like, and archive-like artifacts are treated as
formats, never as executable model implementations.

### Safe inspection boundary

The built-in scanner is named **OMIV bounded static inspector**. Its identity,
configuration, methods, finding categories, and limitations are canonical. It
performs bounded file enumeration, type and magic checks, static byte-pattern
checks, unsafe-serialization indicators, script/native-binary indicators, and
bounded ZIP central-directory or archive-entry-manifest name checks. The ZIP
parser operates only on bytes already admitted by the file and total-byte bounds.
Archive entries are never extracted and nested archives are not recursively
inspected.

Every plan bounds files, total and per-file bytes, archive entries, metadata,
findings, evidence snippets, and recursion depth. Symlinks, traversal, devices,
FIFOs, sockets, proc/sys traversal, unsupported dynamic analysis, and bound
overruns fail closed. OMIV does not execute untrusted artifact code during Phase
5F inspection. It performs no dynamic imports, deserialization, shell commands,
plugin loading, external scanner processes, environment expansion, or network
access.

`CONTROLLED_DYNAMIC_ANALYSIS_RESERVED` is typed but cannot appear in an
operational Phase 5F plan. Static inspection does not establish runtime safety,
behavioral correctness, payload integrity, numerical fidelity, or tokenizer
parity.

### Schemas, policies, and verdicts

The primary strict schemas are:

- `omiv.security-inspection-plan.v1`
- `omiv.scanner-identity.v1`
- `omiv.security-scan-execution-input.v1`
- `omiv.security-scan-execution-record.v1`
- `omiv.security-finding.v1`
- `omiv.security-coverage.v1`
- `omiv.security-evidence-bundle.v1`
- `omiv.security-evidence-policy.v1`
- `omiv.security-evaluation.v1`
- `omiv.security-report.v1`
- `omiv.passport-security-summary.v1`
- `omiv.custody-security-linkage.v1`
- `omiv.security-artifact-index.v1`

All records reject unknown fields. Canonical values reject absolute local paths,
credentials, private material, signed URLs, UUID identities, and caller-supplied
timestamps. Sensitive pattern matches retain only a category, digest, redacted
fingerprint, and bounded normalized indicator—not the matched secret.

Built-in policy profiles are `personal_local_security_review`,
`team_artifact_security_intake`, `team_release_security_gate`,
`enterprise_artifact_security_gate`, and
`regulated_artifact_security_gate`. The regulated profile remains reserved and
fails closed because Phase 5F does not provide runtime or continuous evidence.

Verdict precedence is:

```text
EVIDENCE_BROKEN
→ FAIL
→ SCANNER_UNTRUSTED
→ COVERAGE_INCOMPLETE
→ NOT_EVALUATED
→ REVIEW_REQUIRED
→ PASS_WITH_LIMITATIONS
→ PASS
```

A security PASS means that the supplied, verified evidence satisfies the
selected security policy for the declared inspection scope. It does not prove
that the artifact is universally safe.

No findings does not prove absence of vulnerabilities, especially when coverage
is partial or inspection methods are limited. Scan completion is not an artifact
safety claim. A signed security record proves that a key signed the record. It
does not prove that the scanner was correct, and it never upgrades findings,
coverage, payload integrity, or runtime state.

### Governance, Passport, and custody

Mandatory security requirements in governance may be satisfied only by verified
Phase 5F security evidence that matches subject, policy, coverage, and trust
requirements. The strict adapter emits the reserved Phase 5E
`omiv.artifact-security-evidence.v1` reference only from a reconstructed Phase 5F
evaluation. Arbitrary text, approval records, Passport signatures, custody
integrity, and generic signatures cannot substitute for that evaluation.
`PASS_WITH_LIMITATIONS` is accepted only when the selected canonical security
policy permits governance limitations; a CLI flag cannot upgrade it.

Passport v1/v2 and custody ledgers remain unchanged. Separate
`PassportSecuritySummary` and `CustodySecurityLinkage` records expose coverage,
findings, scanner trust, verdict, and limitations while keeping payload integrity,
approval, deployment, and runtime separate. Security custody events are evidence
linkages only; they do not emit approval, promotion, deployment, or runtime
events.

The Kimi K3 case study has no local payload acquisition or security scan. Phase
5F therefore generates only `reports/security/kimi-k3.security-gap-report.json`:
inspection unavailable, coverage not assessed, and the security requirement
unsatisfied. It generates no Kimi security PASS or malware-free claim.

### Offline security CLI

```bash
omiv security plan-create \
  --artifact ./artifact.safetensors \
  --output /tmp/inspection-plan.json

omiv security inspect \
  --plan /tmp/inspection-plan.json \
  --artifact ./artifact.safetensors \
  --output /tmp/scan-execution.json \
  --bundle-output /tmp/security-bundle.json \
  --report-output /tmp/security-report.json \
  --markdown-output /tmp/security-report.md

omiv security evidence-verify --bundle /tmp/security-bundle.json

omiv security evaluate \
  --bundle /tmp/security-bundle.json \
  --policy team_release_security_gate \
  --output /tmp/security-evaluation.json
```

Additional commands are `show`, `report-verify`, `governance-adapt`, and
`custody-link`. Exit `0` means the selected policy is satisfied with `PASS`; exit
`1` means limitations or review remain; exit `2` means failure, broken evidence,
mandatory incomplete coverage, an untrusted required scanner, unsafe input, or
an operational error.

Synthetic artifacts and canonical records live in `security/examples/`, static
policies in `security/policies/`, reports in `reports/security/`, and their
deterministic inventory in `security/artifact-index.json`. Regenerate all of them
offline with `python -m omiv.security.examples`.

## Phase 5G: deployment and runtime snapshot verification

Phase 5G adds a generic, deterministic `omiv runtime` evidence layer. It models
product subjects, multi-member deployment artifact sets, deployment intents and
instances, intended manifests, deployment records, observer identities, scoped
assertion authority, replay-bound runtime observations, exact observation
coverage, identity drift, and policy-scoped continuity. Core records are not tied
to model weights, Hugging Face, one artifact format, Kubernetes, Docker, a cloud,
or an inference engine.

A deployment record states that deployment was declared, imported, observed,
signed, or corroborated. These origins are not equivalent. A trusted signer is
not automatically authorized to make every deployment or runtime assertion, and
a signed declaration remains a declaration. Observer authority is evaluated for
tenant, project, product, environment, target, artifact class, action, trust
domain, and explicit sequence interval. Enterprise policies can also require
deployer/observer separation, distinct signing identity, distinct trust root, and
independent corroboration.

Evidence origins are not a universal strength ladder. Structural verification,
direct observation, signature presence, signature trust, authority,
corroboration, coverage, and freshness are evaluated independently. Adapter
capability ceilings use explicit accepted-origin sets, not enum ordering.

Artifact-set continuity evaluates the primary artifact and required companion
artifacts independently. Container-image or registry-reference continuity does
not prove loaded model-byte continuity. Engine display-version equality does not
prove engine-binary equality. Matching normalized configuration identity means
only identity under the selected normalization policy; it does not prove complete
semantic equivalence. Canonical configuration records contain allowlisted public
fields and logical secret-reference digests, never secret values or raw process
environments.
Secret-reference digests identify logical reference metadata and provider class;
they are not hashes or fingerprints of secret values.

Runtime observations bind to a deterministic deployment instance, manifest,
target, artifact-set digest, policy, explicit evaluation context, observation
sequence namespace, epoch, sequence, and predecessor. A valid observation for an
older instance cannot be reused for a later deployment. Coverage distinguishes observed, unsupported,
inaccessible, errored, stale, proxy-only, and independently corroborated
dimensions; missing mandatory dimensions cannot produce full PASS.

Built-in policies are `local_runtime_continuity`, `team_service_continuity`,
`enterprise_deployment_continuity`, `air_gapped_runtime_continuity`, and
`regulated_runtime_continuity`. The regulated policy remains fail closed.
Air-gapped continuity is limited when online revocation or continuing offline
trust-bundle freshness cannot be established; unavailable online checks do not
silently become PASS. Trusted timestamp status remains `NOT_AVAILABLE`.
Precedence is broken evidence, replay, mismatch, drift, unauthorized observer,
untrusted observer, unverified deployment, incomplete coverage, stale or absent
observation, proxy/partial continuity, limited PASS, then PASS.

A Phase 5G PASS means only that supplied, verified, policy-authorized deployment
and runtime evidence establishes continuity for explicitly observed dimensions,
subject set, scope, trust domain, deployment instance, and evaluation context.
Phase 5G verifies a point-in-time snapshot. It does not establish continuous
continuity, numerical parity, tokenizer parity, behavioral correctness, model
safety, or runtime security.

Platform-specific products and integrations normalize evidence into the OMIV
canonical model; they do not change core evidence semantics. Only the bounded
local JSON adapter is operational. OCI, Kubernetes, runtime-specific, cloud, and
internal-platform adapter identities are reserved and fail closed. Phase 5G does
not deploy artifacts, contact runtimes or registries, invoke platform SDKs,
execute models, infer workstation identity, or perform continuous monitoring.

The offline CLI provides `intent-create`, `manifest-create`,
`deployment-record-create`, `deployment-verify`, `observation-plan-create`,
`observation-create`, `observation-verify`, `continuity-evaluate`, `show`,
`report-verify`, `governance-adapt`, and `custody-link` under `omiv runtime`.
Exit `0` means full policy satisfaction, exit `1` means limited, partial, proxy,
or reviewable evidence, and exit `2` means mismatch, blocking drift, replay,
broken evidence, authority/trust failure, mandatory coverage failure, or unsafe
input. Fixtures live in `runtime/examples/`, policies in `runtime/policies/`,
reports in `reports/runtime/`, and the duplicate-checked inventory in
`runtime/artifact-index.json`.

## Phase 5H: historical trust and audit bundles

Phase 5H adds deterministic offline historical reconstruction under `omiv
audit`. A finite `EvidenceSetManifest` identifies the exact canonical evidence
used by an immutable `TrustSnapshot`; later revocation, expiry, withdrawal,
supersession, renewal, or policy changes produce new snapshots and transitions
instead of rewriting history. Snapshot dimensions preserve source limitations,
including Phase 5F security limits and Phase 5G snapshot-only runtime limits.

Historical events retain origin, signature, trust, assertion authority,
corroboration, scope, explicit context, epoch, sequence, and predecessor as
separate facts. Timelines detect missing predecessors, sequence conflicts, and
forks without resolving them automatically. Revocation propagation limits
dependent conclusions without deleting records. Supersession selects preferred
future evidence but does not prove that an older record was false. Observation
renewal applies only to explicitly renewed dimensions.

Directory-form audit bundles declare purpose, scope, historical range, member
IDs/digests/sizes, completeness policy, and every exclusion. Model payloads and
private keys are excluded. Offline verification rejects traversal, symlinks,
special or undeclared files, missing members, duplicate canonical IDs, schema or
hash mismatches, and altered reports. Audit-bundle completeness applies only to
the declared purpose, and a bundle signature does not independently prove every
claim inside it.

A TrustSnapshot is a reconstruction for supplied evidence, exact policies, and
an explicit evaluation context. “Latest supplied snapshot” does not mean current
real-world state. Phase 5H provides offline reevaluation capability, not a
daemon, scheduler, webhook, background poller, online revocation service, trusted
timestamp authority, or continuous monitoring system. Continuous observation
remains `NOT_ESTABLISHED`.

Historical reconstruction uses `KNOWN_AS_OF_CUTOFF`: evidence first available after the
cutoff cannot affect the earlier result, even when it asserts an earlier effective time.
Availability exactly at the cutoff is included. Event time is not a trusted timestamp,
and historically effective does not mean known to the evaluator. Retrospective
`EFFECTIVE_AS_OF_CUTOFF` reconstruction is not implemented and fails closed.

Bundle paths use NFC, slash-separated relative names and reject case/Unicode collisions,
Windows reserved names, trailing spaces/dots, traversal, controls, and file/directory
prefix conflicts. Timeline completeness and purpose-specific bundle completeness remain
separate. Graph, timeline, bundle, renewal, report, and index inputs have documented
deterministic limits; limit failures are explicit and never silently truncated.

Fixtures and the representative bundle live in `continuous-trust/`, reports in
`reports/continuous-trust/`, and the deterministic inventory in
`continuous-trust/artifact-index.json`. Detailed architecture and limitations
are documented in `docs/phase-5h-continuous-trust-audit-bundles.md`.

## Phase 6A: local payload integrity

Phase 6 begins the Artifact Assurance and Model Fidelity product layer. Phase
6A provides offline, bounded local byte observation for a declared single file
or directory and comparison with an embedded or materialized referenced
expectation. Declaration, observation, execution, factual comparison, policy,
detached signature, and Phase 5 integration remain separate canonical layers.
Referenced declarations, independently supplied expectation objects, and
materialization results retain separate identities, availability, and authority.

`omiv payload manifest`, `compare`, `verify`, and `verify-manifest` operate only
on explicit local inputs. Single-file observation requires a stable logical
member name. Directory traversal includes hidden files, rejects symlinks,
special files and hardlink aliases, uses bounded SHA-256 streaming, and records
detectable opened-file mutation, path rebinding, and root inventory changes.
It does not claim portable TOCTOU elimination.

Payload paths are relative NFC POSIX-style names. Unsafe, ambiguous,
case-colliding, normalization-colliding, reserved Windows, surrogate, control,
noncharacter, trailing-space, and trailing-dot names fail closed. Canonical
records omit local absolute paths and host identity. Time is caller supplied or
`NOT_RECORDED`; filesystem time is not evidence freshness.

An exact result is always `EXACT_MATCH_FOR_EXPECTATION_SCOPE`. A digest-only
reference is not materialized evidence, selected members are not a complete
artifact expectation, and signatures do not create publisher authority.
Payload digest match != model semantic correctness; local file-set completeness
!= remote repository completeness; file-set completeness != tokenizer parity;
payload integrity != quantization fidelity; payload integrity != behavioral
safety; payload integrity != runtime safety; expected manifest != observed
manifest; signed expected manifest != correct expected manifest; trusted signer
!= authorized publisher; hashing completed != every intended byte was hashed;
opened descriptor stability != stable path binding; local payload identity !=
observed runtime identity; successful local verification != continuously
verified artifact.

Generated records live in `payload-integrity/`, reports in
`reports/payload-integrity/`, and the external, self-excluding index in
`payload-integrity/artifact-index.json`. See
`docs/phase-6a-payload-integrity-manifests.md` for schemas, limits, and scope.

## Phase 6B: shard completeness and remote/local reconciliation

Phase 6B adds provider-neutral remote artifact declarations, bounded collection execution records,
typed remote members and digest semantics, explicit shard topology, qualified completeness, and
comparison with the exact Phase 6A `ObservedPayloadManifest`. Requested and resolved revisions,
provider observation, policy, publisher authority, detached signatures, and derived integrations
remain separate layers.

The core does not depend on Kimi/Moonshot, DeepSeek, or xAI profiles. Offline deterministic fixtures
exercise exact payload-comparable, metadata-only, mismatch, and incomplete cases without network or
model execution. Practice profiles preserve prior Kimi limitations and the explicit DeepSeek gap.
Reviewed revision-specific Grok-1/Grok-2 public-provider metadata fixtures generate xAI practice
evidence offline while preserving zero payload observation, unavailable topology, unestablished
publisher authority/freshness/authenticity, and no xAI endorsement claim. See
`docs/phase-6b-shard-reconciliation.md` for schemas, preservation methodology, CLI commands, limits,
metadata boundaries, and the Phase 6C deferral.

## Phase 6C: quantization representation and numerical fidelity

Phase 6C provides an offline, bounded, provider-neutral foundation for declaring source/candidate
representation relationships, binding exact Phase 6A/6B identities, observing tensor metadata,
reconstructing only explicitly supported values, measuring deterministic numerical error, and
evaluating scope-qualified policies. Structural consistency, numerical fidelity, coverage,
authority, signatures, integrations, reports, and the external self-excluding artifact index remain
separate canonical layers.

V1 numerical calculation supports unquantized identity and normalized uniform affine integers with
explicit finite positive scale, integral representable zero point, bit width, signedness, and
unambiguous one-to-one mapping. Native GGUF codecs, NF4, GPTQ, AWQ, FP8, packed layouts, opaque
provider formats, and implicit split/fused/transposed mappings fail closed. A deterministic sample
never becomes complete-model evidence, and metadata or a trusted signature never creates numerical
fidelity or publisher/transformation authority.

The xAI practice profile consumes the unchanged Phase 6B pinned Grok metadata entirely offline and
records readiness without payload values or a quantized candidate; it makes no quantization,
publisher-authority, authenticity, freshness, security, behavioral, runtime, affiliation, or
endorsement claim. Generated records live in `quantization-fidelity/`, reports in
`reports/quantization-fidelity/`, and the external index in
`quantization-fidelity/artifact-index.json`. See
`docs/phase-6c-quantization-fidelity.md` for schemas, limits, CLI commands, integrations, and exact
limitations.

Offline bounded quantization-representation and numerical reconstruction fidelity
foundation—complete for the declared exact-identity scope, with explicit format, coverage,
sampling, authority, filesystem-race, and behavioral limitations.

## Phase 6D: tokenizer and configuration parity

Phase 6D adds an offline, bounded, provider-neutral foundation for exact tokenizer-asset and
configuration comparison. It preserves raw bytes, canonical JSON, selected typed fields,
vocabulary token-to-ID and ID-to-token mappings, merge order, added-token properties,
special-token roles, ordered pipeline descriptors, unexecuted chat-template text, and explicitly
supplied probe results as separate evidence dimensions. Expectations, observations, comparisons,
policy, authority, integrations, signatures, reports, and the external self-excluding index remain
separate canonical layers.

OMIV does not import model code, execute a tokenizer, render a chat template, infer runtime or
framework defaults, or upgrade remote repository metadata into payload content. Finite probe
success remains probe-scoped. Tokenizer/configuration parity does not establish weight fidelity,
behavioral or semantic equivalence, safety, authenticity, runtime compatibility, publisher
authority, or production readiness.

The xAI practice profile consumes only the unchanged Phase 6B pinned Grok repository-tree evidence
and records readiness without required payload assets. Generated records live in
`tokenizer-configuration-parity/`, reports in `reports/tokenizer-configuration-parity/`, and the
external index in `tokenizer-configuration-parity/artifact-index.json`. See
`docs/phase-6d-tokenizer-configuration-parity.md` for schemas, limits, CLI commands, integration
boundaries, and exact limitations.

Offline bounded tokenizer-asset, configuration-field, and supplied-probe parity
foundation—complete for the declared exact-identity scope, with explicit format, coverage,
authority, execution, and runtime limitations.
