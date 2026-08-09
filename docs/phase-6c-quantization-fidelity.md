# Phase 6C: provider-neutral quantization representation and numerical fidelity

## Objective and classification

Phase 6C is an offline, deterministic, bounded evidence foundation for relating a source artifact to
a candidate representation, observing their tensor representations, reconstructing values only
under implemented semantics, measuring numerical error, and evaluating an explicit policy.

Core classification:

`COMPLETE_AS_PROVIDER_NEUTRAL_QUANTIZATION_REPRESENTATION_AND_NUMERICAL_FIDELITY_EVIDENCE_FOUNDATION_WITH_EXPLICIT_COVERAGE_FORMAT_AND_BEHAVIORAL_LIMITATIONS`

Product wording:

> Offline bounded quantization-representation and numerical reconstruction fidelity
> foundation—complete for the declared exact-identity scope, with explicit format, coverage,
> sampling, authority, filesystem-race, and behavioral limitations.

Numerical reconstruction similarity is not behavioral, semantic, or output parity. Quantization
fidelity is not model correctness, safety, authenticity, publisher authorization, loadability,
tokenizer/configuration compatibility, production readiness, or runtime identity. Metadata-only and
sampled findings remain explicitly limited to their observation scope.

## Architecture and dependency direction

The canonical graph is intentionally acyclic:

```text
relationship declaration
  -> observation plan
  -> execution record
  -> source/candidate representation observations
  -> tensor correspondence and parameter observations
  -> numerical measurements
  -> structural/numerical comparison
  -> policy and authority evaluations
  -> fidelity evidence
  -> derived integrations and reports
  -> signed wrappers and trust reports
  -> external self-excluding artifact index
```

Every downstream reference binds the finalized upstream ID and digest. An execution record binds its
plan and supplied inputs but never its future observations or results. Observations bind the
execution. Reports do not feed evidence identities. A signature envelope remains outside the
unsigned identity, and signature bytes cannot change it. Source fixtures do not depend on generated
objects. The index excludes itself. Executable graph validation rejects self, direct, and indirect
cycles under explicit node and edge limits.

The provider-neutral implementation is under `src/omiv/quantization/`. Practice orchestration and
xAI-specific interpretation are outward-only under `src/omiv/quantization_profiles/`; the generic
core imports no xAI, Grok, Kimi, DeepSeek, or provider-profile module.

## Versioned schemas

Phase 6C registers strict v1 schemas for:

- `QuantizationRelationshipDeclaration`
- `QuantizationObservationPlan`
- `QuantizationExecutionRecord`
- `RepresentationObservation`
- `TensorRepresentationRecord`
- `TensorCorrespondence`
- `QuantizationParameterObservation`
- `DeterministicSampleDefinition`
- `NumericalFidelityMeasurement`
- `QuantizationFidelityComparison`
- `QuantizationFidelityPolicy`
- `QuantizationPolicyEvaluation`
- `QuantizationAuthorityEvaluation`
- `QuantizationFidelityEvidence`
- `QuantizationIntegrationSummary`
- `QuantizationFidelityReport`
- `QuantizationExampleCatalog`
- `QuantizationArtifactIndex`

All canonical objects are frozen, forbid unknown fields, use explicit schema versions, deterministic
collection ordering, canonical IDs/digests, explicit subjects and scopes, bounded collections, and
strict enums. Canonical JSON rejects duplicate keys, non-finite numbers, invalid UTF-8, unsupported
schemas, excessive nesting/object/string/numeric-string size, and non-canonical decimal strings.
Time is caller supplied or `NOT_RECORDED`; no host clock is consulted.

## Artifact and tensor identity

Source and candidate identities are role-bearing and distinct. They preserve subject, provider and
namespace declarations, requested/resolved revisions, artifact-set identity, Phase 6A local manifest
references, Phase 6B remote snapshot references, coverage, digest semantics, and availability.
Availability distinguishes exact local payload identity, comparable remote payload identity,
non-payload remote identity, metadata identity, digest-only reference, absent artifact, unavailable
identity, and invalid identity. A digest-looking string, equal name, equal revision, equal size, or
official-looking namespace cannot establish canonical equality.

Phase 6A `ObservedPayloadManifest` remains authoritative for local bytes. Exact bindings include its
ID/digest, subject, logical root, artifact set, member identity, size, digest, and coverage. Phase 6C
does not invent a competing byte identity. Payload readers must fail closed on path rebound, opened
file mutation, or root inventory change; the synthetic examples read only small reviewed fixtures.

Phase 6B identities remain provenance context. LFS OIDs, Xet object IDs, provider or Git object IDs,
ETags, and opaque identifiers are never upgraded into payload digests without Phase 6B-compatible
payload semantics. Phase 6B listing completeness or topology cannot establish Phase 6C numerical
completeness.

Tensor identity binds artifact identity, NFC logical name, explicitly declared role, shape/rank and
element count, storage/logical dtypes, member or byte range when observed, actual content digest,
representation descriptor, coverage, and provenance. Portable names reject absolute/traversal paths,
backslashes, controls, NUL, surrogates, noncharacters, Windows-reserved components, trailing space or
dot, and configured Unicode/case-fold collisions. Role is never guessed.

## Representation taxonomy and observation

The high-level scheme families are unquantized, uniform affine integer, symmetric integer,
asymmetric integer, codebook, blockwise float, mixed precision, opaque provider format, and unknown.
Descriptors can preserve storage/logical dtype, bit width, signedness, byte/packing order, scale and
zero-point representations, axis, group/block size, codebook identity, rounding, clipping,
exceptional-value handling, format/version, provenance, and observation level.

Observation levels are metadata only, full tensor values, deterministic sample, externally supplied
measurement, opaque format, and not observed. Parameter provenance distinguishes payload,
format-metadata, signed/unsigned imported record, caller declaration, non-authoritative inference,
and unavailable. Missing facts remain absent; filename, extension, type-shaped label, provider
metadata, tensor shape, or framework convention never supplies codec semantics.

## V1 numerical support

V1 computes only:

1. `UNQUANTIZED_IDENTITY`, comparing explicitly supplied normalized values.
2. `UNIFORM_AFFINE_INTEGER`, using `reconstructed = scale * (quantized_value - zero_point)`.

Affine reconstruction requires canonical finite decimal scale greater than zero, an integral zero
point representable by the explicit signedness and bit width, known shape/element count, normalized
integer values, internally consistent declared layout, and an unambiguous one-to-one correspondence.
Range, scale, zero point, axis/group/block, and size violations are explicit. Packed integer decoding
is not implemented in V1, so nibble order, padding, and packed byte layouts fail closed instead of
being guessed.

Native GGUF quantization codecs, NF4, GPTQ, AWQ, FP8, Xet encoding, codebooks, provider codecs, and
fused/split/transposed reconstruction are `FORMAT_NOT_NUMERICALLY_SUPPORTED` unless a future
version implements and tests their exact rules. A type name never silently falls back to affine.

## Correspondence

Correspondence records support one-to-one, explicitly declared one-to-many, many-to-one,
many-to-many, unmapped source/candidate, ambiguous, and unsupported cardinalities. V1 numerical
evaluation requires one-to-one mapping unless a future version supplies an explicit reconstruction
recipe. Other structural mappings remain
`MAPPING_STRUCTURALLY_AVAILABLE_NUMERICALLY_UNAVAILABLE`; ambiguity is not resolved heuristically.
Structural and numerical findings remain separate and simultaneous findings are preserved.

## Deterministic sampling

Sampling uses versioned SHA-256 rejection selection over a domain-separated seed, source and
candidate tensor identities, population size, and a monotonically increasing derivation counter.
Selection is deterministic, unique, sorted, and independent of Python `hash()`, randomness, time,
process state, or unordered iteration.
Definitions bind requested/actual counts, selected indices, inclusion/exclusion rules, and limits.
Zero, empty, over-population, single-element, identity/seed/population changes, boundaries, and limit
failures are explicit. Population metadata is capped at 1,000,000,000 elements; sample count and
full-population traversal at 100,000; hashing at 12,800,000 attempts; and stored candidates at
100,000. A successful sample is never complete tensor or complete model coverage and is not claimed
statistically representative.

## Metrics and canonical numeric semantics

Inputs are bounded decimal strings. Accumulation uses a fresh local `Decimal` context, precision 50,
and `ROUND_HALF_EVEN`; output removes negative zero and uses fixed notation without exponent or
trailing zeros. Inputs are limited to 768 characters, 100 significant digits, adjusted exponent
±308 (scale ±128), intermediate/output adjusted exponent ±640, and 768 rendered characters. These
bounds reject compact exponent bombs before fixed-point rendering and isolate results from mutable
global Decimal flags, traps, precision, rounding, or locale. Binary non-finite inputs are rejected
and JSON never contains NaN or infinity.

Per-tensor metrics preserve compared count, non-finite counts, exact count, maximum absolute error,
MAE, MSE, RMSE, source/error L2 norms, relative L2, dot product, cosine similarity, signed mean
error/bias, and an optional observed quantization-bound count. Being equal to a representable
minimum or maximum does not establish clipping; clipping remains separately
`CLIPPING_NOT_EVALUATED` unless direct transformation evidence establishes otherwise. Metric state
distinguishes available, exact, undefined
zero reference norm, undefined zero vector, non-finite input, not computed, insufficient coverage,
unsupported format, limit exceeded, and invalid. No epsilon is added to zero denominators. Aggregate
records preserve per-tensor failures, failed identities, worst metric, weighted/unweighted semantics,
evaluated elements, and incomplete coverage so an average cannot hide a mandatory failure.

## Coverage and result taxonomy

Coverage independently records source/candidate artifact, source/candidate/mapped tensor,
mandatory-role, numerical tensor, numerical element, byte, parameter, and sampling dimensions.
Numerators, denominators or unavailable denominators, state, and incomplete reason are retained.
Expectation scopes distinguish complete artifact/tensor sets, selected tensors/roles, partial
references, and deterministic samples. Exactness is always qualified by its declared scope.

Structural status, numerical status, and overall evidence status are independent. Examples include
structurally consistent, structural mismatch, incomplete information, ambiguous mapping, incomplete
parameters, and unsupported format; exact/within/outside policy for evaluated scope, sampled
within/outside, insufficient coverage, unsupported format, unavailable payload, and not evaluated;
and conforms/does not conform for declared scope, indeterminate, not evaluated, or invalid. OMIV does
not emit unqualified `MATCH`, `EQUIVALENT`, `VERIFIED`, `SAFE`, or `APPROVED` conclusions.

## Policy and authority

Policies explicitly select allowed schemes/dtypes, required artifact identity and roles, minimum
tensor/element/byte/parameter coverage, sampling permission/gap, global/per-role/per-tensor metric
thresholds, non-finite and unsupported/missing behavior, authority requirements, and evaluation
context. Every requirement is retained as satisfied, failed, not evaluated, not applicable, or
invalid; evaluation does not stop on the first failure. Metadata cannot produce numerical PASS.

Authority evaluates source/candidate publisher, transformer, expectation publisher, measurement
signature, signer trust, signer purpose authorization, policy authority, subject/scope, tenant,
project, and trust-domain context independently. A valid signature proves signed bytes; a trusted CI
key does not create publisher or transformation authority, and authorization for one subject or
purpose does not transfer. Representative declarations, observations, and evidence use the existing
Phase 5D signing architecture. Other canonical layers are deliberately unsigned.

## Phase integrations

- Passport receives a derived summary only; prior Passport schemas/artifacts are untouched.
- Custody receives an append-only input reference to the exact evidence ID/digest.
- Phase 5C attestation references preserve declared transformation versus observed representation;
  they do not prove fidelity.
- Governance receives evidence state, never automatic promotion/deployment approval.
- Security is linked only under exact subject/identity scope and never becomes a fidelity/security
  pass through this integration.
- Runtime receives an expected candidate identity, not observed runtime identity.
- Historical audit receives explicit available/observed/evaluated context or `NOT_RECORDED`, never
  an implicit clock value.
- Phase 6A supplies authoritative local payload identity.
- Phase 6B supplies exact remote provenance only under its digest limitations.

No established Phase 5, Phase 6A, or Phase 6B schema or generated artifact is rewritten.

## Safety and limits

Phase 6C is offline and non-executing: it imports no model code, unpickles no payload, executes no
model/tokenizer/plugin/compiler, follows no symlink silently, and accepts no special file. Dimensions
and collections are validated before allocation. Payload access is bounded and streaming; aggregate
model bytes are never buffered. Canonical output contains logical relative paths, never host/local
absolute paths.

`QuantizationLimits` bounds artifact members, tensors, rank/dimensions/elements, correspondence and
fan-in/out, parameters, sampled/full elements, payload bytes per file and total, stream chunks, JSON
bytes/nesting/strings, findings, report nodes, dependency nodes/edges/depth, generated artifacts, and
metadata bytes. Exceeding a bound is `LIMIT_EXCEEDED`; evidence is never silently truncated. Reports
record total/included/omitted findings and their deterministic selection rule separately from the
complete canonical comparison. Scalability tests cover 10,000 synthetic tensor metadata records,
large deterministic streams, bounded sampling, and bounded reporting as engineering smoke checks,
not performance guarantees.

## Offline CLI and generation

The offline CLI provides `omiv quantization inspect`, `sample`, `verify`, `report`, `verify-index`,
and `practice-xai`. Strict inputs, schemas, and limits are enforced. Canonical JSON is deterministic;
local diagnostics go to stderr. Exit 0 means satisfactory for the explicitly declared scope, exit 1
means mismatch/incomplete/not evaluated, and exit 2 means invalid/unsafe/limit exceeded. There is no
live collection command.

`tools/generate_quantization_fidelity_examples.py` generates deterministic synthetic evidence and
practice reports. It uses no network, host time, randomness, or real model payload. Independent
generations must match in paths, bytes, hashes, schemas, canonical IDs, signatures, reports, and the
self-excluding external index. `tools/audit_phase6c_preservation.py` reconstructs the exhaustive
baseline inventory at `f475096322b8d5336675530a41a9548b08a4dc9b`, including prior index members and
the verified ignored Kimi raw artifact, without modifying it.

## xAI readiness case study

The outward-only profile consumes the unchanged Phase 6B pinned Grok-1 revision
`5de83eb225f49624b424f1c8aa74f96983b5885c` and Grok-2 revision
`daf4395a80ad177386cfe39641b64fc12b1d70ed`. It records:

`XAI_QUANTIZATION_FIDELITY_READINESS_RECORDED_WITHOUT_PAYLOAD_OR_QUANTIZED_CANDIDATE`

Pinned public metadata and Phase 6B evidence are available, but Phase 6B established zero
payload-comparable members. No source tensor values, quantized candidate, relationship, codec,
tensor parameters, or numerical measurements exist. Fidelity, security, and behavioral parity are
`NOT_EVALUATED`; publisher authority, authenticity, and freshness are `NOT_ESTABLISHED`; runtime is
`NOT_OBSERVED`; time is `NOT_RECORDED`. The profile claims no xAI affiliation, endorsement,
approval, or current repository state and does not infer whether Grok is quantized.

A future evaluation would require a locally supplied exact source/candidate pair bound to Phase 6A,
an explicit relationship and codec/parameters, unambiguous tensor correspondence, a scoped policy,
and either full values or an explicitly limited deterministic sample. The pinned Phase 6B snapshot
would remain provenance context, not payload evidence.

## Extension points and remaining limitations

Future versions may add exact versioned packed layouts and native codecs, explicit split/fused/
transposed recipes, more streaming payload adapters, stronger filesystem primitives, statistical
sampling policies, and runtime/behavioral evaluation in separate phases. V1 does not eliminate all
filesystem races, interpret arbitrary formats, prove tensor-semantic completeness, establish model
loadability or correctness, or generalize measured values beyond the exact declared scope.
