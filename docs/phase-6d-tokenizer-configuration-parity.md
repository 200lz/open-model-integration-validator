# Phase 6D: tokenizer and configuration parity evidence

## Objective and classification

Phase 6D is a provider-neutral, offline, deterministic and bounded foundation for observing and
comparing supplied tokenizer and configuration assets. Its classification is:

`COMPLETE_AS_PROVIDER_NEUTRAL_TOKENIZER_AND_CONFIGURATION_PARITY_EVIDENCE_FOUNDATION_WITH_EXPLICIT_FORMAT_PROBE_AND_RUNTIME_LIMITATIONS`

Product wording:

> Offline bounded tokenizer-asset, configuration-field, and supplied-probe parity
> foundation—complete for the declared exact-identity scope, with explicit format, coverage,
> authority, execution, and runtime limitations.

The foundation does not establish behavioral, generation, semantic or weight equivalence;
runtime-loaded identity; authenticity; safety; security; deployment approval; or production
readiness. Finite supplied probes cannot establish complete tokenizer equivalence.

## Architecture and dependency direction

Canonical dependencies point only downstream:

```text
expectation + parity declaration
  -> inspection plan
  -> execution record
  -> configuration and asset observations
  -> vocabulary / merges / added tokens / special tokens / pipeline / template observations

probe-set definition + inspection plan
  -> probe execution record
  -> supplied probe-result observation

finalized observations + expectation + supplied probes
  -> comparison
  -> policy evaluation + authority evaluation
  -> parity evidence
  -> integration summaries and reports
  -> signed wrappers
  -> external self-excluding artifact index
```

Plans contain no execution or result identity. Execution records contain no resulting observation,
comparison, evidence, report, wrapper or index reference. Observations bind finalized execution
ID/digest pairs. Probe results bind finalized probe execution and probe-set references. Reports and
signatures remain outside unsigned canonical identities. The external index excludes itself.

## V1 schemas

Phase 6D registers strict dispatch for:

- `omiv.tokenizer-configuration-expectation.v1`
- `omiv.tokenizer-configuration-parity-declaration.v1`
- `omiv.tokenizer-configuration-inspection-plan.v1`
- `omiv.tokenizer-configuration-execution-record.v1`
- `omiv.configuration-observation.v1`
- `omiv.tokenizer-asset-observation.v1`
- `omiv.vocabulary-observation.v1`
- `omiv.merge-table-observation.v1`
- `omiv.added-token-observation.v1`
- `omiv.special-token-observation.v1`
- `omiv.tokenizer-pipeline-observation.v1`
- `omiv.chat-template-observation.v1`
- `omiv.tokenizer-probe-set-definition.v1`
- `omiv.tokenizer-probe-execution-record.v1`
- `omiv.tokenizer-probe-result-observation.v1`
- `omiv.tokenizer-configuration-comparison.v1`
- `omiv.tokenizer-configuration-policy.v1`
- `omiv.tokenizer-configuration-policy-evaluation.v1`
- `omiv.tokenizer-configuration-authority-evaluation.v1`
- `omiv.tokenizer-configuration-parity-evidence.v1`
- `omiv.tokenizer-configuration-integration-summary.v1`
- `omiv.tokenizer-configuration-report.v1`
- deterministic scenario catalog/result and external artifact-index schemas.

Every canonical object uses explicit schema, subject, scope, deterministic ordering, bounded typed
collections, canonical ID/digest, explicit time or `NOT_RECORDED`, and no embedded signature.

## Expectations and artifact identity

Expectations are either embedded or referenced. Availability remains one of full canonical
expectation, digest-only reference, unavailable, or invalid. Digest-only and missing expectations
cannot masquerade as supplied empty expectations, and an empty scope cannot pass vacuously. A
digest-only expectation retains its exact schema/ID/digest while separately recording that the
canonical object was not supplied and verified. Generated graph verification checks both the ID
and digest of every reference whose target is present in the external index.

Asset identities distinguish exact Phase 6A local payload identity, established comparable Phase 6B
payload identity, non-payload remote identity, metadata identity, digest-only reference, absent
artifact and invalid/unavailable identity. Equal name, provider, revision, size or digest-shaped
string is insufficient. LFS OIDs, Xet IDs, Git/provider object IDs, ETags and opaque remote IDs are
not payload digests without explicit Phase 6B semantics.

For local files, Phase 6A `ObservedPayloadManifest` remains the byte-identity authority. Phase 6D
binds its manifest ID/digest, artifact-set digest, logical root, member path, size and SHA-256. It
does not create a competing local artifact identity.

## Configuration observation and comparison

Strict bounded JSON observation supports explicitly planned assets such as model, generation,
tokenizer, special-token and added-token configuration files. Filenames never establish semantic
roles. Duplicate keys, invalid UTF-8, non-finite values, oversized values, deep structures and
excessive numeric digits/exponents are rejected.

Model-provided fields such as `auto_map`, `architectures`, `tokenizer_class` and `model_type` are
data only. No code is imported. No defaults are imported from Transformers, llama.cpp, vLLM,
TensorRT-LLM or another runtime.

Field presence distinguishes explicit value, explicit null, absent, explicitly policy-defaulted,
non-authoritative inference, unavailable and invalid. Typed boolean, integer, decimal, string,
lists, explicit null and bounded typed-object digest values remain distinct. Raw byte identity,
strict canonical JSON identity and normalized selected-field identity are independent.

Comparisons retain all field-path, presence, type, value, null, default provenance and
comparability findings. Alias, coercion, default and allowed transformation rules must be explicit,
versioned, scope-bound and identity-bearing. An allowed transformation difference retains the raw
mismatch.

## Token content, vocabulary and merges

Token contents are not filesystem paths. Unicode text preserves exact scalar values without NFC,
NFD, trimming, case-folding or whitespace normalization. Surrogates are rejected. Byte-sequence
tokens use canonical lowercase hex and are never reinterpreted as UTF-8. Therefore precomposed
`é`, decomposed `e` plus combining acute, and their byte encodings remain distinct.

Vocabulary observations preserve content encoding, token ID, source order, provenance and explicit
classification. IDs may be sparse and need not start at zero. Duplicate tokens, duplicate IDs and
bidirectional ambiguity are recorded; ambiguous mappings are not compared unsafely. Record count,
distinct-token count, distinct-ID count, maximum ID, maximum-ID-plus-one, base-vocabulary count and
added-token count remain separate. Cross-asset vocabulary-size rules must select an explicit
cardinality basis and remain not evaluated when that basis is unavailable.

Supported BPE text merge observations preserve header, operands, rank, order, duplicate and
malformed records. Merge records are never reordered before comparison. Unsupported merge formats
fail closed.

Added-token observations distinguish absent properties from explicit false and preserve content,
ID, `special`, `single_word`, `lstrip`, `rstrip`, `normalized`, source order and provenance.

## Special tokens and cross-asset consistency

Roles include BOS, EOS, PAD, UNK, MASK, SEP, CLS, additional special, model-defined and absent role.
Role, content, encoding, ID, added-token properties, provenance, source asset and declared behavior
remain independent. Missing ID, explicit-null ID and ID zero are distinct. Spelling never implies a
role.

Explicit versioned rules can check config vocabulary size, special-token maps, vocabulary IDs,
added tokens, generation fields, pipeline model vocabulary and template references. Results remain
consistent, inconsistent, missing-input, not-applicable or not-evaluated for the selected rule.

## Pipeline and chat templates

Pipeline observations preserve ordered normalizer, pre-tokenizer, model, post-processor, decoder,
cleanup and unknown component descriptors. Type identifier, position, parameter digest/count,
declared implementation, provenance, source asset, unknown fields and support state are recorded.
No implementation or plugin is imported. Equal type names establish no behavioral equivalence.

Chat templates are untrusted data. Phase 6D records exact content bytes/digest, language/name,
provenance and whitespace/newline identity. It never executes Jinja, renders templates, imports
filters, calls `apply_chat_template`, or infers runtime output. Exact text equality is only exact
observed text equality for the declared scope.

## Supplied probes and Unicode coverage

Probe definitions support encode, decode, template render, special-token insertion, round trip and
normalization boundary kinds. Inputs are harmless inline synthetic values, digest-only references,
or unavailable. Production prompts need not be stored. Digest-only input is not independently
reproducible.

Probe executions bind finalized plan and probe-set ID/digest pairs, supplied tool identity and
explicit or `NOT_RECORDED` context. They contain no resulting probe identity. OMIV compares supplied
results; it does not execute arbitrary tokenizers or templates. Outputs separately identify inline
synthetic, digest-only and unavailable states. Digest-only outputs retain digest, interpretation and
length without storing plaintext and cannot receive an exact reproducible-probe status. Token IDs,
masks, offsets, output lengths and inline output digests are validated together.

Deterministic synthetic probes cover empty/ASCII text, whitespace, tab, LF, CRLF, non-breaking
space, NFC/NFD, combining marks, CJK, Japanese, emoji, variation selectors, zero-width joiner,
right-to-left text, punctuation, special-looking text, escaped NUL, bounded long input, unknown
token and byte-sequence content. Reports escape C0/C1, bidi and zero-width presentation controls as
well as Markdown metacharacters without changing the underlying canonical token identity.

## Coverage and result taxonomy

Coverage independently records reference/candidate assets, configuration files/fields, vocabulary
tokens/IDs, merges, added tokens, special roles, pipeline components, templates, probe definitions,
executed probes, outputs, bytes and authority. Every dimension retains numerator, denominator,
denominator availability, selected scope and incomplete reason. Unknown is not zero; zero is not
complete; empty selected scope cannot pass.

Overall results are scope-qualified parity, mismatch, partial parity, indeterminate, not comparable,
not evaluated or invalid. `PARITY_ESTABLISHED_FOR_DECLARED_SCOPE` requires every selected policy
dimension to have sufficient non-empty evidence. Unqualified match, equivalence, compatibility,
safety or approval is never emitted.

## Policy and authority

Typed policy selects required identity strength, assets, fields, roles, pipeline components, probes,
coverage, duplicate behavior, merge order, template requirements, aliases/coercions,
transformation differences, unsupported/missing behavior and authority. All failed dimensions are
retained. Metadata-only evidence cannot become parity.

Authority independently evaluates expectation publisher, source/candidate publisher, transformer,
observation signer, probe executor, policy and subject/scope context. Signature validity, signer
trust, purpose authority, publisher authority, transformer authority, probe-executor authority and
expectation authority are distinct. A trusted internal key cannot self-authorize a publisher claim.

Only expectation, tokenizer-asset observation and final parity evidence are representative signable
objects. Existing Phase 5D algorithms, trust roots, bindings, delegation, revocation and policy are
reused; no parallel signature implementation exists.

## Phase 5 and Phase 6 integrations

Passport output is derived summary only. Custody linkage is append-only. Phase 5C attestations remain
claims, not parity proof. Governance receives evidence state without promotion. Security evidence
requires exact matching bytes and parity cannot create security PASS. Runtime integration can set an
expected identity but cannot create an observed runtime identity. Historical time fields remain
explicit or `NOT_RECORDED`.

Phase 6B remote listing evidence remains non-payload unless explicit comparable semantics exist.
Phase 6C weight fidelity and Phase 6D tokenizer/configuration parity are independent in both
directions. An allowed quantization-related config difference requires an explicit policy rule and
the mismatch remains visible.

## Filesystem safety and limits

Local observation rejects symlinks, hardlink aliases and special files, uses bounded reads, compares
pre/post file identity and size, and preserves path-rebound, opened-file-changed and root-changed
findings. Canonical paths are portable relative NFC paths; local absolute paths are diagnostic-only
and never serialized.

Typed limits cover asset files/bytes, JSON bytes/depth/members, strings/numbers, configuration
fields, vocabularies, token IDs/content, merges, added/special tokens, pipeline components,
templates, probes/results, findings, graph/report reconstruction and generated files/bytes.
Exceeded limits fail deterministically as `LIMIT_EXCEEDED`; canonical evidence is never silently
truncated. Human reports expose deterministic truncation counts/rules.

No path can trigger Python imports, pickle, `trust_remote_code`, tokenizer/template execution,
plugins, inference, compiler invocation, current time, Python `hash()` or host randomness.

## Deterministic generation and CLI

`tools/generate_tokenizer_configuration_examples.py` reads only committed synthetic fixtures and
prior pinned evidence. Independent runs produce identical paths, bytes, IDs, reports, signatures
and the external self-excluding index. `tools/audit_phase6d_preservation.py` reconstructs every
prior generated root and prior index member against the Phase 6C release baseline.

Offline CLI commands are available under `omiv tokenizer-config`: `inspect`, `verify`, `report`,
`verify-index` and `practice-xai`. They use strict parsing and semantic exit codes. No live
collection or tokenizer execution command exists.

## xAI readiness

The outward-only xAI profile classification is:

`XAI_TOKENIZER_AND_CONFIGURATION_PARITY_READINESS_RECORDED_WITHOUT_REQUIRED_PAYLOAD_ASSETS`

It verifies the unchanged pinned Grok-1 and Grok-2 Phase 6B fixture hashes and exact historical
revisions. It preserves zero payload-comparable members, no downloaded tokenizer/config content,
no vocabulary, merges, special-token mapping, pipeline, template, fields or probes, parity
`NOT_EVALUATED`, authority/authenticity/freshness `NOT_ESTABLISHED`, runtime `NOT_OBSERVED`, and
security/behavior `NOT_EVALUATED`. Observation time is `NOT_RECORDED`. Member names never imply
contents, and no xAI endorsement, affiliation, approval or current-state claim is made.

## Future extension points and explicit limitations

Future work may add explicitly specified safe formats, supplied adapters and richer versioned
cross-asset rules. It must retain exact artifact binding, non-execution, bounded parsing, scope,
coverage and authority. Phase 6D intentionally does not perform runtime behavior, universal
framework equivalence, current remote observation, security evaluation, model authenticity or
production admission.
