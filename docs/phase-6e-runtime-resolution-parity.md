# Phase 6E: runtime resolution, deployment binding, and output provenance

## Objective and non-goals

Phase 6E is an offline-first, deterministic evidence foundation for requested-versus-resolved model
identifiers, time-scoped resolution receipts, deployment expectations and observations, supplied
cross-backend results, inference correlation identities, attestation claims, and output provenance.
Normal operation performs no registry lookup, inference, model loading, tokenizer execution, or
template execution. It does not implement a cryptographic provable-inference scheme.

The fixed product description is:

> Offline-first, bounded runtime-resolution, deployment-binding, supplied-backend-result parity,
> and output-provenance evidence foundation—complete for declared evidence scope, with explicit
> distinction between provider documentation, control-plane state, runtime observation, service
> attestation, and proof of weight-attributable inference.

It does not establish immutable API aliases, complete backend equivalence, identical weights,
weight-attributable inference, safety, authenticity, publisher approval, or production readiness.

## Architecture and dependency graph

Canonical dependencies flow only downstream:

```text
requested identifier -> resolution plan -> execution -> receipt -> continuity
artifact expectation + deployment declaration -> deployment observation
  -> runtime observation -> runtime binding
probe set + runtime binding -> backend plan -> execution -> result -> comparison
runtime binding + exact request + execution + result -> inference identity
  -> attestation claim -> output provenance
finalized evidence -> policy -> authority -> Phase 6E evidence
  -> integrations/reports -> signed wrappers -> external index
```

Plans never reference future execution or results. Execution records never reference the receipt or
result they may later support. Reports, signatures, and indexes are downstream of unsigned evidence.
Fixtures are inputs only, and the external artifact index excludes itself. Executable graph
verification validates reference ID/digest pairs and rejects cycles and bounded-depth violations.

## V1 schemas

The strict dispatcher registers `RequestedModelIdentifier`, `IdentifierClassification`,
`ResolutionPlan`, `ResolutionExecutionRecord`, `ProviderRoutingStatement`,
`RegistryResolutionReceipt`, `ResolutionContinuityAssessment`, `RuntimeArtifactExpectation`,
`DeploymentDeclaration`, `DeploymentObservation`, `RuntimeIdentityExpectation`,
`RuntimeIdentityObservation`, `ModelRuntimeBinding`, `BackendDescriptor`, `CrossBackendProbeSet`,
`BackendExecutionPlan`, `BackendExecutionRecord`, `BackendResultObservation`,
`CrossBackendComparison`, `InferenceIdentity`, `InferenceAttestation`,
`OutputProvenanceEvidence`, `RuntimeResolutionPolicy`, its policy and authority evaluations,
`RuntimeResolutionParityEvidence`, `RuntimeResolutionIntegrationSummary`,
`AssumptionRegisterEntry`, reports, scenario records/catalog, and the external artifact index.

Every top-level canonical object uses a schema-specific domain separator. Subject, scope, exact
ID/digest references, availability, context/time or `NOT_RECORDED`, limitations, and bounded
collections are identity-bearing. Signatures are excluded from unsigned identities.

## Assumption register

Phase 6E invalidates the assumption that a stable API identifier necessarily identifies a stable
release when reviewed provider documentation demonstrates mutable routing and redirects. It weakens
the assumption that verified artifact identity alone proves runtime model identity because artifact
and deployment verification are separate from weight-attributable inference. Entries preserve
evidence references, strength, trust boundary, affected schemas/policies, explicit time fields,
limitations, and supersession.

## Identifier and resolution semantics

Identifier kinds include immutable pinned, versioned, mutable/latest alias, deprecated resolving,
redirected, provider opaque, user alias, unknown, and invalid. Spelling—digits, dates, versions,
hexadecimal text, `stable`, or `latest`—never proves immutability.

Receipts preserve provider/namespace, lookup source, disclosed target, evidence digest, observation
level, redirect chain, temporal context, authority, coverage, and limitations. Provider documentation
can establish only `PROVIDER_DOCUMENTED_POLICY`; it cannot establish a control-plane response,
direct runtime observation, or cryptographic attestation. At least two comparable supplied receipts
are required to record alias rebinding. Equal observations do not imply continuous monitoring.

Resolution mechanisms distinguish `HTTP_REDIRECT`, `PROVIDER_SEMANTIC_ROUTING`,
`MODEL_ALIAS_RESOLUTION`, and `DEPRECATION_COMPATIBILITY_ROUTING`. Provider, namespace, API
surface, purpose, observation method, mechanism, and resolved-identity semantics must all be
comparable before continuity is assessed. The reviewed xAI rules are provider-semantic model
routing, not evidence that OMIV observed HTTP redirects or live API resolution.

`requested_at`, `resolved_at`, `effective_at`, `available_at`, `observed_at`, `evaluated_at`, and
`supplied_at` remain distinct or `NOT_RECORDED`. Historical reconstruction remains
`KNOWN_AS_OF_CUTOFF`; late documentation does not rewrite what was known at an earlier cutoff.

## Deployment and runtime binding

Declaration, control-plane configuration, orchestrator state, process arguments, environment,
filesystem/file-descriptor/memory-map observation, runtime self-report, hardware/TEE references,
cryptographic runtime attestation, and provable-inference references are distinct strengths. Names
that sound strong do not pass automatically: policy must explicitly accept a supported strength and
exact artifact/release binding. Even `RUNTIME_IDENTITY_BOUND_FOR_DECLARED_SCOPE` is not provable
inference.

Every successful scope-qualified runtime binding references the exact selected policy and requires
the observation strength and artifact reference that policy accepts. Filesystem identity remains
distinct from memory mapping and active inference attribution.

Phase 6A remains the local byte-identity authority. Phase 6B provider object IDs, LFS/Xet/Git IDs,
ETags, requested slugs, and resolved slugs are not promoted to payload or weight identity.

## Supplied backend results

Phase 6E compares only explicitly supplied observations. Backend descriptors preserve declared
version/build/hardware/precision/quantization/kernel context but do not imply behavior. Probes bind
request identity, runtime and tokenizer/config identities, decoding/tool configuration, execution
mode, seed declaration, result dimensions, and limits.

Dimensions include bytes, text, token IDs, canonical structured JSON, tool-call structure, finish
reason, bounded selected logits, errors, final streaming aggregate, and stream chunk boundaries.
Final aggregate equality and chunk-boundary equality remain separate. Text is never normalized
unless an identity-bearing policy explicitly requires it.

Deterministic and stochastic declarations remain distinct. A seed or greedy decoding is not proof of
cross-backend determinism. Stochastic mismatch is not an automatic policy failure. Finite probe
success remains `EXACT_FOR_DECLARED_PROBES`; it cannot establish complete backend equivalence or
identical weights.

Selected-logit samples reuse the Phase 6C isolated 50-digit, `ROUND_HALF_EVEN`, bounded Decimal
semantics. Maximum/mean absolute and relative errors or rank/top-k findings apply only to explicitly
supplied positions and coverage; they never become full-logit or behavioral evidence.

## Privacy, inference identity, and provenance

Requests and outputs independently support `INLINE_SYNTHETIC`, `DIGEST_ONLY`, and `UNAVAILABLE`.
Production plaintext is not required. Domain-separated digests bind canonicalization, media type,
encoding, length when supplied, and streaming semantics so bytes, Unicode, JSON, token IDs, tool
calls, image/audio, and stream aggregates cannot collide ambiguously.

`InferenceIdentity` is a correlation record binding exact request, resolution, runtime binding,
backend execution/result, tokenizer/config/decoding identities, output digest, time, coverage, and
limitations. Equality of this record does not prove its claims true.

`InferenceAttestation` is a claim over a finalized inference identity. An unsigned claim, service
signature, provider/hardware/TEE reference, cryptographic-runtime reference, and provable-inference
reference remain distinct methods. Service-signature validity is not weight attribution and is not
provable-inference verification.

`OutputProvenanceEvidence` preserves proof availability, verifier availability, verification status,
claimed artifact identity, authority, and limitations. Phase 6E rejects proof-object substitution,
creates no fake proof bytes, and records `PROVABLE_INFERENCE_NOT_IMPLEMENTED`,
`PROVABLE_INFERENCE_FORMAT_UNAVAILABLE`, or `WEIGHT_ATTRIBUTION_NOT_ESTABLISHED` truthfully.
Reference-only proof metadata is typed and must bind the exact request digest, output digest, and
runtime-binding ID/digest. It also preserves scheme/version, verifier identity/version,
challenge availability, freshness, replay state, authority, policy, and limitations; none of these
fields imply verification.

## Policy and authority

Typed policies select identifier/redirect behavior, minimum resolution and runtime strength,
artifact/tokenizer/quantization binding, dimensions/tolerances, stochastic behavior, coverage,
attestation/proof statuses, authority, historical mode, and missing/unsupported behavior. Every
failed or unevaluated requirement is retained. Policy cannot upgrade documentation into runtime
observation or a service signature into weight attribution.

Authority is evaluated separately for namespace, routing publisher, resolution observer, artifact
publisher, deployment, runtime observer, backend executor, inference attestor, provenance verifier,
policy, purpose, subject/scope, provider, tenant/project, and trust domain. An official-looking
domain is provenance context, not cryptographic authority. Representative signing reuses Phase 5D
only for resolution receipts, runtime bindings, and final Phase 6E evidence.

## Phase integrations

Phase 5A receives a derived summary; Phase 5B may append an exact evidence reference; Phase 5C
deployment/transformation statements remain claims; Phase 5D trust is reused; Phase 5E gets no
automatic approval; Phase 5F gets no security pass; Phase 5G observations remain independent;
Phase 5H historical semantics are preserved. Phase 6A bytes, Phase 6B remote revision evidence,
Phase 6C numerical reconstruction, and Phase 6D tokenizer/config parity remain independent. Exact
bytes plus tokenizer parity plus a deployment declaration still do not establish observed runtime
weights, and exact backend outputs do not prove identical weights.

## Bounded public-document practice capture

The opt-in collector allowlists exactly the xAI release notes, xAI May 15 retirement migration page,
and Anthropic responsible-scaling roadmap. It permits only HEAD/GET, six total requests, three
redirects per request, 2 MiB per response, 6 MiB total, HTTPS allowlisted hosts, no queries,
credentials, cookies, or arbitrary links. Raw bodies remain outside the repository. Committed
fixtures contain only source/final URL, GET body SHA-256, content type/length, explicit request
accounting, `NOT_RECORDED` collection/publication/update times, and reviewed factual claims. Each
claim binds a bounded raw-body byte region by offset, length, and SHA-256; raw headers and complete
response bodies remain outside the repository.

The pinned capture used three HEAD and three GET requests and 1,158,612 response bytes. Afterwards,
all generation and tests are offline.

## Practice evidence

The xAI profile records reviewed provider-documented routing: `grok-voice-latest` to
`grok-voice-think-fast-2.0` starting August 5, 2026, plus retirement-page replacement routing. It
does not claim an OMIV request, API response, current route, exact artifact/weights, runtime
identity, publisher authority, endorsement, or affiliation. “A model name is not a model identity”
is an evidence-model principle, not a claim that every model identifier is mutable.

The Anthropic profile records the public September 30, 2026 prototype target, the stated goal of
output attribution to specified weights, and the separate production intended-version verification
roadmap item. It does not claim prototype completion, architecture, cryptography, hardware,
performance, a public proof format, a verifier, or successful proof.

## Resource limits, generation, and CLI

Limits cover identifiers, receipts/redirects, continuity/deployment/runtime observations, backends,
probes/executions/results/token IDs/JSON/logits, findings, inference identities, attestations/proof
references, dependency graph/report reconstruction, generated files/bytes, and public documents.
Exceeded bounds produce `LIMIT_EXCEEDED`; canonical evidence is never silently truncated. Bounded
reports state total/included/omitted findings and deterministic selection.

Offline commands include `omiv runtime-resolution inspect`, `verify`, `report`, `verify-index`,
`practice-xai`, and `practice-anthropic`. The separate public-document collector requires explicit
network opt-in and an out-of-repository raw-output directory. Generated examples are deterministic,
contain harmless synthetic inputs only, sign only representative classes, and use an external
self-excluding index.

## Remaining limitations and future extensions

V1 does not perform live resolution, control-plane collection, model/tokenizer loading, inference,
distributional equivalence, universal backend parsing, hardware/TEE verification, or provable
inference. It supplies evidence architecture and fail-closed states for future independently
specified observers and proof verifiers. Those extensions must preserve the existing trust
boundaries and cannot reinterpret Phase 6E claims retroactively.
