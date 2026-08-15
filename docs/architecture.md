# OMIV architecture

OMIV is an offline-first evidence and verification framework. Its core concern is
not whether an artifact or deployment sounds trustworthy, but which facts were
declared, observed, reconstructed, signed, authorized by policy, or unavailable.

## Design boundaries

OMIV uses a provider-neutral core for strict models, canonical serialization,
domain-separated identities and digests, typed references, verification results,
resource limits, and fail-closed handling. Provider and format specifics enter
through bounded adapters and practice profiles; they do not redefine the core
evidence semantics.

The main layers are:

1. **Canonical evidence objects.** Strict schemas identify subjects, scopes,
   observations, declarations, limitations, and upstream references.
2. **Format adapters.** GGUF, Safetensors, mapping, payload, and related adapters
   translate bounded supplied data into canonical records without silently reading
   model payloads.
3. **Model and practice profiles.** Profiles add declared structural expectations
   or evidence contracts. A readiness contract is not a completed integration.
4. **Trust and policy.** Signatures establish integrity under a key; authority and
   policy are evaluated separately. Signature validity is not publisher authority.
5. **Portable verification.** The CLI reconstructs identities and scoped results
   locally. Missing evidence stays missing.

## Evidence flow

Evidence normally moves downstream from resolution and acquisition to artifact
identity, transformations, policy, runtime binding, and historical audit. Not every
edge is automated and no downstream record retroactively strengthens an upstream
observation.

Important non-equivalences are architectural invariants:

- declaration is not observation;
- a name or mutable alias is not an artifact identity;
- artifact identity is not runtime identity;
- a valid signature is not proof of publisher authority;
- a finite probe is not complete behavioral equivalence;
- an output digest is not proof of which weights produced the output;
- absent, unsupported, or unchecked evidence is not `PASS`.

## Canonical identities and digests

Each canonical object has a schema-specific identity domain and explicit
identity-bearing fields. Canonicalization makes semantically identical supported
objects reconstruct the same digest while rejecting unknown or malformed structure.
Typed ID/digest references prevent a matching identifier from substituting for the
wrong content. Integrity proves internal consistency; it does not prove that a
declaration or observation is true in the outside world.

## Phase 5 foundation

Phase 5 supplies Model Passports, custody ledgers, lifecycle attestations,
cryptographic trust, governance and approval records, artifact-security evidence,
deployment/runtime continuity, and historical audit bundles. These areas preserve
separate trust dimensions instead of collapsing them into one score. Policy results
remain scoped to their selected policy and evidence set.

## Phase 6 evidence boundaries

| Phase | Evidence authority | Boundary that remains explicit |
| --- | --- | --- |
| 6A | Local payload manifests and exact byte identity | Bytes do not establish publisher, safety, or runtime use |
| 6B | Remote metadata, topology, and shard reconciliation | Metadata/object IDs do not become payload identity |
| 6C | Quantization representation and bounded numerical reconstruction | Selected values do not establish whole-model equivalence |
| 6D | Tokenizer/configuration structural parity and supplied probes | Finite probes do not establish complete behavior |
| 6E | Resolution receipts, deployment/runtime bindings, supplied backend results, inference identity, and output provenance | Supplied records do not perform live resolution, inference, or weight-attributable proof |

Phase 6A–6E objects can reference one another only through defined downstream
interfaces. Exact payload bytes plus tokenizer parity plus a deployment declaration
still do not prove which weights were actively used for inference.

Provable inference is a reference/readiness boundary only; it is not implemented.

## External artifact availability

Some practice evidence has an external local dependency. In particular, the large
Kimi raw inventory is intentionally not distributed. Verifiers report
`NOT_AVAILABLE` where a full reconstruction needs it, while portable digest-only or
independent bounded examples remain explicit about reduced scope. OMIV does not
download a missing artifact automatically.

Remote collectors are separate, bounded, and opt-in. Default verification is local
and offline. Committed public-document evidence stores bounded normalized records,
not credentials, raw provider responses, model payloads, or a claim about current
provider state.

## Offline verification

An offline verifier accepts supplied evidence, performs strict parsing, reconstructs
canonical identity/digest relationships, evaluates only available scoped rules, and
emits deterministic results and limitations. Verification does not require a hosted
service. The [quickstart](quickstart.md) demonstrates this path with a small tracked
synthetic object.

## Phase 6F Assurance Bundle boundary

Phase 6F remains Assurance Bundle interoperability. Local preflight precedes costly
work; fixed core documents retain concise verdicts, findings, and unknowns; and
offline verification covers portable directory and deterministic `.omiv` transports,
Phase 5/6A–6E schemas, semantic reconstruction, and optional Ed25519 trust-policy
binding. It composes existing evidence without rewriting canonical meaning or
replacing an earlier verifier. It is not released, and Phase 7 scope remains
unfrozen. See the [Phase 6F guide](phase-6f-assurance-bundle-interoperability.md).

## Public and future commercial operation

The public core owns canonical schemas, canonicalization, evidence semantics,
signatures and verification, the offline CLI, portable evidence, policy-result
semantics, and future Assurance Bundle verification. Possible future managed
operation may automate collection, policy, history, admission, identity management,
and enterprise connectors, but it may not secretly strengthen or redefine canonical
public results. See the [public/commercial boundary](public-commercial-boundary.md).

## Implementation map

- `src/omiv/` contains the provider-neutral core, adapters, profiles, and CLI.
- `src/omiv/assurance/` contains Phase 6F preflight, registry/projection, portable
  core documents, deterministic archive, signatures, assembly, and offline verification.
- `src/omiv/smart_preflight/` contains the isolated Phase 7A candidate for bounded
  local discovery and conservative generation of a normal Phase 6F request.
- `src/omiv/runtime_compatibility/` contains the isolated Phase 7B candidate for
  explicitly supplied, bounded local runtime compatibility profiles and evidence.
  Its Phase 7B.1 native-output profile embeds the reconstructable canonical plan,
  retains raw process observations, and keeps unobservable runtime internals unknown.
- `schemas/` and phase-specific directories contain portable evidence and examples.
- `docs/phase-*.md` describe released engineering phases and their limits.
- `tools/audit_*.py` perform bounded offline repository and preservation audits.
- `tests/` exercise canonicalization, verification, CLI behavior, and non-goals.

The [documentation index](README.md) routes to detailed evidence and phase
references. The [technical reference](reference/technical-reference.md) retains the
complete historical command and evidence documentation that formerly occupied the
root README.
