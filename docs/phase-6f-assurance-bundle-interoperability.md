# Phase 6F: Assurance Bundle interoperability

## Status and boundary

The Phase 6F engineering scope is complete on the current main line. It remains
Assurance Bundle interoperability; this is not a new validation phase and no release
is claimed. Phase 7 scope remains unfrozen.

Phase 6F composes supplied Phase 5 and Phase 6A–6E canonical evidence without
changing its meaning. It does not replace an originating verifier, upgrade unknowns,
or prove authority, runtime use, numerical fidelity, or semantic fidelity that the
source evidence did not prove. Missing, unsupported, invalid, and untested states
remain explicit and fail closed.

## Product workflow

Preflight happens before download, network, conversion, or GPU work:

```console
omiv assurance plan --request examples/assurance-bundle/request.json --root . --output plan.json
omiv assurance build --plan plan.json --root . --output bundle
omiv assurance pack --bundle bundle --output bundle.omiv
omiv verify bundle.omiv --report-output verification.json
```

The concise terminal result is for people. The plan, manifest, core documents,
evidence, signature records, and verification report retain the machine-readable
record. None of these commands downloads a model, invokes a converter, starts a
runtime, or uses a GPU.

The request declares each evidence member, its phase, expected schema, assurance
dimension, and whether it is supporting evidence or a dimension verdict. Preflight
reports local availability, schema support, byte cost, unresolved gaps, and any
proposed costly work. A proposed operation is information only; it is never executed.

## Portable bundle v1

A directory bundle and its deterministic ZIP_STORED `.omiv` transport contain:

```text
assurance-bundle.json
subject.json
verdict.json
evidence-index.json
findings.json
unknowns.json
capabilities.json
evidence/ ...
provenance/ ...
runtime/ ...
fidelity/ ...
signatures/*.json
```

The manifest records canonical identity, preflight identity, profile, required
features, exact evidence members, fixed core-file hashes, and limitations. Local
source paths never enter the portable manifest. The archive uses sorted portable
paths, fixed timestamps and modes, no compression, and bounded streaming extraction,
so the same directory produces identical archive bytes.

`capabilities.json` advertises the v1 profile, directory and ZIP_STORED transports,
Ed25519 signatures, supported Phase 5/6A–6E evidence schemas, and resource limits.
Verification rejects an unsupported profile or required feature instead of guessing.

## Verdict and unknown semantics

Only evidence explicitly assigned the `DIMENSION_VERDICT` role contributes a
semantic status. OMIV conservatively maps a canonical phase status to `PASS`, `WARN`,
`FAIL`, `UNKNOWN`, or `NOT_TESTED`; schema validity alone never becomes `PASS`.
Supporting evidence remains non-verdict evidence.

Offline verification recalculates this projection from the packaged canonical
evidence and rejects a different manifest projection. `verdict.json` provides the
short dimension summary, while `unknowns.json` records unresolved claims and the
next action. Full findings and evidence remain available to automation.

## Integrity, signatures, and trust

Verification checks manifest identity, profile/features, the exact file set,
portable paths, regular non-symlink files, resource bounds, sizes, SHA-256 digests,
core-document canonical identities, core projections, phase schemas, and semantic
projections. Binary evidence is streamed; JSON parsing is bounded.

An optional detached Ed25519 record signs the manifest digest:

```console
omiv assurance sign --bundle bundle --private-key signer.pem --key-id release-key
omiv assurance pack --bundle bundle --output signed.omiv
omiv verify signed.omiv --trust-policy trust-policy.json
```

A cryptographically valid signature is `VALID_UNTRUSTED` without an external policy.
Signer authority requires a supplied `omiv.assurance-trust-policy.v1` policy. Invalid
signatures, or a required trusted-signature threshold that is not met, invalidate the
verification. Signing does not make the underlying claim true.

## Exit behavior and limits

- `0`: ready preflight or complete, policy-satisfying bundle verification;
- `1`: blocked/review-required preflight, incomplete bundle, invalid bundle, or trust
  failure;
- `2`: malformed input, unsafe path, exceeded bound, or operational failure.

V1 limits requests to 256 evidence members, JSON evidence to 64 MiB per member,
individual streamed members to 1 GiB, and total evidence to 4 GiB. Output directories
and archives must not already exist. Case-insensitive portable-path collisions,
traversal, links, compressed archive entries, duplicate entries, and undeclared files
are rejected.

Tracked conformance requests live in `fixtures/assurance-bundle/`. One must resolve
to complete and one to incomplete without executing its declared GPU operation.

## Non-goals and Phase 7

Phase 6F does not discover a model from a single artifact, collect remote evidence,
run a backend, compare logits, or decide deployment policy. Those require later
product workflows. The proposed Phase 7 sequence is planning input only:

1. Smart Preflight / Auto Planner;
2. runtime compatibility profiles;
3. numerical and semantic fidelity profiles;
4. automated collectors and provider/runtime adapters.

That sequence does not freeze Phase 7 scope.
