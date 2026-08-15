# Phase 7A candidate: Smart Preflight / Auto Planner

## Status and boundary

Phase 7 scope is not frozen. This document describes a minimal candidate vertical
slice under active development; it does not claim a finalized Phase 7 boundary or a
release.

The slice discovers supplied local canonical evidence, validates it against the
existing Phase 5/6A–6E registry, classifies only final Phase 6A–6E evidence records
as possible dimension verdicts, and emits a normal `omiv.assurance-request.v1` for
the unchanged Phase 6F preflight. It does not alter an Assurance Bundle schema,
projection, verdict, unknown, signature, trust-policy, or offline-verification rule.

## Local workflow

```console
omiv smart-preflight plan \
  --intent examples/smart-preflight/intent.json \
  --root . \
  --output smart-plan.json \
  --assurance-request-output assurance-request.json
omiv assurance plan \
  --request assurance-request.json \
  --root . \
  --output assurance-plan.json
```

The intent declares a subject, one or more bounded local search paths, and optional
required assurance dimensions. The Smart Preflight plan records every validated
candidate, dimension coverage, selection decisions, local inspection costs,
findings, and an embedded Phase 6F request when a safe handoff exists.

The planner is deterministic for unchanged local inputs. Search order is portable
path byte order. It validates canonical objects before selection and uses content
digests for portable member names.

## Conservative selection

Automatic `DIMENSION_VERDICT` selection is restricted to final evidence schemas:

- `omiv.payload-integrity-evidence.v1`;
- `omiv.remote-local-reconciliation-evidence.v1`;
- `omiv.quantization-fidelity-evidence.v1`;
- `omiv.tokenizer-configuration-parity-evidence.v1`; and
- `omiv.runtime-resolution-parity-evidence.v1`.

Other registered objects remain visible supporting candidates. One unique final
record covers a requested dimension. Byte-identical copies are deduplicated; two
distinct records for the same dimension are `AMBIGUOUS`, and neither is selected.
Missing and ambiguous dimensions never receive placeholder evidence or an inferred
PASS. The caller must narrow the search or make an explicit evidence choice.

The generated request contains no planned costly operation. Phase 6F independently
re-opens, hashes, validates, and projects the selected evidence; Phase 7A does not
pre-authorize a bundle result.

## Safety and limits

Discovery is read-only, local, bounded, and does not follow symlinks. It performs no
model download, conversion, remote collection, subprocess execution, runtime start,
or GPU operation. The candidate v1 limits are 10,000 directory entries, 4,096 JSON
files, 256 MiB cumulative JSON bytes, 64 MiB per JSON member, and depth 16. Hitting a
global discovery limit blocks the partial auto plan.

Exit behavior is:

- `0` for a complete, unique local selection and written Phase 6F handoff;
- `1` for gaps, ambiguity, or a blocked partial plan; and
- `2` for malformed input, unsafe scope, or an operational failure.

These limits and selection rules are candidate scope and may change before Phase 7
is frozen.

## Metadata-only reference acceptance

The provider-neutral `reference-preflight` candidate extends the concise preflight
experience to reviewed remote-metadata fixtures without changing the local discovery
planner above. Its first acceptance fixture is Muse Glimmer 30B:

```console
omiv reference-preflight plan \
  --profile fixtures/reference-preflight/muse-glimmer-30b.json \
  --reference meta-models/Muse-Glimmer-30B-GGUF \
  --root . \
  --output muse-reference-evidence.json \
  --assurance-request-output muse-assurance-request.json
```

The command replays pinned observations offline. Provider and runtime names, artifact
roles, revisions, declared sizes and provider-exposed identities live in the fixture;
the operational code only validates, canonicalizes and projects the generic schema.
It does not refresh metadata, download a payload, inspect GGUF bytes, invoke a runtime,
or upgrade declarations into compatibility or fidelity claims.

The generated Phase 6F request uses an `EXTERNAL` opaque supporting member and declares
the future GPU cost. This preserves the evidence bytes in a portable Assurance Bundle
without adding the Phase 7 candidate schema to the Phase 5/6A–6E verdict registry. The
Phase 6F verdict therefore remains `UNKNOWN`, while the reference-preflight evidence
retains the more detailed qualified states such as `NOT_DOWNLOADED`,
`NOT_ESTABLISHED`, `NOT_RUN`, and `NOT_EVALUATED`.

See the [offline acceptance example](../examples/reference-preflight/README.md) and
[normalized fixture notes](../fixtures/reference-preflight/README.md).
The example's future GPU recommendation is bounded to a deterministic PNG probe,
one 32 GB RTX 5090, USD 5, four hours, explicit disk tiers, and mandatory exact-Pod
termination; it remains unexecuted metadata rather than a runtime result.
