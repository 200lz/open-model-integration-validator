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
