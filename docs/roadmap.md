# OMIV roadmap

The Engineering Track and Release Track are independent namespaces. Engineering
status describes repository capabilities; release status describes the public-preview
release gates after the repository became publicly readable.

## Engineering Track

| Milestone | Status | Scope |
| --- | --- | --- |
| Phase 5 | RELEASED | Passport, custody, attestations, trust, governance, security, runtime continuity, historical audit |
| Phase 6A | RELEASED | Local payload integrity manifests |
| Phase 6B | RELEASED | Shard reconciliation |
| Phase 6C | RELEASED | Quantization fidelity evidence |
| Phase 6D | RELEASED | Tokenizer/configuration parity |
| Phase 6E | RELEASED | Runtime resolution, deployment binding, supplied results, output provenance |
| Phase 6F | COMPLETE; NOT RELEASED | Assurance Bundle interoperability: preflight/plan, conservative verdicts, explicit unknowns, portable directory and deterministic `.omiv`, Phase 5/6A–6E schema registry, detached signatures/trust policy, and offline fail-closed verification |
| Phase 7 | FUTURE, SCOPE NOT FROZEN | No finalized scope claim |

Phase 7A Smart Preflight / Auto Planner now has a minimal candidate vertical slice
under development: bounded local discovery, conservative ambiguity handling, and a
generated Phase 6F request. It is incubation evidence rather than a frozen Phase 7
scope or release claim. A metadata-only reference acceptance profile exercises the
same concise, evidence-qualified boundary without changing the Phase 6F verdict
registry. See the [candidate guide](phase-7a-smart-preflight.md).

Phase 7B Runtime Compatibility Profiles now has a hardened Phase 7B.1 candidate slice
under development: explicit local executable and artifact pins, direct bounded
CPU-only native invocation, raw observations with unobservable internal stages kept
`UNKNOWN`, and evidence embedding its reconstructable canonical plan. It is
incubation evidence rather than a frozen scope, release, or general compatibility
claim. See the [candidate guide](phase-7b-runtime-compatibility-profiles.md).

## Release Track

| Milestone | Status |
| --- | --- |
| R1A readiness | COMPLETE |
| R1B private clean-clone CI | COMPLETE |
| R1C launch UX | COMPLETE |
| R1D offline walkthrough | COMPLETE |
| R1E GitHub metadata/security | COMPLETE |
| R1F final publication audit | COMPLETE; public controls verified |

The repository is publicly readable and live GitHub state is authoritative. The
signed annotated `v0.10.0` tag and its published GitHub pre-release exist. The first
Trusted Publishing run failed before publication because its isolated runner lacked
the signer's public key, so the PyPI project/version remain absent. See the
[publication recovery record](v0.10.0-publication-recovery.md), [R1F
audit](r1f-final-publication-audit.md), and [release notes](v0.10.0-release-notes.md).

The Phase 6F engineering scope is complete on the current main line. This does not
mark it released or alter any Phase 5/6A–6E boundary. Phase 7 scope is still not
frozen; candidate sequencing and the Phase 7A/7B/7B.1 slices are planning input
rather than a scope claim.

Return to the [documentation index](README.md) or the [main README](../README.md).
