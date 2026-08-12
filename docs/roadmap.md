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
| Phase 6F | PLANNED, NOT IMPLEMENTED | Future Assurance Bundle interoperability; scope requires separate instruction |
| Phase 7 | FUTURE, SCOPE NOT FROZEN | No finalized scope claim |

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

Phase 6F development remains planned and unimplemented; Release Track work does not
update the existing Phase 6F branch.

Return to the [documentation index](README.md) or the [main README](../README.md).
