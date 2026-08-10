# OMIV roadmap

The Engineering Track and Release Track are independent namespaces. Engineering
status describes repository capabilities; release status describes preparation for
a future public-preview launch.

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
| R1F final publication audit | IMPLEMENTED, PRIVATE RELEASE AND VISIBILITY AUTHORIZATION PENDING |

The R1F baseline remains private, and live GitHub visibility is authoritative after
any separately authorized transaction. R1F implementation
does not mean the repository is public and does not select rollback authority.
Any visibility change requires separate authorization.
The target remains an untagged and unreleased `v0.10.0` public-preview candidate.
No GitHub release or PyPI publication is claimed. See the
[R1F final-publication audit](r1f-final-publication-audit.md).

After public launch, Phase 6F development resumes from the latest public `main`
baseline. Release Track work does not update the existing Phase 6F branch.

Return to the [documentation index](README.md) or the [main README](../README.md).
