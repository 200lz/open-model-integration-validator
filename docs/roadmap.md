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
| R1D offline walkthrough | IMPLEMENTED, RELEASE PENDING |
| R1E GitHub metadata | PLANNED |
| R1F final publication audit | PLANNED |

R1D implementation does not mean the repository is public. The target remains an
untagged and unreleased `v0.10.0` public-preview candidate, R1E–R1F remain, and any
visibility change requires separate authorization. No GitHub release,
public-repository state, or PyPI publication is claimed.

After public launch, Phase 6F development resumes from the latest public `main`
baseline. Release Track work does not update the existing Phase 6F branch.

Return to the [documentation index](README.md) or the [main README](../README.md).
