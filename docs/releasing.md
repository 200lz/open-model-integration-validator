# Release process

This document describes the remaining release procedure. The repository is publicly
available as a 0.10.0 Alpha preview, but this document does not authorize or announce
a tag, GitHub Pre-release, or PyPI publication. Version 1.0.0 is reserved for a later
stability decision, and Phase 6F is not part of 0.10.0.

## Candidate preparation

1. Start from the reviewed public `main` commit and a clean index.
2. Update `project.version`, `omiv.__version__`, `CITATION.cff`, and the changelog.
3. Review source ownership, third-party redistribution, dependency licenses, legal
   files, package metadata, and public documentation.
4. Run the audit tool, focused tests, full tests, lint, scoped formatting, Mypy,
   compileall, strict data parsing, generated-artifact verification, and Git fsck.
5. Build wheel and sdist twice in clean temporary environments with a documented
   `SOURCE_DATE_EPOCH`; compare hashes, file inventories, extracted bytes, and metadata.
6. Install the wheel into a clean environment, run `pip check`, import OMIV, and run
   CLI smoke tests.
7. Review the final diff and confirm that no credentials, private paths, payloads,
   copied webpages, or overclaims were introduced.

The source-install path remains the active quickstart. The PyPI command is conditional
until `PYPI_VERSION_NOT_YET_PUBLISHED` is cleared by an independently verified
publication. The future chain is one release commit → signed annotated `v0.10.0`
tag → one wheel, one sdist, and deterministic `SHA256SUMS` → GitHub Pre-release →
the exact same bytes through PyPI Trusted Publishing → post-publication install test.
The publisher workflow never rebuilds and never uses `skip-existing`.

## Tag and publication controls

The nine historical tags v0.1.0 through v0.9.0 are annotated but unsigned. They are
accepted as `LEGACY_UNSIGNED_TAGS_ACCEPTED_WITH_LIMITATION` and must not be recreated.

If a future release tag is separately authorized, the maintainer must create an
annotated, cryptographically signed tag only after tests and artifact hashes are
recorded. A tag signature authenticates the tag under the selected key; it does not
certify model safety or evidence truth. GitHub release creation and PyPI publication
each require separate explicit authorization. Publication automation must not hold
write permission on untrusted pull-request code.

R1E applied and verified the reviewed repository profile, topics, Dependabot alerts,
and Dependabot security updates while the repository remained private. Private
Vulnerability Reporting is not verified at the private R1F baseline.

A controlled 2026-08-10 attempt was public for approximately 5 hours 39 minutes. PVR,
secret scanning, and push protection verified while public, but the branch-protection
request returned HTTP 422 and was never applied. The authorized rollback to PRIVATE
succeeded. It cannot erase prior observation, indexing, links, caches, copies,
watchers, forks, or repository-network effects. No tag, GitHub Release, PyPI
publication, or announcement occurred. Public-only API states are now
`API_STATE_UNAVAILABLE` while private. Both prior authorizations were consumed, so a
new visibility authorization and new rollback-policy selection are required before
another attempt.

The authorized [R1F transaction](r1f-final-publication-audit.md) completed its exact
private audit, public visibility change, public-only control read-backs, and
unauthenticated public-read smoke check. The resulting controls remain authoritative
in live GitHub state; this preparation still does not create a tag, Release, or PyPI
project.

If a future release gate fails, classify the corresponding typed failure in the release
notes and do not announce, tag, create a GitHub Release, or publish to PyPI. Preserve
the exact normalized state and require separate remediation authority. Tag creation,
GitHub Release creation, PyPI publication, and announcement remain separate later
operations with separate authorization.

## Historical tag inventory

| Tag | Target commit | Kind | Signer state | Original message |
| --- | --- | --- | --- | --- |
| v0.1.0 | `918c0613dbf7645f9acf43d4dd46f13b7ac94b02` | annotated | unsigned | Kimi K3 schema validation MVP |
| v0.2.0 | `196716ded188329ee6d56558b50be31cf7fd4627` | annotated | unsigned | Kimi K3 structural coverage validator |
| v0.3.0 | `1c8cce2e855af43ba6f0eef9db5d9f77e8caece1` | annotated | unsigned | GGUF inventory and structural fidelity validation |
| v0.4.0 | `8bf40d8727cfdeb9f92f70b4eb3fd4c92025d694` | annotated | unsigned | Deterministic GGUF comparison reporting |
| v0.5.0 | `50b35e530ea8a77506ff8375ba82deefd7ef77fc` | annotated | unsigned | Hugging Face inventory and Qwen2 tensor ontology |
| v0.6.0 | `e78ff62207761a0ab66909b074a70fb5d93e81f3` | annotated | unsigned | HF to GGUF semantic mapping validation |
| v0.7.0 | `eefc64604ed11c5e8fa2955385bfc9611b4ee529` | annotated | unsigned | Extensible model pack architecture |
| v0.8.0 | `7bf36669f082d8e0c7998d725b54c61dc7baa321` | annotated | unsigned | Conversion provenance and reproducible lineage validation |
| v0.9.0 | `b83435c525f113315fac72a7362d4b25f468c3ee` | annotated | unsigned | Logical target realization and backend fallback validation |

The tag name is historical release identity; it is not the package version currently
recorded at a later commit. Version 0.10.0 reconciles the next package candidate with
the sequence without altering the historical tags.
