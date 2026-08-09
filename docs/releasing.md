# Release process

This document describes a future release procedure. It does not authorize or announce
a release. The upcoming public-preview version is 0.10.0; version 1.0.0 is reserved for
a later stability decision, and Phase 6F is not part of 0.10.0.

## Candidate preparation

1. Start from the reviewed `main` commit and a clean index.
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

## Tag and publication controls

The nine historical tags v0.1.0 through v0.9.0 are annotated but unsigned. They are
accepted as `LEGACY_UNSIGNED_TAGS_ACCEPTED_WITH_LIMITATION` and must not be recreated.

For a future release, a maintainer may create an annotated, cryptographically signed
tag only after tests and artifact hashes are recorded. A tag signature authenticates
the tag under the selected key; it does not certify model safety or evidence truth.
GitHub release creation and PyPI publication each require separate explicit
authorization. Publication automation must not hold write permission on untrusted
pull-request code.

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
