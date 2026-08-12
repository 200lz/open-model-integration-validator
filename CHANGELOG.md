# Changelog

This project follows pre-1.0 semantic versioning. Dates are omitted where the
repository does not provide a supported release-date claim.

## Unreleased

Release infrastructure correction:

- pin the approved public release-signing key and verify its digest, typed
  fingerprints, lifetime, capabilities, and public-only packet inventory in an
  isolated temporary keyring;
- add an explicit, fail-closed `workflow_dispatch` recovery route that consumes only
  the existing reviewed GitHub Release assets; and
- preserve the immutable `v0.10.0` tag and GitHub pre-release after the initial OIDC
  workflow stopped at signed-tag verification because no public key was bootstrapped.

This correction does not publish to PyPI, alter release assets, implement Phase 6F/7,
or change runtime package code.

## v0.10.0 — Public Preview

Public-release preparation:

- adopt Apache-2.0 for original OMIV source and add ownership, dependency,
  redistribution, trademark, security, governance, support, and contribution records;
- align package and CLI version metadata at 0.10.0;
- add hardened Python 3.11–3.14 CI with no privileged or remote-integration behavior;
- remove the current conversion integration test's machine-specific source default;
- document public/commercial boundaries and a future release-signing policy.

Capabilities accumulated after historical v0.9.0 include Model Passports, custody
ledgers, attestations, cryptographic trust, governance gates, artifact security,
deployment/runtime continuity, continuous trust, payload integrity, shard
reconciliation, quantization fidelity, tokenizer-configuration parity, and
runtime-resolution parity (Phases 5 and 6A–6E).

The repository, signed annotated tag, and GitHub pre-release are publicly available.
PyPI publication remains incomplete and separately controlled.

Limitations:

- Phase 6F Assurance Bundle interoperability is not implemented;
- evidence integrity does not prove real-world truth, model safety, or provider
  authority;
- default operation is offline; explicitly invoked remote collectors are bounded;
- no hosted service, enterprise product, compliance certification, or SLA is included;
- no v0.10.0 PyPI project/version exists yet.

## Released historical tags

| Tag | Recorded scope |
| --- | --- |
| v0.9.0 | Logical target realization and backend fallback validation |
| v0.8.0 | Conversion provenance and reproducible lineage validation |
| v0.7.0 | Extensible model-pack architecture |
| v0.6.0 | HF-to-GGUF semantic mapping validation |
| v0.5.0 | Hugging Face inventory and Qwen2 tensor ontology |
| v0.4.0 | Deterministic GGUF comparison reporting |
| v0.3.0 | GGUF inventory and structural-fidelity validation |
| v0.2.0 | Kimi K3 structural-coverage validation |
| v0.1.0 | Kimi K3 schema-validation MVP |

These annotated historical tags retain their original targets and messages. They are
unsigned and classified `LEGACY_UNSIGNED_TAGS_ACCEPTED_WITH_LIMITATION`; no signature
claim is made and they will not be rewritten.
