# Changelog

This project follows pre-1.0 semantic versioning. Dates are omitted where the
repository does not provide a supported release-date claim.

## Unreleased

Phase 6F Assurance Bundle interoperability engineering scope:

- add a local-only preflight plan before download, network, conversion, or GPU work;
- add fixed portable core documents, explicit missing/unknown evidence, and
  conservative dimension verdicts reconstructed during verification;
- add concise CLI summaries while retaining canonical machine-readable plans,
  manifests, and verification reports; and
- add Phase 5/6A–6E schema-registry interoperability and offline fail-closed
  verification for exact file sets, bytes, schemas, and semantic projections;
- add deterministic bounded `.omiv` archives and streaming binary evidence handling;
- add detached Ed25519 signatures with external trust-policy thresholds; and
- add capability negotiation, tracked conformance fixtures, and product-level
  `omiv verify bundle.omiv`.

The Phase 6F engineering scope is complete but not released, and Phase 7 scope
remains unfrozen.

Phase 7A candidate incubation:

- add bounded, read-only local discovery of canonical Phase 5/6A–6E evidence;
- conservatively auto-select only one unique final Phase 6A–6E verdict record per
  requested dimension, leaving distinct candidates ambiguous;
- emit a deterministic Smart Preflight plan and a standard Phase 6F Assurance
  request without changing Phase 6F semantics; and
- prohibit downloads, conversion, remote collectors, runtimes, and GPU work in the
  candidate planner.

This vertical slice is not a frozen Phase 7 scope or release claim.

Phase 7B candidate incubation:

- add a provider-neutral local runtime compatibility plan/run/verify workflow with
  an initial synthetic llama.cpp-compatible runner profile;
- bind results to explicit executable/artifact digests, runtime version, invocation,
  limits, CPU-only environment, and a supplied test vector;
- retain bounded stdout/stderr, five fail-closed stage results, findings, unknowns,
  limitations, and canonical JSON evidence; and
- add adversarial orchestration tests and a tracked fully offline example that does
  not require a real runtime, model, conversion, or GPU.

This candidate does not release or freeze Phase 7 or change Phase 6F/7A semantics.

Phase 7B.1 candidate hardening:

- replace executable-authored OMIV stage reports with direct execution of the bounded
  native argument array and retain raw native stdout/stderr and process observations;
- derive exact OUTPUT status in OMIV while keeping LOAD, TOKENIZER, PREFILL, and
  DECODE `UNKNOWN` when the native surface cannot independently establish them;
- embed the complete canonical plan in evidence and verify every duplicated request,
  pin, profile, invocation, environment, limit, and test-vector field offline; and
- reject outer-rehashed incoherent plan/evidence mutations while stating explicitly
  that canonical integrity is not origin authenticity.

This hardening remains candidate work. It does not release or freeze Phase 7,
register Phase 7B evidence in Phase 6F, or change Phase 7A selection.

Release infrastructure correction:

- pin the approved public release-signing key and verify its digest, typed
  fingerprints, lifetime, capabilities, and public-only packet inventory in an
  isolated temporary keyring;
- add an explicit, fail-closed `workflow_dispatch` recovery route that consumes only
  the existing reviewed GitHub Release assets; and
- preserve the immutable `v0.10.0` tag and GitHub pre-release after the initial OIDC
  workflow stopped at signed-tag verification because no public key was bootstrapped.

This correction does not publish to PyPI, alter release assets, or implement Phase 7.

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
