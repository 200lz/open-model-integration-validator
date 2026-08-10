# README migration map

The launch-oriented README replaced a historically layered technical guide. Before
that change, every Markdown heading was inventoried. The complete original content
was moved without substantive deletion to
[technical-reference.md](technical-reference.md). Its title and relative link
targets were adapted to the new location. This deterministic map records each
source heading and its route.

Classification meanings:

- `RETAIN_IN_README`: rewritten launch-level coverage remains in the root README.
- `MOVE_TO_EXISTING_DOCUMENT`: detailed ownership already exists in a linked phase document.
- `MOVE_TO_NEW_REFERENCE_DOCUMENT`: the original text is retained in the technical reference.
- `ALREADY_DOCUMENTED_ELSEWHERE`: an established document is the preferred maintained route.
- `REMOVE_AS_OBSOLETE_WITH_JUSTIFICATION`: no section used this classification.

| Original heading | Classification | Maintained route |
| --- | --- | --- |
| Open Model Integration Validator | RETAIN_IN_README | Root README identity and positioning |
| Install | MOVE_TO_NEW_REFERENCE_DOCUMENT | Technical reference; concise flow in `docs/quickstart.md` |
| Model Passports | MOVE_TO_NEW_REFERENCE_DOCUMENT | Technical reference |
| Model Chain of Custody ledgers | MOVE_TO_NEW_REFERENCE_DOCUMENT | Technical reference |
| Core, format adapters, and model packs | MOVE_TO_NEW_REFERENCE_DOCUMENT | Technical reference; summarized in architecture |
| Normalize | MOVE_TO_NEW_REFERENCE_DOCUMENT | Technical reference |
| Validate | MOVE_TO_NEW_REFERENCE_DOCUMENT | Technical reference |
| Evidence provenance | MOVE_TO_NEW_REFERENCE_DOCUMENT | Technical reference |
| Limitations | RETAIN_IN_README | Root README limitations plus technical reference |
| Optional GGUF structural inventories | MOVE_TO_NEW_REFERENCE_DOCUMENT | Technical reference |
| Deterministic reports and hashes | MOVE_TO_NEW_REFERENCE_DOCUMENT | Technical reference |
| Output safety | MOVE_TO_NEW_REFERENCE_DOCUMENT | Technical reference |
| Local Hugging Face Safetensors inventories | MOVE_TO_NEW_REFERENCE_DOCUMENT | Technical reference |
| Semantic mapping manifests | MOVE_TO_NEW_REFERENCE_DOCUMENT | Technical reference |
| Conversion provenance and lineage | MOVE_TO_NEW_REFERENCE_DOCUMENT | Technical reference |
| Conservative conversion capture | MOVE_TO_NEW_REFERENCE_DOCUMENT | Technical reference |
| Logical target realizations | MOVE_TO_NEW_REFERENCE_DOCUMENT | Technical reference |
| Pinned remote repository snapshots and bounded Range probes | MOVE_TO_NEW_REFERENCE_DOCUMENT | Technical reference |
| Incremental remote GGUF v3 headers | MOVE_TO_NEW_REFERENCE_DOCUMENT | Technical reference |
| Deterministic split GGUF aggregation | MOVE_TO_NEW_REFERENCE_DOCUMENT | Technical reference |
| Kimi K3 target-side GGUF ontology | MOVE_TO_NEW_REFERENCE_DOCUMENT | Technical reference |
| Phase 4F-5 grouped semantic mapping | MOVE_TO_NEW_REFERENCE_DOCUMENT | Technical reference |
| Phase 4F-6 independent validation bundles | MOVE_TO_NEW_REFERENCE_DOCUMENT | Technical reference |
| Phase 4F-7 cross-quantization structural comparison | MOVE_TO_NEW_REFERENCE_DOCUMENT | Technical reference |
| Phase 4F evidence-linked publication case study | MOVE_TO_NEW_REFERENCE_DOCUMENT | Technical reference |
| Artifact acquisition and transformation attestations | MOVE_TO_NEW_REFERENCE_DOCUMENT | Technical reference |
| Phase 5D: signed attestations and trust roots | MOVE_TO_NEW_REFERENCE_DOCUMENT | Technical reference |
| Phase 5E: policy decisions, approval, and promotion gates | MOVE_TO_NEW_REFERENCE_DOCUMENT | Technical reference |
| Governance semantics | MOVE_TO_NEW_REFERENCE_DOCUMENT | Technical reference |
| Governance schemas | MOVE_TO_NEW_REFERENCE_DOCUMENT | Technical reference |
| Policy profiles and precedence | MOVE_TO_NEW_REFERENCE_DOCUMENT | Technical reference |
| Offline governance CLI | MOVE_TO_NEW_REFERENCE_DOCUMENT | Technical reference |
| Phase 5F: artifact security evidence | ALREADY_DOCUMENTED_ELSEWHERE | `docs/phase-5f-artifact-security-evidence.md` and technical reference |
| Safe inspection boundary | ALREADY_DOCUMENTED_ELSEWHERE | Phase 5F document and technical reference |
| Schemas, policies, and verdicts | ALREADY_DOCUMENTED_ELSEWHERE | Phase 5F document and technical reference |
| Governance, Passport, and custody | ALREADY_DOCUMENTED_ELSEWHERE | Phase 5F document and technical reference |
| Offline security CLI | ALREADY_DOCUMENTED_ELSEWHERE | Phase 5F document and technical reference |
| Phase 5G: deployment and runtime snapshot verification | ALREADY_DOCUMENTED_ELSEWHERE | `docs/phase-5g-deployment-runtime-verification.md` |
| Phase 5H: historical trust and audit bundles | ALREADY_DOCUMENTED_ELSEWHERE | `docs/phase-5h-continuous-trust-audit-bundles.md` |
| Phase 6A: local payload integrity | ALREADY_DOCUMENTED_ELSEWHERE | `docs/phase-6a-payload-integrity-manifests.md` |
| Phase 6B: shard completeness and remote/local reconciliation | ALREADY_DOCUMENTED_ELSEWHERE | `docs/phase-6b-shard-reconciliation.md` |
| Phase 6C: quantization representation and numerical fidelity | ALREADY_DOCUMENTED_ELSEWHERE | `docs/phase-6c-quantization-fidelity.md` |
| Phase 6D: tokenizer and configuration parity | ALREADY_DOCUMENTED_ELSEWHERE | `docs/phase-6d-tokenizer-configuration-parity.md` |
| Phase 6E: runtime resolution, deployment binding, and output provenance | ALREADY_DOCUMENTED_ELSEWHERE | `docs/phase-6e-runtime-resolution-parity.md` |

Audit tooling compares the reference headings and this table so future maintenance
cannot silently drop a routed section.

Return to the [documentation index](../README.md) or the [main README](../../README.md).
