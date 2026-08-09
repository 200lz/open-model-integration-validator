# Third-party notices and redistribution review

This inventory supports the upcoming OMIV 0.10.0 public preview. It is a technical
review, not legal advice. Original OMIV source is Apache-2.0 unless otherwise noted;
that statement does not relicense third-party dependencies, provider metadata, model
metadata, names, or bounded public-document evidence.

## Tracked-material classification

| Material | Classification | Redistribution conclusion and limitation |
| --- | --- | --- |
| `src/omiv`, tests, tools, schemas, policies, mappings, and project documentation | `ORIGINAL_PROJECT_SOURCE` | Authored in this repository by the approved project author; Apache-2.0. Schemas describing external formats do not copy an external implementation. |
| Synthetic JSON, text, key, GGUF, and Safetensors test inputs | `ORIGINAL_SYNTHETIC_FIXTURE` | Project-created, deliberately non-production fixtures; Apache-2.0. The two format-marker binaries contain 10 and 42 bytes and no model payload. |
| Canonical inventories, reports, attestations, passports, trust records, and Phase 5/6 examples | `PROJECT_GENERATED_EVIDENCE` | Deterministic OMIV output. It may describe third-party artifacts; Apache-2.0 applies to OMIV's original structure and code, not underlying provider rights. |
| Pinned Hugging Face repository listings, model header descriptors, tensor names, shapes, dtypes, sizes, and digests | `THIRD_PARTY_METADATA` | Limited factual, normalized metadata. No checkpoint or tokenizer payload is retained. Source and revision remain recorded; underlying artifacts retain their terms. |
| Three normalized xAI/Anthropic public-document fixtures | `THIRD_PARTY_DOCUMENT_DERIVATION` | Bounded claim metadata only; no complete webpage or raw response is stored. Source documents retain their terms. |
| Copied or vendored implementation source | `THIRD_PARTY_CODE` | None found. |
| Copied long-form third-party prose | `THIRD_PARTY_TEXT` | None found. Descriptive provider/model names and short claim summaries remain attributed. |
| Images, logos, badges, fonts, or other media | `UNKNOWN_ORIGIN` | None tracked. |

No tracked material remains classified `UNKNOWN_ORIGIN`. No model or tokenizer
payload, complete copied webpage, vendored repository, or Git submodule is present.

## Direct Python dependencies

Versions are those inspected in the release-audit environment; project constraints
remain authoritative. License evidence came from installed `.dist-info` metadata and
included license files.

| Dependency | Audited version | Role | License evidence | Classification | Limitation |
| --- | ---: | --- | --- | --- | --- |
| cryptography | 49.0.0 | runtime | `License-Expression: Apache-2.0 OR BSD-3-Clause`; included Apache and BSD texts | `APACHE_2_COMPATIBLE` | Dual-licensed dependency; OMIV does not implement its primitives. |
| pydantic | 2.13.4 | runtime | `License-Expression: MIT`; included `LICENSE` | `PERMISSIVE_COMPATIBLE` | Separate upstream project. |
| PyYAML | 6.0.3 | runtime | `License: MIT`; included `LICENSE` | `PERMISSIVE_COMPATIBLE` | Separate upstream project. |
| typer | 0.27.0 | runtime | `License-Expression: MIT`; included `LICENSE` | `PERMISSIVE_COMPATIBLE` | Its distribution also includes Click-derived BSD-licensed material. |
| gguf | 0.19.0 | optional `gguf` extra | included MIT `LICENSE` | `PERMISSIVE_COMPATIBLE` | Optional adapter dependency; no llama.cpp source is vendored. |
| mypy | 2.3.0 | development/CI | `License-Expression: MIT`; included MIT license and Apache-2.0 typeshed license | `PERMISSIVE_COMPATIBLE` | Not installed at runtime by OMIV. |
| pytest | 9.1.1 | development/CI | `License-Expression: MIT`; included `LICENSE` | `PERMISSIVE_COMPATIBLE` | Not installed at runtime by OMIV. |
| Ruff | 0.16.0 | development/CI | `License-Expression: MIT`; included `LICENSE` | `PERMISSIVE_COMPATIBLE` | Not installed at runtime by OMIV. |
| Hatchling | 1.31.0 | build backend | `License-Expression: MIT`; included `LICENSE.txt` | `PERMISSIVE_COMPATIBLE` | Acquired only in the temporary build-validation environment. |

The public CI uses the official `actions/checkout` and `actions/setup-python`
Actions at immutable commits. Both upstream projects declare MIT licenses. GitHub's
hosted runner and service terms remain separate from OMIV's license.

### Temporary build-tool acquisition record

The bounded package audit acquired these wheels from PyPI into a temporary validation
environment. SHA-256 applies to the downloaded wheel bytes. None was added to OMIV's
runtime dependencies or installed into the project virtual environment.

| Package | Version | Wheel SHA-256 | Source URL |
| --- | ---: | --- | --- |
| build | 1.5.0 | `13f3eecb844759ab66efec90ca17639bbf14dc06cb2fdf37a9010322d9c50a6f` | `https://files.pythonhosted.org/packages/0d/fe/6bea5c9162869c5beba5d9c8abbed835ec85bf1ec1fba05a3822325c45f3/build-1.5.0-py3-none-any.whl` |
| Hatchling | 1.31.0 | `aac80bec8b6fe35e8480f1c335be8910fa210a0e6f735a139be205dadcacb544` | `https://files.pythonhosted.org/packages/64/e2/2c0af0a52d16be74a4f194564fcdc417521ed863e9b65e4bc9052dacba6f/hatchling-1.31.0-py3-none-any.whl` |
| packaging | 26.3 | `d7193f7c8e4e93f444fde0262bf90af30e16fa0ad0ad44cb553c87339b23cd1c` | `https://files.pythonhosted.org/packages/63/34/ba1c580383c9eada3711951fef0795c80b829a078d72188184bcab9dd527/packaging-26.3-py3-none-any.whl` |
| pathspec | 1.1.1 | `a00ce642f577bf7f473932318056212bc4f8bfdf53128c78bbd5af0b9b20b189` | `https://files.pythonhosted.org/packages/f1/d9/7fb5aa316bc299258e68c73ba3bddbc499654a07f151cba08f6153988714/pathspec-1.1.1-py3-none-any.whl` |
| pluggy | 1.6.0 | `e920276dd6813095e9377c0bc5566d94c932c33b27a3e3945d8389c374dd4746` | `https://files.pythonhosted.org/packages/54/20/4d324d65cc6d9205fabedc306948156824eb9f0ee1633355a8f7ec5c66bf/pluggy-1.6.0-py3-none-any.whl` |
| pyproject-hooks | 1.2.0 | `9e5c6bfa8dcc30091c74b0cf803c81fdd29d94f01992a7707bc97babb1141913` | `https://files.pythonhosted.org/packages/bd/24/12818598c362d7f300f18e74db45963dbcb85150324092410c8b49405e42/pyproject_hooks-1.2.0-py3-none-any.whl` |
| trove-classifiers | 2026.6.1.19 | `ab4c4ec93cc4a4e7815fa759906e05e6bb3f2fbd92ea0f897288c6a43efd15b3` | `https://files.pythonhosted.org/packages/7c/a4/81502f486f01db95bc8320646a8a12511f5e556cb63d5e224d91816605c4/trove_classifiers-2026.6.1.19-py3-none-any.whl` |

## Provider and model metadata evidence

| Evidence | Source and acquisition | Pinned identity | Repository-file SHA-256 | Redistribution status and limitation |
| --- | --- | --- | --- | --- |
| Qwen2.5 0.5B HF inventory | Hugging Face repository metadata and local Safetensors header inventory for `Qwen/Qwen2.5-0.5B-Instruct` | `7ae557604adf67be50417f59c2c2f167def9a775` | `59309e5a2755ebf9a79428b71f856335262749d7aad8f99e93d3191d8921b8d9` | Normalized tensor/header facts; no weights. Underlying Qwen materials retain their terms. |
| Kimi K3 source inventory | Local normalization of a released 96-shard Safetensors header inventory for `moonshotai/Kimi-K3` | source-inventory digest `15a6757becb69c56492fdb630d6853696082a9ec6109bcea05f387a5052ea469` | `e52d44dbdfcb7728e26ad05187e0ac73742343a2ca75402723232edc14747294` | Normalized names, shapes, dtypes, and counts only; no weights or tokenizer payload. |
| Kimi K3 GGUF snapshots | Bounded Hugging Face public model revision/tree API for `unsloth/Kimi-K3-GGUF`, subtrees `UD-IQ1_M` and `UD-Q4_K_XL` | `3d4b61ab4b6789d401191c476cbb4567246db8f5` | `f12f4de75b05210083aeab8955f4f533f03447553476d117e1655ca85a687c22`, `9ee07f597ca618336875ce2e29cdc873a961d5bdc28d3fd0c7fbc7aeb90f0ad3` | Repository listing and bounded header facts. No GGUF tensor payload is included. |
| xAI Grok-1 metadata | Hugging Face public model revision and recursive tree API; normalized response, raw response not retained | `5de83eb225f49624b424f1c8aa74f96983b5885c` | `645ea0fbd09c85a1d69d4fd217bae43e580a04fcd484308d1cd71b528658ae78` | File-list facts only; zero weight bytes downloaded. Not an xAI attestation. |
| xAI Grok-2 metadata | Hugging Face public model revision and recursive tree API; normalized response, raw response not retained | `daf4395a80ad177386cfe39641b64fc12b1d70ed` | `ad495d2fbb3daaed25ddf8d351647254f2d7020d2d4492b89f90aea486c3a60b` | File-list facts only; zero weight bytes downloaded. Not an xAI attestation. |
| DeepSeek readiness profile | Project-created offline readiness contract; no remote acquisition | No revision: pinned snapshot explicitly not supplied | `80c3052be8ce79bb4ee0070dbfb813662e0696bd0db40b44098812d0398df216` | Not third-party captured content or operational evidence. It records missing evidence without inferring publisher authority. |

The metadata review establishes a bounded public-preview use of factual evidence; it
does not grant rights to redistribute provider model weights, tokenizer contents,
model cards, or other payloads.

## Bounded public-document derivations

| Normalized fixture | Exact source URL | Observed body size / SHA-256 | Claim regions | Limitation |
| --- | --- | --- | --- | --- |
| xAI release notes | `https://docs.x.ai/developers/release-notes` | 528275 bytes / `55450f91c5cf5e32197ff5d810170a38858fbdabe48998ebcc2ed604f63b7e7c` | 1 region, 81 bytes, with offset/length/digest | Documents a provider statement, not production routing. |
| xAI May 15 retirement | `https://docs.x.ai/developers/migration/may-15-retirement` | 399122 bytes / `338855e9c107c79dcb60e4affb107d85c6ec5dbf4cc83152e56e4d445dfbdef5` | 3 regions, 290 bytes total, each with offset/length/digest | Documents migration guidance, not current routing. |
| Anthropic roadmap | `https://www.anthropic.com/responsible-scaling-policy/roadmap` | 231215 bytes / `cbc20ac3ed7c133228efaf14ad17a6ca64d5746570434ce5a3174e7098ef101d` | 3 regions, 205 bytes total, each with offset/length/digest | A roadmap is not an implemented verifier or proof format. |

Each normalized fixture records retrieval method, observation state, human-review
status, source URL, full-body digest, claim-level byte offset/length/digest, and
temporal limitations. Raw bodies and complete webpages are not committed.

All provider and model names are used descriptively. OMIV is not affiliated with or
endorsed by Anthropic, Hugging Face, Moonshot AI, Qwen, Unsloth, or xAI.
